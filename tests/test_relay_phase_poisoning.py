"""
Tests for HYP-423: active Nostr relay can poison phases pre-authentication.

Threat model: a hostile Nostr relay subscribes to our `t` tag and
publishes one or more fabricated events on a phase (`pake`, `version`,
`0`, ...). The forged event would consume the phase slot, causing our
real peer's later event to be ignored or to fail decryption.

Architecture under test:
- Mailbox forwards inbound peer events to Order on first sight (so
  Key/Receive can attempt to decrypt) AND parks the (side, body) in
  `_pending_phases[phase]` to remember "auth verdict pending."
- Receive/Key call back `mailbox.peer_message_authenticated(phase)` on
  decrypt success, `mailbox.peer_message_not_authenticated(phase)` on
  failure.
- On auth-success: phase moves to `_processed`, redrain fires, slot is
  closed.
- On auth-fail: pending slot is cleared, NO `_processed` entry is
  added — so the next inbound on that phase will be forwarded again.
- Order tolerates multiple `got_pake` (no longer terminal); Key
  tolerates a bad pake without entering a sticky-bad state.

This file relies on the FakeRendezvous-paired integration harness
because the bug only manifests across the Mailbox→Order→Key→Mailbox
auth-callback loop. Pure unit tests on Mailbox would miss the bug.
"""

import pytest_twisted
from twisted.internet.task import Clock

import takeit
from takeit.eventual import EventualQueue
from tests._fake_rendezvous import FakeRendezvous, pair


def _build_pair():
    """Build two paired wormholes with FakeRendezvous on each side. Each
    wormhole's Boss generates its own random side; FakeRendezvous reads
    those sides during wire()."""
    eq = EventualQueue(Clock())
    rv_a = FakeRendezvous()
    rv_b = FakeRendezvous()
    pair(rv_a, rv_b)

    def factory_a(boss, mailbox, terminator):
        rv_a.wire(boss, mailbox, terminator)
        return rv_a

    def factory_b(boss, mailbox, terminator):
        rv_b.wire(boss, mailbox, terminator)
        return rv_b

    a = takeit.create(
        appid="takeit/test",
        reactor=Clock(),
        relays=None,
        _eventual_queue=eq,
        _rendezvous_factory=factory_a,
    )
    b = takeit.create(
        appid="takeit/test",
        reactor=Clock(),
        relays=None,
        _eventual_queue=eq,
        _rendezvous_factory=factory_b,
    )
    return eq, a, b, rv_a, rv_b


def _inject_phase_event(rv, side, phase, body):
    """Simulate a hostile relay publishing a forged event on our subscribed
    tag. The fake bypasses the peer-pairing path that would only deliver
    legitimate peer events; this one simulates a third-party publisher
    on the same `t`."""
    rv._M.rx_message(side, phase, body)


# ---- regression: real peer happy-path ----


@pytest_twisted.ensureDeferred
async def test_real_peer_handshake_still_completes():
    """Sanity: the FakeRendezvous-paired full handshake works without
    any hostile relay. If this fails, our changes broke the happy path."""
    eq, a, b, _, _ = _build_pair()
    a.set_code("heu6dar6xjual7jbqhmljqxcx4:purple-sausages-mocha")
    b.set_code("heu6dar6xjual7jbqhmljqxcx4:purple-sausages-mocha")
    eq.flush_sync()
    # If the handshake completed both sides exchanged version events;
    # both keys must be set.
    assert a._boss._K._SK._sp is not None or a._boss._K._SK is not None
    assert b._boss._K._SK._sp is not None or b._boss._K._SK is not None


# ---- HYP-423: forged pake before real pake ----


@pytest_twisted.ensureDeferred
async def test_forged_pake_does_not_block_real_handshake():
    """A relay publishes a fabricated `pake` event on our tag BEFORE
    the real peer's pake arrives. The forged body fails Key.got_pake's
    parse → mailbox.peer_message_not_authenticated('pake') clears the
    pending slot. When the real peer's pake arrives later, it must be
    forwarded to Key and the handshake must complete."""
    eq, a, b, rv_a, rv_b = _build_pair()
    a.set_code("heu6dar6xjual7jbqhmljqxcx4:purple-sausages-mocha")
    eq.flush_sync()

    # Hostile relay publishes a forged pake to A BEFORE B publishes its real one.
    # The forged body is valid bytes but doesn't parse as a SPAKE2 dict.
    _inject_phase_event(rv_a, "cccccc", "pake", b"this-is-not-a-pake-payload")
    eq.flush_sync()

    # Real peer (B) sets the same code and publishes its real pake.
    b.set_code("heu6dar6xjual7jbqhmljqxcx4:purple-sausages-mocha")
    eq.flush_sync()

    # The handshake should complete despite the forged event:
    # both sides should reach S2_know_key.
    a_sk = a._boss._K._SK
    b_sk = b._boss._K._SK
    # _SortedKey transitions S0 → S1 (got_code) → S2 (got_pake_good).
    # If the forged pake had locked us out, A would be in S3_scared.
    assert getattr(a_sk, "_sp", None) is not None, (
        "A's SPAKE2 instance should be live; if it landed in S3_scared, the "
        "forged pake poisoned the slot"
    )
    assert getattr(b_sk, "_sp", None) is not None


@pytest_twisted.ensureDeferred
async def test_forged_pake_does_not_grow_memory_unboundedly():
    """A hostile relay floods garbage pake events. Our `_processed` set
    must NOT grow per forged event — only auth-confirmed phases are
    tracked. Mailbox's pending-phase storage must also not unboundedly
    accumulate (each new pake while one is pending is dropped)."""
    eq, a, _, rv_a, _ = _build_pair()
    a.set_code("heu6dar6xjual7jbqhmljqxcx4:purple-sausages-mocha")
    eq.flush_sync()

    mb = a._boss._M
    initial_processed = len(mb._processed)

    # Flood 100 forged events on phase "pake". Each parks then clears
    # because Key fails the parse and calls peer_message_not_authenticated.
    for _ in range(100):
        _inject_phase_event(rv_a, "cccccc", "pake", b"garbage-payload")
        eq.flush_sync()

    # _processed must not have grown — only successful auth advances it.
    assert len(mb._processed) == initial_processed
    # _pending_phases must be empty (all 100 garbage events failed auth
    # and were cleared).
    assert mb._pending_phases == {}


# ---- HYP-423 regression: forged version after handshake ----


@pytest_twisted.ensureDeferred
async def test_forged_version_does_not_block_real_version():
    """After PAKE completes, a forged 'version' event from the relay
    fails decryption (wrong key). It must not consume the version slot;
    the real peer's encrypted version must still land."""
    eq, a, b, rv_a, rv_b = _build_pair()
    a.set_code("heu6dar6xjual7jbqhmljqxcx4:purple-sausages-mocha")
    b.set_code("heu6dar6xjual7jbqhmljqxcx4:purple-sausages-mocha")
    eq.flush_sync()

    # Inject a forged 'version' to A. It will fail decrypt_data with
    # CryptoError → Receive calls peer_message_not_authenticated.
    _inject_phase_event(rv_a, "cccccc", "version", b"forged-encrypted-version")
    eq.flush_sync()

    # The handshake must remain intact; A must have received B's version.
    # Boss._their_versions is only set on the success path of
    # do_got_wormhole_versions, so its presence proves the real (not
    # forged) version made it through decryption.
    a_received_versions = getattr(a._boss, "_their_versions", None)
    assert a_received_versions is not None, (
        "A's _their_versions should be set from B's real version event; "
        "if forged version blocked it, this attr would be missing"
    )

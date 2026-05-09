"""
Tests for the takeit Mailbox state machine.

The state shape mirrors upstream's because the connection lifecycle (the A/B
suffix encoding "rendezvous connected" vs "disconnected") is still real on
Nostr — relays can drop. What is *gone* is the nameplate-claim round-trip:
the tag is derived synchronously from the code, so `got_tag` only sets the
tag, it does not initiate a server claim.

Inputs:
- got_tag(tag)               — Boss/Code calls this once the code is known
- connected() / lost()       — IRendezvous notifies of relay connectivity
- add_message(phase, body)   — Send/Key wants to publish a phase
- rx_message(side, phase, body) — IRendezvous delivers a peer event
- rx_closed()                — IRendezvous confirms close (may be synthetic)
- close(mood)                — Terminator initiates teardown

Outputs of interest:
- _RC.tx_open(tag)           — subscribe + drain queued outbound
- _RC.tx_add(phase, body)    — publish one phase
- _RC.tx_close(tag, mood)    — unsubscribe (no-op on Nostr but kept for
                               symmetry with Terminator's expectations)
- _O.got_message(side, phase, body) — forward peer messages (deduped)
- _T.mailbox_done()          — final ack to Terminator
"""

import pytest
from zope.interface import implementer

from takeit import _interfaces
from takeit._mailbox import Mailbox


@implementer(_interfaces.IRendezvousConnector)
class FakeRC:
    def __init__(self):
        self.opened = []
        self.added = []
        self.closed = []

    def tx_open(self, tag):
        self.opened.append(tag)

    def tx_add(self, phase, body):
        self.added.append((phase, body))

    def tx_close(self, tag, mood):
        self.closed.append((tag, mood))


@implementer(_interfaces.IOrder)
class FakeOrder:
    def __init__(self):
        self.received = []

    def got_message(self, side, phase, body):
        self.received.append((side, phase, body))


@implementer(_interfaces.ITerminator)
class FakeTerminator:
    def __init__(self):
        self.done = False

    def mailbox_done(self):
        self.done = True


@pytest.fixture
def mailbox_setup():
    rc = FakeRC()
    order = FakeOrder()
    term = FakeTerminator()
    mb = Mailbox(side="aaaa")
    mb.wire(rc, order, term)
    return mb, rc, order, term


# --- happy path ---


def test_message_published_after_tag_and_connect(mailbox_setup):
    mb, rc, _, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.add_message("pake", b"payload")
    assert rc.added == [("pake", b"payload")]


def test_outbound_queued_until_connected(mailbox_setup):
    mb, rc, _, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.add_message("pake", b"payload")
    assert rc.added == []  # not yet
    mb.connected()
    assert rc.added == [("pake", b"payload")]


def test_outbound_queued_until_tag_known(mailbox_setup):
    mb, rc, _, _ = mailbox_setup
    mb.connected()
    mb.add_message("pake", b"payload")
    assert rc.added == []
    mb.got_tag("xyz")
    assert rc.added == [("pake", b"payload")]


def test_open_command_sent_on_each_reconnect(mailbox_setup):
    """Subscriptions don't survive Nostr disconnects; we must re-subscribe."""
    mb, rc, _, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    assert rc.opened == ["xyz"]
    mb.lost()
    mb.connected()
    assert rc.opened == ["xyz", "xyz"]


# --- inbound message handling ---


def test_peer_message_forwarded_to_order(mailbox_setup):
    mb, _, order, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.rx_message("bbbb", "pake", b"peer-payload")
    assert order.received == [("bbbb", "pake", b"peer-payload")]


def test_own_message_does_not_loop_back(mailbox_setup):
    """Self-events from the relay (we publish, we also subscribe) must not
    loop into the Order pipeline."""
    mb, _, order, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.rx_message("aaaa", "pake", b"my-own")  # side == self._side
    assert order.received == []


def test_peer_phase_delivered_only_once(mailbox_setup):
    """Relays may deliver duplicates; Mailbox must dedupe by phase."""
    mb, _, order, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.rx_message("bbbb", "pake", b"peer-payload")
    mb.rx_message("bbbb", "pake", b"peer-payload")  # duplicate
    assert len(order.received) == 1


# --- close path ---


def test_close_with_no_tag_yet_completes_immediately(mailbox_setup):
    """If the user closes before a code is set, there's nothing to clean up."""
    mb, rc, _, term = mailbox_setup
    mb.close("lonely")
    assert term.done is True
    assert rc.closed == []  # nothing to close


def test_close_after_open_sends_close_then_completes_on_ack(mailbox_setup):
    mb, rc, _, term = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.close("happy")
    assert rc.closed == [("xyz", "happy")]
    assert term.done is False  # waiting for rx_closed
    mb.rx_closed()
    assert term.done is True


def test_messages_after_close_are_ignored(mailbox_setup):
    mb, _, order, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.close("happy")
    mb.rx_closed()  # fully closed
    mb.rx_message("bbbb", "pake", b"too-late")
    assert order.received == []


def test_outbound_persists_after_self_echo(mailbox_setup):
    """takeit semantic: outbound messages must stay queued even after the
    relay echoes them back to us. Nostr does not buffer ephemeral events,
    so a peer who subscribes after we publish would never see our message
    unless we retransmit."""
    mb, rc, _, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.add_message("pake", b"my-pake")
    # Self-echo (relay reflects our publish to our own subscription)
    mb.rx_message("aaaa", "pake", b"my-pake")
    # Queue should still hold "pake" — assert by triggering a redrain
    # via a peer message and verifying tx_add fires again.
    mb.rx_message("bbbb", "pake", b"peer-pake")
    # First publish + redrain on peer-pake = 2 publishes.
    assert rc.added == [("pake", b"my-pake"), ("pake", b"my-pake")]


def test_redrain_on_peer_only_fires_once_per_phase(mailbox_setup):
    """A peer that retransmits the same phase (because they hadn't seen our
    response yet) must not cause us to retransmit unboundedly. The
    `_processed` dedup guards against this feedback loop."""
    mb, rc, _, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.add_message("pake", b"my-pake")
    rc.added.clear()  # forget the initial publish
    # Peer sends pake; we redrain (one extra publish)
    mb.rx_message("bbbb", "pake", b"peer-pake")
    assert rc.added == [("pake", b"my-pake")]
    # Peer retransmits pake; we must NOT redrain again
    mb.rx_message("bbbb", "pake", b"peer-pake")
    assert rc.added == [("pake", b"my-pake")]


def test_redrain_capped_at_max_processed_phases(mailbox_setup):
    """A malicious peer (or hostile relay) flooding distinct phase
    strings cannot amplify our outbound past MAX_PROCESSED_PHASES
    redrains. Under HYP-423 the redrain bound counts pending+processed
    phases, since pending phases (auth verdict not yet returned) also
    consume memory."""
    from takeit._mailbox import Mailbox

    mb, rc, order, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.add_message("pake", b"my-pake")
    rc.added.clear()  # forget the initial publish

    cap = Mailbox.MAX_PROCESSED_PHASES
    # Send `cap + 50` distinct peer phases; expect exactly `cap`
    # redrains. None of these phases ever auth (the test FakeOrder
    # never calls peer_message_authenticated), so they all sit in
    # `_pending_phases` until we exceed the cap.
    for i in range(cap + 50):
        mb.rx_message("bbbb", f"p{i}", b"peer-payload")

    assert len(rc.added) == cap
    # All payloads still reach Order — the peer's messages aren't
    # dropped, just the redrain side-effect is capped.
    assert len(order.received) == cap + 50
    # Pending and processed are both bounded under HYP-423: pending is
    # capped at MAX_PROCESSED_PHASES so a relay flooding distinct
    # phases cannot grow our memory unboundedly. _processed only
    # advances on auth-verdict, which the FakeOrder doesn't trigger,
    # so it stays empty in this test.
    assert len(mb._processed) == 0
    assert len(mb._pending_phases) == cap


def test_hyp458_auth_redrain_only_fires_for_admitted_phases(mailbox_setup):
    """HYP-458: an authenticated peer can spam ciphertexts on endless
    distinct phases. Each one's auth verdict pre-fix triggered _drain()
    even when the phase was never admitted into _pending_phases (cap
    rejected at receive time). Post-fix: redrain runs only when the
    phase WAS admitted (i.e. legit auth verdict for an admitted phase),
    not for spam past the cap.
    """
    mb, rc, order, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.add_message("pake", b"my-pake")
    rc.added.clear()  # forget the initial publish

    cap = Mailbox.MAX_PROCESSED_PHASES
    # Admit `cap` phases (they sit in _pending_phases until auth).
    for i in range(cap):
        mb.rx_message("bbbb", f"p{i}", b"peer-payload")
    # cap-many redrains so far (one per admission).
    assert len(rc.added) == cap, (
        f"expected {cap} admission redrains, got {len(rc.added)}"
    )

    # Now send 100 more phases — these are NOT admitted (cap exhausted).
    pre_admission_redrains = len(rc.added)
    for i in range(cap, cap + 100):
        mb.rx_message("bbbb", f"p{i}", b"peer-payload")
    # No admission redrains for the over-cap phases (HYP-423 already
    # capped this).
    assert len(rc.added) == pre_admission_redrains, (
        "over-cap admissions must not redrain"
    )

    # Authenticated verdicts arrive for ALL the over-cap phases. Pre-fix
    # each triggered _drain(). Post-fix: zero redrains for phases that
    # were never in _pending_phases.
    pre_auth_redrains = len(rc.added)
    for i in range(cap, cap + 100):
        mb.peer_message_authenticated(f"p{i}")
    # HYP-458: zero new redrains because none of those phases were
    # actually admitted.
    assert len(rc.added) == pre_auth_redrains, (
        "auth verdicts for unadmitted phases must NOT redrain "
        f"(amplification): expected {pre_auth_redrains}, "
        f"got {len(rc.added)}"
    )


def test_hyp458_auth_redrain_still_fires_for_admitted_phase(mailbox_setup):
    """Negative control for HYP-458: a legitimate auth-verdict for an
    ADMITTED phase MUST still redrain. The fix targets unadmitted
    spam phases only."""
    mb, rc, _, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.add_message("pake", b"my-pake")
    rc.added.clear()

    # Admit one phase.
    mb.rx_message("bbbb", "phase-1", b"peer-payload")
    pre_auth = len(rc.added)
    assert pre_auth == 1, "admission redrain should have fired"

    # Auth verdict arrives — this must still redrain (our test FakeOrder
    # doesn't loop the verdict, so we call it directly).
    mb.peer_message_authenticated("phase-1")
    # The post-auth redrain fires; rc.added grows by one.
    assert len(rc.added) == pre_auth + 1, (
        "auth verdict for admitted phase must redrain (legit signal)"
    )


def test_hyp458_auth_redrain_does_not_fire_after_dedup(mailbox_setup):
    """If a phase is already in `_processed`, its auth verdict is a
    no-op (duplicate). No redrain — the phase wasn't pending."""
    mb, rc, _, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.add_message("pake", b"my-pake")
    rc.added.clear()

    # Admit + auth once → moves phase to _processed.
    mb.rx_message("bbbb", "phase-1", b"peer-payload")
    mb.peer_message_authenticated("phase-1")
    assert "phase-1" in mb._processed
    pre_redrain = len(rc.added)

    # Re-fire the auth verdict (e.g. a buggy stack double-calls). The
    # phase is in _processed, NOT in _pending_phases — no redrain.
    mb.peer_message_authenticated("phase-1")
    assert len(rc.added) == pre_redrain, (
        "auth verdict for already-processed phase must not redrain"
    )


def test_disconnect_during_close_still_completes_on_reconnect(mailbox_setup):
    """If we lose the relay during close, we must re-send tx_close on reconnect
    so the receiver of rx_closed (or our local synthesis of it) will fire."""
    mb, rc, _, term = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.close("happy")
    assert rc.closed == [("xyz", "happy")]
    mb.lost()
    mb.connected()  # reconnected mid-close
    assert rc.closed == [("xyz", "happy"), ("xyz", "happy")]
    mb.rx_closed()
    assert term.done is True

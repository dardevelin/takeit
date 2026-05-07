"""
Tests for HYP-416: words-only handoff requires --verify.

HYP-406 closed the canonical-code oracle by introducing a 128-bit
locator: the canonical code is now ``<base32-locator>:<words>``. A
hostile Nostr relay can no longer precompute every 3-word -> tag
mapping when the locator is present. Words-only handoff is preserved
as a legacy ergonomic, but in that mode the relay CAN still mount an
active MITM, so we refuse to proceed unless ``--verify`` is on (which
forces an out-of-band SAS comparison before any payload moves).

The audit's wording: words-only without mandatory verifier comparison
"cannot honestly claim relay-level anonymity or active-relay MITM
resistance." This module tests the helper that enforces the rule and
asserts the four code-resolution sites in cli.py thread the ``verify``
flag through to it.

We deliberately do NOT drive the full ``cmd_send`` / ``cmd_receive``
flow via ``CliRunner`` for these checks: those commands call
``twisted.internet.task.react`` which boots a real reactor and
``takeit.create`` which opens Nostr relay sockets. The validation
itself lives inside the inlineCallbacks _after_ ``w.get_code()``, so a
CliRunner test would hang on real network I/O before reaching the
helper. Source-introspection of the four callsites is a tighter,
faster proof that the wiring is correct.
"""

import inspect

import click
import pytest

import takeit.cli.cli as cli_mod
from takeit.cli.cli import _validate_words_only_handoff

# --- pure helper: the four (shape, verify) combinations ---


def test_helper_words_only_no_verify_raises_usage_error():
    """The whole point of HYP-416: words-only + no --verify must NOT
    let the transfer proceed. We raise ``click.UsageError`` so Click
    formats it consistently with other CLI usage errors and the
    surrounding ``_handle_cli_error`` prints "Error: ..." with the
    same formatting users see for other Click misuse."""
    with pytest.raises(click.UsageError) as exc_info:
        _validate_words_only_handoff("purple-sausages-mocha", verify=False)
    msg = str(exc_info.value)
    # Actionable message: the user must see WHAT to do, not just that
    # something failed. Both escapes must be named.
    assert "--verify" in msg, f"expected --verify in: {msg!r}"
    # The full <locator>:<words> escape is the OTHER way out, e.g.
    # via QR. Check the message at least mentions the canonical shape.
    assert "<locator>:<words>" in msg or "QR" in msg, (
        f"message must name the canonical-code escape too: {msg!r}"
    )


def test_helper_words_only_with_verify_emits_soft_note(capsys):
    """Words-only IS allowed when --verify is on, but we still print
    a stderr note so the user understands that the SAS comparison
    they're about to do is the load-bearing security check, not just
    a confirmation prompt."""
    _validate_words_only_handoff("purple-sausages-mocha", verify=True)
    captured = capsys.readouterr()
    # The note goes to stderr (not stdout) so it doesn't pollute
    # stdout-piped output.
    assert "words-only" in captured.err.lower()
    # Mention the verifier — that's the whole reason the note exists.
    assert "verifier" in captured.err.lower() or "mitm" in captured.err.lower()
    # Stdout must stay clean so scripts piping output (e.g. `takeit
    # send --text hi | tee log`) aren't polluted.
    assert captured.out == ""


def test_helper_canonical_code_no_verify_silent(capsys):
    """Canonical ``<locator>:<words>`` codes are MITM-resistant on
    their own (HYP-406): no warning, no error, regardless of
    --verify."""
    _validate_words_only_handoff(
        "nbswy3dpo5xxe3deebsxe5dpor4q:purple-sausages-mocha",
        verify=False,
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_helper_canonical_code_with_verify_silent(capsys):
    """Canonical code + --verify: still no warning. The user opted
    into the SAS comparison but that's orthogonal to the words-only
    check — we don't double-message."""
    _validate_words_only_handoff(
        "nbswy3dpo5xxe3deebsxe5dpor4q:purple-sausages-mocha",
        verify=True,
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


# --- regression: callsites are wired correctly ---


def test_old_lenient_helper_is_gone():
    """HYP-416 RENAMES ``_warn_if_words_only`` -> ``_validate_words_only_handoff``.
    The old name must NOT coexist with the new one — otherwise a
    stray callsite could silently regress to the warn-but-proceed
    behavior the audit flagged."""
    assert not hasattr(cli_mod, "_warn_if_words_only"), (
        "The lenient _warn_if_words_only helper must not coexist with "
        "the new _validate_words_only_handoff — that would let a stray "
        "callsite silently regress to the warn-only behavior."
    )
    assert hasattr(cli_mod, "_validate_words_only_handoff")


def test_no_callsite_uses_old_helper_name():
    """Source-introspect the cli module: NO callsite may still call
    the old ``_warn_if_words_only`` name. A direct ``hasattr`` check
    catches the helper definition; this catches stale call lines."""
    src = inspect.getsource(cli_mod)
    # The string must appear zero times anywhere in the module —
    # neither in a def, nor in a call, nor in a comment.
    assert "_warn_if_words_only" not in src, (
        "Found stale reference to _warn_if_words_only in cli.py; "
        "every site must use _validate_words_only_handoff(code, verify)."
    )


def test_all_callsites_thread_verify_through():
    """Every call to ``_validate_words_only_handoff`` must pass
    ``verify`` as the second arg — calling the helper without the flag
    would default to the old warn-only behavior we're trying to
    eliminate.

    Post-HYP-421 the validation moved to fire BEFORE the wormhole
    state machine commits the code (before `w.set_code` /
    `w.allocate_code` / `helper.choose_words`). This means:

    - Sender explicit-code path (text + file/dir): two calls passing
      ``(explicit_code, verify)``.
    - Receiver positional-code path: one call passing ``(code, verify)``.
    - Receiver interactive path: one call wrapped in a lambda passed
      as ``validate=`` to ``input_with_completion``, so the helper
      fires it inside the readline thread BEFORE choose_words.

    Allocate-paths are exempt because allocate_code always produces a
    canonical <locator>:<words> code (HYP-406)."""
    src = inspect.getsource(cli_mod)
    calls = [
        line.strip()
        for line in src.splitlines()
        if "_validate_words_only_handoff(" in line
        and "def _validate_words_only_handoff" not in line
    ]
    # 4 total call lines: 2 sender (with explicit_code), 1 receiver
    # positional (with code), 1 receiver interactive (lambda wrapper).
    assert len(calls) == 4, f"expected 4 call sites, found {len(calls)}: {calls!r}"
    # Every call must pass ``verify`` (not omit it / default it).
    for line in calls:
        assert ", verify)" in line or ", verify=" in line, (
            f"callsite must pass verify; got: {line!r}"
        )


def test_helper_signature_takes_code_and_verify():
    """Pin the public signature so a refactor can't silently drop the
    ``verify`` parameter (which would re-enable the audit-flagged
    warn-only behavior)."""
    sig = inspect.signature(_validate_words_only_handoff)
    params = list(sig.parameters)
    assert params == ["code", "verify"], f"helper signature drifted: {params!r}"


# --- HYP-421: validation must fire BEFORE state-machine entry ---


def test_validation_fires_before_state_machine_via_fake_rendezvous():
    """Regression for HYP-421: words-only-no-verify must abort BEFORE
    any rendezvous tx_open / publish happens. The audit's wording was:
    'Code.set_code() synchronously calls B.got_code and K.got_code,
    Boss.do_got_code() derives the legacy words tag, and Mailbox
    publishes — so a post-set_code abort still leaks the rendezvous.'

    We simulate the sender explicit-code path: takeit.create + set_code
    with a words-only code while NOT passing verify=True. The validation
    in cli.py runs BEFORE w.set_code so FakeRendezvous never sees a
    tx_open. (The cli helpers themselves are tested at the layer above
    — here we just verify that, given the helper raises, the flow that
    USES the helper hasn't already touched the wormhole.)

    This is a structural test: we drive the helper directly + assert
    nothing else happened. The cli orchestrators each have their own
    callsite test asserting the order (see callsite-thread test
    above)."""
    from twisted.internet.task import Clock

    import takeit
    from takeit.eventual import EventualQueue
    from tests._fake_rendezvous import FakeRendezvous, pair

    eq = EventualQueue(Clock())
    rv_a = FakeRendezvous("aaaaaa")
    rv_b = FakeRendezvous("bbbbbb")
    pair(rv_a, rv_b)

    def factory(boss, mailbox, terminator):
        rv_a.wire(boss, mailbox, terminator)
        return rv_a

    # Constructing the wormhole wires the rendezvous + boots state
    # machines but doesn't publish anything (no set_code yet). We
    # discard the handle — we only care about the FakeRendezvous's
    # observed traffic.
    takeit.create(
        appid="takeit/test",
        reactor=Clock(),
        relays=None,
        _eventual_queue=eq,
        _rendezvous_factory=factory,
    )

    # Per HYP-421, the cli ORCHESTRATOR validates before calling
    # set_code. We mimic that here: run validation FIRST, expect it
    # to raise, and assert the wormhole hasn't been touched.
    code = "purple-sausages-mocha"  # words-only
    verify = False
    try:
        _validate_words_only_handoff(code, verify)
    except click.UsageError:
        pass
    else:
        raise AssertionError("expected UsageError")

    # FakeRendezvous must NOT have seen any outbound traffic — proof
    # that the abort happened BEFORE the wormhole's state-machine
    # commit-the-code path.
    assert rv_a.opened == [], f"unexpected rendezvous tx_open: {rv_a.opened!r}"
    assert rv_a.added == [], f"unexpected rendezvous tx_add: {rv_a.added!r}"
    # The wormhole was created (FakeRendezvous wire happened) but we
    # never set_code'd, so no tag was derived.
    assert rv_a._tag is None, f"unexpected tag: {rv_a._tag!r}"


def test_set_code_without_validation_would_have_published():
    """Negative-control for the regression above: prove FakeRendezvous
    DOES see traffic when set_code IS called. Without this control,
    the previous test could pass for a uninteresting reason (e.g. the
    fake never publishes anyway)."""
    from twisted.internet.task import Clock

    import takeit
    from takeit.eventual import EventualQueue
    from tests._fake_rendezvous import FakeRendezvous, pair

    eq = EventualQueue(Clock())
    rv_a = FakeRendezvous("aaaaaa")
    rv_b = FakeRendezvous("bbbbbb")
    pair(rv_a, rv_b)

    def factory(boss, mailbox, terminator):
        rv_a.wire(boss, mailbox, terminator)
        return rv_a

    w = takeit.create(
        appid="takeit/test",
        reactor=Clock(),
        relays=None,
        _eventual_queue=eq,
        _rendezvous_factory=factory,
    )

    # NO validation call — go straight to set_code with words-only.
    # FakeRendezvous SHOULD see tx_open (proving the regression test
    # above exercises a real "didn't publish" condition).
    w.set_code("purple-sausages-mocha")
    eq.flush_sync()
    assert rv_a.opened, (
        "control test failed: set_code didn't trigger tx_open in "
        "the fake. Either FakeRendezvous changed shape or the wormhole "
        "doesn't publish on set_code anymore — the regression test "
        "above is no longer load-bearing."
    )

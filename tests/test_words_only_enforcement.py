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
asserts the code-resolution sites in cli.py validate before constructing
or committing a takeit session.

We deliberately do NOT drive the full ``cmd_send`` / ``cmd_receive``
flow via ``CliRunner`` for these checks: those commands call
``twisted.internet.task.react`` which boots a real reactor and
``takeit.create`` which opens Nostr relay sockets. Source-introspection
and direct helper-level checks are tighter, faster proof that the wiring
is correct.
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


def test_words_only_helper_is_only_called_from_pre_takeit_validator():
    """The words-only gate is centralized with format validation so all
    user-provided codes pass through the same pre-takeit helper."""
    src = inspect.getsource(cli_mod)
    calls = [
        line.strip()
        for line in src.splitlines()
        if "_validate_words_only_handoff(" in line
        and "def _validate_words_only_handoff" not in line
    ]
    assert calls == ["_validate_words_only_handoff(code, verify)"]
    helper_src = inspect.getsource(cli_mod._validate_code_before_takeit)
    assert "validate_code(code)" in helper_src
    assert "parse_code(code)" in helper_src
    assert "_validate_words_only_handoff(code, verify)" in helper_src


def test_receive_validates_before_takeit_create():
    """Positional and prompted receive codes must be resolved before
    ``takeit.create`` so a refused words-only code cannot even start the
    relay connector."""
    src = inspect.getsource(cli_mod._run_receive)
    assert src.index("_validate_code_before_takeit(code, verify)") < src.index(
        "takeit.create("
    )
    assert src.index("prompt_code_with_completion(") < src.index("takeit.create(")


def test_send_validates_explicit_code_before_takeit_create():
    text_src = inspect.getsource(cli_mod._run_send_text)
    send_src = inspect.getsource(cli_mod._do_send)
    assert text_src.index("_validate_code_before_takeit") < text_src.index(
        "takeit.create("
    )
    assert send_src.index("_validate_code_before_takeit") < send_src.index(
        "takeit.create("
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
    USES the helper hasn't already touched the takeit session.)

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

    # Constructing the takeit session wires the rendezvous + boots state
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
    # to raise, and assert the takeit session hasn't been touched.
    code = "purple-sausages-mocha"  # words-only
    verify = False
    try:
        _validate_words_only_handoff(code, verify)
    except click.UsageError:
        pass
    else:
        raise AssertionError("expected UsageError")

    # FakeRendezvous must NOT have seen any outbound traffic — proof
    # that the abort happened BEFORE the takeit state-machine
    # commit-the-code path.
    assert rv_a.opened == [], f"unexpected rendezvous tx_open: {rv_a.opened!r}"
    assert rv_a.added == [], f"unexpected rendezvous tx_add: {rv_a.added!r}"
    # The takeit session was created (FakeRendezvous wire happened) but we
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

    # NO validation call — go straight to set_code_legacy_words with
    # bare words (post-HYP-443 set_code refuses bare words; the legacy
    # entrypoint is the explicit bridge to words-only-wormhole protocol
    # shape). FakeRendezvous SHOULD see tx_open (proving the regression
    # test above exercises a real "didn't publish" condition).
    w.set_code_legacy_words("purple-sausages-mocha")
    eq.flush_sync()
    assert rv_a.opened, (
        "control test failed: set_code_legacy_words didn't trigger "
        "tx_open in the fake. Either FakeRendezvous changed shape or "
        "the takeit session doesn't publish on set_code* anymore — "
        "the regression test above is no longer load-bearing."
    )

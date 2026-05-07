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
    eliminate. The four sites: ``_run_send_text``, ``_do_send`` (file
    + dir), and ``_run_receive`` (allocate / explicit-code /
    interactive paths share one call site)."""
    src = inspect.getsource(cli_mod)
    # Find every call line. The argument list must literally be
    # `(code, verify)` — no other shape is acceptable. (If a future
    # caller wants different variable names, this test should be
    # updated AT THE SAME TIME as the rename.)
    calls = [
        line.strip()
        for line in src.splitlines()
        if "_validate_words_only_handoff(" in line
        and "def _validate_words_only_handoff" not in line
    ]
    # Three call lines today (text-send, file/dir-send, receive). The
    # receiver --allocate / explicit / interactive paths converge on
    # ONE call line because all three branches set ``code`` first.
    assert len(calls) == 3, f"expected 3 call sites, found {len(calls)}: {calls!r}"
    for line in calls:
        assert "_validate_words_only_handoff(code, verify)" in line, (
            f"callsite must pass (code, verify); got: {line!r}"
        )


def test_helper_signature_takes_code_and_verify():
    """Pin the public signature so a refactor can't silently drop the
    ``verify`` parameter (which would re-enable the audit-flagged
    warn-only behavior)."""
    sig = inspect.signature(_validate_words_only_handoff)
    params = list(sig.parameters)
    assert params == ["code", "verify"], f"helper signature drifted: {params!r}"

"""
Tests for HYP-433: directory-send cleanup must not unlink an
attacker-pre-created file at the predictable temp-zip path.

The threat: takeit send <dir> writes a temp zip at
.{dir_name}.takeit-zip-{pid} alongside the source directory.
materialize_and_hash uses O_EXCL|O_NOFOLLOW so it REFUSES to write
to a pre-existing path (HYP-407 hardening). But pre-fix, the
surrounding try/finally unconditionally os.unlink(tmp_zip_path) — so
an attacker who pre-creates the predictable path could have takeit
delete arbitrary files via this cleanup primitive.

The fix: track whether materialize_and_hash actually created the
file (a `tmp_zip_created` flag set only after a successful return)
and only unlink in the finally if the flag is set.

Testing approach: this is a flow that lives inside cmd_send (a
long-running Click command driving a reactor) so a CliRunner test
won't terminate without a real peer. Instead we source-introspect
cmd_send to assert the load-bearing pattern (flag-based finally) is
in place. Per `feedback_no_brittle_format_assertions.md`, the check
normalizes whitespace before substring matching so a future
ruff-format pass can't break it. The accompanying behavioral
defense is `test_materialize_refuses_pre_existing_path` in
test_directory_zip.py, which proves materialize_and_hash itself
won't write to a pre-existing path.
"""

import inspect

from takeit.cli import cli as cli_mod


def _normalize(s):
    return " ".join(s.split())


def test_directory_send_finally_unlinks_only_when_we_created_the_file():
    """The cleanup helper must check a `tmp_zip_created` flag before
    calling os.unlink. The flag is set ONLY after materialize_and_hash
    returns successfully (i.e. only when WE wrote the file).

    Without this flag, an attacker who pre-creates
    `.{dir_name}.takeit-zip-{pid}` in the source directory could have
    takeit delete arbitrary files via this cleanup."""
    # _run_send is the inlineCallbacks coroutine that cmd_send dispatches
    # to via twisted.internet.task.react. The directory-prep block lives
    # there.
    src = inspect.getsource(cli_mod._run_send)
    normalized = _normalize(src)
    # Flag is initialized to False before the try block.
    assert "tmp_zip_created = False" in normalized, (
        "expected the directory-send block to declare "
        "`tmp_zip_created = False` before its try block"
    )
    # Flag is set to True only after a successful materialize_and_hash.
    assert "tmp_zip_created = True" in normalized
    # The unlink is gated by the flag.
    assert "if tmp_zip_created:" in normalized, (
        "expected the finally block to gate os.unlink behind "
        "`if tmp_zip_created:` so an attacker who pre-creates the "
        "predictable temp-zip path cannot have takeit delete it"
    )

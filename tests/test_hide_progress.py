"""
Tests for `--hide-progress` (HYP-391).

The flag suppresses both the progress bar and the toss-spinner so
scripted use (CI, pipes) gets clean stderr without ANSI escape codes.
Auto-suppression on non-TTY stays as it was (matches wormhole's UX).
"""

from click.testing import CliRunner

from takeit.cli.cli import (
    _make_progress_bar,
    _make_spinner,
    cmd_receive,
    cmd_send,
)

# --- Click flag presence ---


def test_send_has_hide_progress_flag():
    runner = CliRunner()
    result = runner.invoke(cmd_send, ["--help"])
    assert result.exit_code == 0
    assert "--hide-progress" in result.output


def test_receive_has_hide_progress_flag():
    runner = CliRunner()
    result = runner.invoke(cmd_receive, ["--help"])
    assert result.exit_code == 0
    assert "--hide-progress" in result.output


# --- _make_progress_bar gate ---


def test_progress_bar_returns_noop_when_hidden(monkeypatch):
    """When --hide-progress is set, the bar is a no-op shim regardless
    of TTY state — explicit suppression beats TTY auto-detect."""
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    bar = _make_progress_bar(1024, desc="test", hide=True)
    # The shim has update/close + context-manager methods but no real
    # tqdm machinery underneath.
    assert bar.__class__.__name__ == "_Noop"


def test_progress_bar_returns_noop_on_non_tty(monkeypatch):
    """Existing behavior: not a TTY → no bar."""
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    bar = _make_progress_bar(1024, desc="test", hide=False)
    assert bar.__class__.__name__ == "_Noop"


def test_progress_bar_real_when_tty_and_not_hidden(monkeypatch):
    """TTY + hide=False → real (wrapped tqdm) bar."""
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    bar = _make_progress_bar(1024, desc="test", hide=False)
    # The real path returns a _SpinningBar wrapping a tqdm bar; the
    # Noop class is the only other option, so distinguish by name.
    assert bar.__class__.__name__ != "_Noop"
    bar.close()


# --- _make_spinner gate ---


def test_spinner_returns_noop_when_hidden(monkeypatch):
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    sp = _make_spinner(reactor=None, hide=True)
    # Same Noop pattern: start/stop are present but do nothing.
    sp.start()
    sp.stop()


def test_spinner_returns_noop_on_non_tty(monkeypatch):
    """The toss-spinner is purely visual — when stdout isn't a TTY it's
    just ANSI noise in the log. Auto-suppress."""
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    sp = _make_spinner(reactor=None, hide=False)
    sp.start()
    sp.stop()


def test_spinner_real_when_tty_and_not_hidden(monkeypatch):
    """TTY + hide=False → real TossSpinner. We don't actually start it
    (would need a reactor) — just confirm we got the live class back."""
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    from takeit.cli._spinner import TossSpinner

    sp = _make_spinner(reactor=None, hide=False)
    assert isinstance(sp, TossSpinner)

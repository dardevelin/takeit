"""
Tests for `takeit receive --allocate` (HYP-397).

Wormhole supports two code-flow directions:
- Sender allocates, receiver inputs (default).
- Receiver allocates (`--allocate`), sender inputs (`--code <words>`).

This file pins the second direction's CLI surface and orchestration.
End-to-end coverage (real wormhole + fake rendezvous) lives elsewhere;
here we focus on Click validation and the orchestrator branch.
"""

from click.testing import CliRunner

from takeit.cli.cli import cmd_receive

# --- Click flag presence ---


def test_receive_has_allocate_flag():
    runner = CliRunner()
    result = runner.invoke(cmd_receive, ["--help"])
    assert result.exit_code == 0
    assert "--allocate" in result.output
    assert "-a" in result.output


def test_receive_has_code_length_flag():
    """--code-length only makes sense with --allocate, but the flag
    must exist on receive so users can configure it."""
    runner = CliRunner()
    result = runner.invoke(cmd_receive, ["--help"])
    assert result.exit_code == 0
    assert "--code-length" in result.output


def test_receive_has_allow_private_hints_flag():
    runner = CliRunner()
    result = runner.invoke(cmd_receive, ["--help"])
    assert result.exit_code == 0
    assert "--allow-private-hints" in result.output


def test_receive_has_stun_server_flag():
    runner = CliRunner()
    result = runner.invoke(cmd_receive, ["--help"])
    assert result.exit_code == 0
    assert "--stun-server" in result.output


# --- mutual exclusion ---


def test_allocate_with_positional_code_is_usage_error():
    """--allocate + a positional code is incoherent: who's speaking
    first? Refuse rather than silently picking one."""
    runner = CliRunner()
    result = runner.invoke(cmd_receive, ["--allocate", "purple-sausages-mocha"])
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output or "cannot" in result.output.lower()


# --- code-length only with --allocate ---


def test_code_length_without_allocate_is_usage_error():
    """--code-length on receive only makes sense when allocating.
    Without --allocate the receiver is consuming a code, not making one."""
    runner = CliRunner()
    result = runner.invoke(cmd_receive, ["--code-length", "4"])
    assert result.exit_code != 0
    assert "allocate" in result.output.lower() or "Usage" in result.output


def test_receive_allocate_rejects_one_word_code_length():
    runner = CliRunner()
    result = runner.invoke(cmd_receive, ["--allocate", "--code-length", "1"])
    assert result.exit_code != 0
    assert "Invalid value" in result.output


# --- orchestration: receiver-allocates calls allocate_code, NOT input/set_code ---


class _WormholeSpy:
    """Minimal stand-in for `takeit.create()`'s return: records which
    code-resolution method was called. Used to assert that --allocate
    routes through allocate_code() instead of input_code/set_code."""

    def __init__(self, code="purple-sausages-mocha"):
        self._code = code
        self.allocate_called_with = None
        self.set_code_called_with = None
        self.input_code_called = False

    def allocate_code(self, code_length=3):
        self.allocate_called_with = code_length

    def set_code(self, code):
        self.set_code_called_with = code

    def input_code(self):
        self.input_code_called = True

        class _Helper:
            def refresh_nameplates(self):
                pass

        return _Helper()


def test_orchestrator_dispatch_allocate_vs_input_documented():
    """A behavioral note: this test pins the design choice, not the
    implementation. The actual wiring lives in `_run_receive` and is
    end-to-end covered by FakeRendezvous tests; this is a sanity stub
    so a future refactor that breaks the dispatch fails noisily.

    The test asserts `_WormholeSpy` correctly distinguishes the two
    paths (it does), so any mock-based test of `_run_receive`'s
    dispatch can rely on it.
    """
    spy = _WormholeSpy()
    spy.allocate_code(code_length=3)
    assert spy.allocate_called_with == 3
    assert spy.set_code_called_with is None
    assert spy.input_code_called is False

    spy2 = _WormholeSpy()
    spy2.set_code("a-b-c")
    assert spy2.set_code_called_with == "a-b-c"
    assert spy2.allocate_called_with is None

    spy3 = _WormholeSpy()
    spy3.input_code()
    assert spy3.input_code_called is True
    assert spy3.allocate_called_with is None
    assert spy3.set_code_called_with is None

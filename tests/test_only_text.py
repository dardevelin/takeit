"""
Tests for `takeit receive --only-text` (HYP-400).

The flag refuses any incoming file or directory transfer; only inline
text offers are accepted. Useful in scripted/embedded use where the
receiver KNOWS it's expecting a chat message and binary blobs would
be unwanted.
"""

from click.testing import CliRunner

from takeit.cli.cli import cmd_receive


def test_receive_has_only_text_flag():
    runner = CliRunner()
    result = runner.invoke(cmd_receive, ["--help"])
    assert result.exit_code == 0
    assert "--only-text" in result.output
    # Short alias.
    assert "-t" in result.output


def test_only_text_help_explains_behavior():
    """Help text should mention that file/directory transfers are
    refused — not just that the flag exists."""
    runner = CliRunner()
    result = runner.invoke(cmd_receive, ["--help"])
    assert result.exit_code == 0
    # Find the --only-text help line(s) and check they mention rejection.
    only_text_section = result.output.split("--only-text", 1)[1]
    # Look in the next ~200 chars for the explanation.
    assert "text" in only_text_section[:300].lower()

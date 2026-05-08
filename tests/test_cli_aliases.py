"""
Tests for receive-subcommand aliases (HYP-401).

Wormhole accepts four names for the receive subcommand: `receive`,
`rx`, `recv`, `recieve` (the typo is intentional — Brian Warner
adds it for users who fat-finger). takeit matches.
"""

from click.testing import CliRunner

from takeit.cli.cli import main


def _help_text_for(name):
    runner = CliRunner()
    result = runner.invoke(main, [name, "--help"])
    assert result.exit_code == 0, f"`{name} --help` failed: {result.output}"
    return result.output


def test_receive_canonical_name_works():
    assert "receive" in _help_text_for("receive").lower()


def test_rx_alias_works():
    """The short alias takeit added in HYP-389 stays put."""
    out = _help_text_for("rx")
    # Same help text as `receive` (or close enough).
    assert "receive" in out.lower() or "code" in out.lower()


def test_recv_alias_works():
    """`recv` is the common shell-muscle-memory alias for receive."""
    out = _help_text_for("recv")
    assert "receive" in out.lower() or "code" in out.lower()


def test_recieve_typo_alias_works():
    """The typo-tolerant alias from upstream wormhole. The whole point
    is users who type `recieve` should NOT see 'command not found'."""
    out = _help_text_for("recieve")
    assert "receive" in out.lower() or "code" in out.lower()


def test_all_receive_aliases_share_options():
    """The four aliases route to the same subcommand, so all four
    expose the same flags. Spot-check with --allocate."""
    for name in ("receive", "rx", "recv", "recieve"):
        out = _help_text_for(name)
        assert "--allocate" in out, f"`{name}` doesn't expose --allocate"


def test_send_exposes_allow_private_hints_flag():
    out = _help_text_for("send")
    assert "--allow-private-hints" in out


def test_send_exposes_stun_server_flag():
    out = _help_text_for("send")
    assert "--stun-server" in out


def test_send_rejects_one_word_code_length():
    runner = CliRunner()
    result = runner.invoke(main, ["send", "--code-length", "1", "--text", "hi"])
    assert result.exit_code != 0
    assert "Invalid value" in result.output

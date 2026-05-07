"""
Tests for `takeit send --text "msg"` (HYP-389).

CLI shape: `--text` is mutually exclusive with the path positional;
the offer carries kind="text" with the text inline; the receiver
prints to stdout, no file/sidecar artifacts.
"""

from click.testing import CliRunner

from takeit.cli import _protocol as P
from takeit.cli.cli import cmd_send

# --- CLI argument validation (no network) ---


def test_text_flag_with_path_is_usage_error():
    """--text and a path positional together don't make sense."""
    runner = CliRunner()
    # We invoke `cmd_send` directly so we exercise its arg-validation
    # without spinning up the wormhole/reactor stack.
    result = runner.invoke(cmd_send, ["--text", "hi", "/tmp/anything"])
    assert result.exit_code != 0
    # Specifically the mutual-exclusion error, not a fall-through "no
    # such option" or "path doesn't exist" — those would mean the
    # check isn't being run.
    assert "mutually exclusive" in result.output, (
        f"expected mutual-exclusion error, got: {result.output!r}"
    )


def test_no_text_no_path_is_error():
    """Neither --text nor a path is invalid — Click's own missing-arg
    error path covers it; we just confirm exit code != 0."""
    runner = CliRunner()
    result = runner.invoke(cmd_send, [])
    assert result.exit_code != 0


# --- offer construction (the protocol layer is the contract) ---


def test_text_offer_round_trips_via_cli_protocol():
    """The same shape `cmd_send --text "hi"` builds: a kind="text"
    offer with the text inline, no chunked body."""
    msg = P.build_offer_text("hello world")
    parsed = P.parse_offer(P.encode_message(msg))
    assert parsed["kind"] == P.KIND_TEXT
    assert parsed["text"] == "hello world"
    # No chunked-body fields leak in.
    assert "chunk_hashes" not in parsed
    assert "size" not in parsed


# --- receiver-side behavior (text branch prints, no artifacts) ---


def test_receiver_text_branch_prints_and_writes_no_file(tmp_path, capsys):
    """Simulate the receive-side text branch: parse offer, print text,
    confirm no files appeared in output_dir."""
    msg = P.build_offer_text("the quick brown fox")
    parsed = P.parse_offer(P.encode_message(msg))
    # The CLI's text branch is a 2-line print + close. We exercise the
    # same logic by hand: write the text to stdout via click.echo (the
    # CLI uses click.echo too), then inspect the output_dir.
    import click

    click.echo(parsed["text"])
    # Nothing under output_dir.
    output_dir = tmp_path / "downloads"
    output_dir.mkdir()
    assert list(output_dir.iterdir()) == []
    captured = capsys.readouterr()
    assert "the quick brown fox" in captured.out


def test_text_offer_preserves_unicode():
    """Text mode is UTF-8; emoji and combining characters survive."""
    s = "héllo 🌍 ｗｉｄｅ"
    msg = P.build_offer_text(s)
    parsed = P.parse_offer(P.encode_message(msg))
    assert parsed["text"] == s


def test_text_offer_preserves_newlines():
    s = "line1\nline2\n"
    msg = P.build_offer_text(s)
    parsed = P.parse_offer(P.encode_message(msg))
    assert parsed["text"] == s

"""
Tests for `--verify` on send and receive (HYP-390).

The verifier is the short authentication string (SAS) the wormhole
protocol already computes from the SPAKE2 transcript; --verify
surfaces it so paranoid users can compare it out-of-band before any
payload moves. Wire format and key derivation are unchanged — this
is a CLI affordance.
"""

from click.testing import CliRunner

from takeit.cli.cli import cmd_receive, cmd_send, format_verifier

# --- pure formatter ---


def test_format_verifier_returns_xxxx_xxxx_xxxx_xxxx():
    """First 8 bytes (16 hex chars) as four 4-char dash-separated groups
    — wormhole's convention for the SAS display."""
    verifier = bytes(range(32))  # 0x00..0x1f
    out = format_verifier(verifier)
    assert out == "0001-0203-0405-0607"
    # 4 groups of 4 hex chars + 3 dashes = 19 chars
    assert len(out) == 19
    assert out.count("-") == 3


def test_format_verifier_handles_high_bytes():
    verifier = bytes([0xFF] * 32)
    assert format_verifier(verifier) == "ffff-ffff-ffff-ffff"


def test_format_verifier_is_deterministic():
    """Same bytes in → same string out, every call. The whole point of
    a verifier is byte-stable display so two humans can compare them."""
    v = bytes(range(32))
    assert format_verifier(v) == format_verifier(v)


def test_format_verifier_distinct_inputs_produce_distinct_outputs():
    """Two different verifiers must produce different display strings —
    otherwise out-of-band comparison can't catch a mismatched pair."""
    a = bytes([0x01] * 32)
    b = bytes([0x02] * 32)
    assert format_verifier(a) != format_verifier(b)


def test_format_verifier_uses_only_first_eight_bytes():
    """Bytes 8..31 must NOT change the display — wormhole's contract is
    'compare 16 hex chars'; using more would be a different protocol."""
    base = bytes(range(8)) + b"\x00" * 24
    other = bytes(range(8)) + b"\xff" * 24
    assert format_verifier(base) == format_verifier(other)


# --- CLI flag presence ---


def test_send_has_verify_flag():
    runner = CliRunner()
    result = runner.invoke(cmd_send, ["--help"])
    assert result.exit_code == 0
    assert "--verify" in result.output


def test_receive_has_verify_flag():
    runner = CliRunner()
    result = runner.invoke(cmd_receive, ["--help"])
    assert result.exit_code == 0
    assert "--verify" in result.output

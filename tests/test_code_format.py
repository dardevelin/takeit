"""
Tests for takeit's two-part code format (HYP-406).

Post-HYP-406 a takeit code is `<base32-locator>:<words>`. The locator
is 128 random bits (16 bytes → 26 base32 chars without padding) carrying
the public Nostr routing tag; the words are the SPAKE2 password.

`parse_code(s)` is the canonical splitter: given a user-typed string,
return (locator_bytes_or_None, words_str). Words-only handoff (no
locator) is supported as a legacy ergonomic but with explicit warnings
and mandatory verifier comparison enforced upstream.
"""

import pytest

from takeit._code_format import (
    LOCATOR_BYTES,
    encode_locator,
    generate_locator,
    parse_code,
)

# --- generate_locator ---


def test_generate_locator_returns_16_bytes():
    loc = generate_locator()
    assert isinstance(loc, bytes)
    assert len(loc) == LOCATOR_BYTES == 16


def test_generate_locator_is_random():
    """Two calls must produce different bytes — the whole point of a
    fresh-per-transfer locator is that it's not predictable."""
    locs = {generate_locator() for _ in range(100)}
    # Birthday-collision probability for 100 16-byte values is ~3e-37.
    assert len(locs) == 100


# --- encode_locator ---


def test_encode_locator_is_base32_lowercase_no_padding():
    loc = bytes(range(16))  # 0x00..0x0f
    encoded = encode_locator(loc)
    # 16 bytes of base32 with no padding = ceil(16 * 8 / 5) = 26 chars.
    assert len(encoded) == 26
    assert encoded == encoded.lower()
    assert "=" not in encoded
    # All chars in the RFC 4648 base32 alphabet (lowercased).
    assert all(c in "abcdefghijklmnopqrstuvwxyz234567" for c in encoded)


def test_encode_locator_round_trips_via_parse():
    """encode_locator(loc) is the inverse of parse_code's locator-decode
    on a `<encoded>:<words>` shape."""
    loc = bytes(range(16))
    code = f"{encode_locator(loc)}:purple-sausages-mocha"
    parsed_loc, parsed_words = parse_code(code)
    assert parsed_loc == loc
    assert parsed_words == "purple-sausages-mocha"


def test_encode_locator_rejects_wrong_length():
    with pytest.raises(ValueError, match="16 bytes"):
        encode_locator(b"\x00" * 15)
    with pytest.raises(ValueError, match="16 bytes"):
        encode_locator(b"\x00" * 17)


# --- parse_code: full-code shape ---


def test_parse_code_full_shape():
    """`<26-char-base32>:<words>` round-trips through encode + parse."""
    loc = generate_locator()
    code = f"{encode_locator(loc)}:purple-sausages-mocha"
    parsed_loc, words = parse_code(code)
    assert parsed_loc == loc
    assert words == "purple-sausages-mocha"


def test_parse_code_full_shape_with_4_words():
    """The words section is opaque to parse_code — any wordlist length
    is accepted; word-count validation lives downstream."""
    loc = generate_locator()
    code = f"{encode_locator(loc)}:a-b-c-d"
    parsed_loc, words = parse_code(code)
    assert parsed_loc == loc
    assert words == "a-b-c-d"


# --- parse_code: words-only legacy shape ---


def test_parse_code_words_only_returns_none_locator():
    """Words alone is the legacy shape. parse_code returns
    (None, words) so the caller can branch on locator-presence."""
    parsed_loc, words = parse_code("purple-sausages-mocha")
    assert parsed_loc is None
    assert words == "purple-sausages-mocha"


def test_parse_code_distinguishes_full_vs_words_by_colon():
    """The colon is the discriminator. A code with `:` is full-shape;
    without `:` is words-only. (Words use `-` as separator, so no
    accidental colon collision.)"""
    full_loc, full_words = parse_code(
        "aaaaaaaaaaaaaaaaaaaaaaaaaa:purple-sausages-mocha"
    )
    words_loc, words_words = parse_code("purple-sausages-mocha")
    assert full_loc is not None
    assert words_loc is None
    assert full_words == words_words


# --- parse_code: malformed input ---


def test_parse_code_rejects_empty_string():
    with pytest.raises(ValueError, match="empty|must"):
        parse_code("")


def test_parse_code_rejects_whitespace():
    """Whitespace inside a code is always a typo — refuse rather than
    silently strip (which would mask real corruption)."""
    with pytest.raises(ValueError, match="whitespace"):
        parse_code("purple-sausages mocha")
    with pytest.raises(ValueError, match="whitespace"):
        parse_code("\tpurple-sausages-mocha")


def test_parse_code_rejects_too_many_colons():
    """A code can have AT MOST one `:` (separating locator from words).
    Two `:` is malformed (the second one would be inside the words,
    which is supposed to use `-`)."""
    with pytest.raises(ValueError, match="colon|format"):
        parse_code("aaaaa:bbbb:cccc")


def test_parse_code_rejects_bad_base32_in_locator():
    """A locator that doesn't decode as valid base32 is malformed.
    Only the RFC 4648 alphabet (a-z, 2-7) is accepted."""
    # Length 26 (correct) but contains non-base32 chars.
    bad = "1" * 26 + ":purple-sausages-mocha"
    with pytest.raises(ValueError, match="base32|locator"):
        parse_code(bad)


def test_parse_code_rejects_wrong_length_locator():
    """A locator section that doesn't decode to exactly 16 bytes is
    malformed. Most common cause: someone trimmed/extended manually."""
    short = "aaaaa:purple-sausages-mocha"  # 5 chars instead of 26
    with pytest.raises(ValueError, match="locator"):
        parse_code(short)
    long = "a" * 50 + ":purple-sausages-mocha"
    with pytest.raises(ValueError, match="locator"):
        parse_code(long)


def test_parse_code_rejects_empty_words_section():
    """A code with a colon but no words is malformed."""
    loc_b32 = encode_locator(generate_locator())
    with pytest.raises(ValueError, match="words|empty"):
        parse_code(f"{loc_b32}:")


def test_parse_code_rejects_empty_locator_section():
    """A code starting with a colon (empty locator) is malformed."""
    with pytest.raises(ValueError, match="locator|empty"):
        parse_code(":purple-sausages-mocha")


# --- case sensitivity ---


def test_parse_code_locator_is_case_insensitive():
    """Base32 is case-insensitive by RFC 4648; we accept both for
    user-friendliness when reading codes off paper or screen."""
    loc = generate_locator()
    lower = encode_locator(loc)
    upper_code = f"{lower.upper()}:purple-sausages-mocha"
    parsed_loc, _ = parse_code(upper_code)
    assert parsed_loc == loc


def test_parse_code_words_preserve_case():
    """Words come from the PGP wordlist which is all-lowercase. We
    don't auto-lowercase user input — if they typed it weird, we
    return it weird and let SPAKE2 fail."""
    parsed_loc, words = parse_code("Purple-Sausages-Mocha")
    assert words == "Purple-Sausages-Mocha"

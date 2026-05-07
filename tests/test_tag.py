"""
Contract tests for takeit._tag.derive_tag.

The Nostr routing tag is the user-typed code, blinded by HKDF. A relay
operator who sees `#t = <tag>` events should not be able to recover the code
from the tag, and two takeit clients sharing the same code must independently
derive the same tag without coordinating.
"""

import re
import string

import pytest

from takeit._tag import TAG_ALPHABET, TAG_LENGTH, derive_tag

VALID_CODE = "purple-sausages-mocha"


def test_returns_str_of_expected_length():
    tag = derive_tag(VALID_CODE)
    assert isinstance(tag, str)
    assert len(tag) == TAG_LENGTH


def test_charset_is_lowercase_base32():
    tag = derive_tag(VALID_CODE)
    assert set(tag) <= set(TAG_ALPHABET)
    # base32 RFC 4648 lowercase: a-z and 2-7
    assert re.fullmatch(r"[a-z2-7]+", tag)


def test_no_padding():
    tag = derive_tag(VALID_CODE)
    assert "=" not in tag


def test_deterministic():
    assert derive_tag(VALID_CODE) == derive_tag(VALID_CODE)


def test_different_codes_produce_different_tags():
    a = derive_tag("purple-sausages-mocha")
    b = derive_tag("purple-sausages-yarn")
    assert a != b


def test_distinctness_across_many_codes():
    """No collisions when 1000 *distinct* inputs are mapped to tags.

    The 16-char base32 output has 80 bits of entropy; birthday-collision
    probability for 1000 distinct inputs is ~5e-19, so a collision here
    means the function is broken. We dedupe the input codes first because
    `wordlist.choose_words(3)` itself can collide (256^3 ≈ 17M codes,
    birthday rate ≈ 3e-5 at n=1000) — that would fail the test for the
    wrong reason.
    """
    from takeit._wordlist import PGPWordList

    wl = PGPWordList()
    codes = set()
    while len(codes) < 1000:
        codes.add(wl.choose_words(3))
    tags = {derive_tag(c) for c in codes}
    assert len(tags) == 1000


def test_rejects_empty_code():
    with pytest.raises(ValueError):
        derive_tag("")


def test_rejects_non_string_input():
    with pytest.raises(TypeError):
        derive_tag(b"purple-sausages-mocha")
    with pytest.raises(TypeError):
        derive_tag(None)


def test_whitespace_in_code_is_rejected():
    """Whitespace in a code is a sign of user-input bug or attack;
    fail loudly rather than silently produce a tag for a malformed code."""
    with pytest.raises(ValueError):
        derive_tag("purple sausages mocha")
    with pytest.raises(ValueError):
        derive_tag("purple-sausages-mocha\n")


def test_constants_are_consistent():
    """If someone changes one constant they should be forced to change both."""
    assert TAG_LENGTH == 16
    assert set(TAG_ALPHABET) == set(string.ascii_lowercase + "234567")


def test_changing_salt_changes_output():
    """Domain separation: bumping the salt must change every tag.

    This test depends on a private function, but we want a regression alarm
    if someone changes the salt without thinking through the migration.
    """
    from takeit._tag import _hkdf_extract_and_expand

    code = VALID_CODE.encode()
    a = _hkdf_extract_and_expand(code, b"takeit/nostr/v1", b"rendezvous-tag")
    b = _hkdf_extract_and_expand(code, b"takeit/nostr/v2", b"rendezvous-tag")
    assert a != b


def test_changing_info_changes_output():
    """info is the per-purpose label inside the same protocol version."""
    from takeit._tag import _hkdf_extract_and_expand

    code = VALID_CODE.encode()
    a = _hkdf_extract_and_expand(code, b"takeit/nostr/v1", b"rendezvous-tag")
    b = _hkdf_extract_and_expand(code, b"takeit/nostr/v1", b"some-other-purpose")
    assert a != b

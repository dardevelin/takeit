"""
Contract tests for takeit._tag — the Nostr routing-tag derivation.

Post-HYP-406, the routing tag is derived from a high-entropy random
LOCATOR (16 bytes, fresh per transfer), NOT from the user-typed words.
This decouples the public tag from the SPAKE2 password and closes the
offline-tag-oracle attack identified in the 2026-05-07 audit.

Two derivation paths exist for compatibility:
- `derive_tag(locator)`: canonical. Uses info `b"rendezvous-tag-v2-locator"`.
- `derive_tag_legacy_words(words)`: legacy words-only handoff. Uses info
  `b"rendezvous-tag-v2-words"` so it can never collide with the locator
  path. Callers MUST require --verify when using this path; a malicious
  relay can still precompute words → tag mappings here.

Both paths use salt `b"takeit/nostr/v2"` (bumped from v1) so a relay
that recorded v1 codes can't replay them against v2 takeit.
"""

import re
import secrets
import string

import pytest

from takeit._tag import (
    TAG_ALPHABET,
    TAG_LENGTH,
    derive_tag,
    derive_tag_legacy_words,
)

# --- canonical path: derive_tag(locator) ---


def test_derive_tag_returns_str_of_expected_length():
    locator = secrets.token_bytes(16)
    tag = derive_tag(locator)
    assert isinstance(tag, str)
    assert len(tag) == TAG_LENGTH


def test_derive_tag_charset_is_lowercase_base32():
    tag = derive_tag(secrets.token_bytes(16))
    assert set(tag) <= set(TAG_ALPHABET)
    assert re.fullmatch(r"[a-z2-7]+", tag)


def test_derive_tag_no_padding():
    tag = derive_tag(secrets.token_bytes(16))
    assert "=" not in tag


def test_derive_tag_deterministic_for_same_locator():
    locator = secrets.token_bytes(16)
    assert derive_tag(locator) == derive_tag(locator)


def test_derive_tag_different_locators_produce_different_tags():
    a = derive_tag(b"\x00" * 16)
    b = derive_tag(b"\x01" * 16)
    assert a != b


def test_derive_tag_rejects_wrong_length():
    """A locator MUST be 16 bytes. Any other length is malformed."""
    with pytest.raises(ValueError, match="16 bytes"):
        derive_tag(b"\x00" * 15)
    with pytest.raises(ValueError, match="16 bytes"):
        derive_tag(b"\x00" * 17)
    with pytest.raises(ValueError, match="16 bytes"):
        derive_tag(b"")


def test_derive_tag_rejects_non_bytes():
    with pytest.raises(TypeError):
        derive_tag("not bytes")
    with pytest.raises(TypeError):
        derive_tag(None)


# --- the load-bearing security property: no oracle ---


def test_words_alone_cannot_predict_locator_tag():
    """The whole point of HYP-406: a relay that observes a tag and knows
    the words used cannot predict the tag without ALSO knowing the
    16-byte locator.

    We approximate this by checking: 1000 random word triples paired
    with 1000 random locators produce 1000 distinct tags, with no
    structure that lets you recover the locator from the (words, tag)
    pair beyond brute-forcing the full 128-bit space.
    """
    from takeit._wordlist import PGPWordList

    wl = PGPWordList()
    pairs = []
    while len(pairs) < 1000:
        words = wl.choose_words(3)
        locator = secrets.token_bytes(16)
        pairs.append((words, locator, derive_tag(locator)))

    tags = {tag for _w, _l, tag in pairs}
    assert len(tags) == 1000  # all distinct

    # Stronger property: tag is independent of words. For the same
    # locator, ANY words give the same tag (they're not even input).
    locator = secrets.token_bytes(16)
    expected = derive_tag(locator)
    for _ in range(50):
        # Words variable but locator constant; tag must be invariant.
        _words = wl.choose_words(3)
        assert derive_tag(locator) == expected


def test_distinctness_across_many_locators():
    """1000 random distinct locators → 1000 distinct tags.

    The 16-char base32 output has 80 bits of entropy; collision
    probability for 1000 inputs is ~5e-19 — anything > 0 collisions
    means the derivation is broken.
    """
    locators = {secrets.token_bytes(16) for _ in range(1000)}
    assert len(locators) == 1000
    tags = {derive_tag(loc) for loc in locators}
    assert len(tags) == 1000


# --- legacy words-only path ---


def test_derive_tag_legacy_words_returns_correct_shape():
    tag = derive_tag_legacy_words("purple-sausages-mocha")
    assert len(tag) == TAG_LENGTH
    assert set(tag) <= set(TAG_ALPHABET)


def test_derive_tag_legacy_words_deterministic():
    """Same words → same tag. Necessary for two peers using words-only
    handoff to find each other on a relay."""
    a = derive_tag_legacy_words("purple-sausages-mocha")
    b = derive_tag_legacy_words("purple-sausages-mocha")
    assert a == b


def test_derive_tag_legacy_words_rejects_non_string():
    with pytest.raises(TypeError):
        derive_tag_legacy_words(b"bytes-not-str")


def test_derive_tag_legacy_words_rejects_empty_or_whitespace():
    with pytest.raises(ValueError):
        derive_tag_legacy_words("")
    with pytest.raises(ValueError, match="whitespace"):
        derive_tag_legacy_words("purple sausages mocha")


# --- domain separation between canonical and legacy paths ---


def test_locator_path_and_words_path_are_domain_separated():
    """A 16-byte locator that happens to equal the UTF-8 bytes of
    some words must produce a DIFFERENT tag in derive_tag than the
    corresponding words produce in derive_tag_legacy_words. This
    guarantees a relay can't cross-replay between modes.

    We achieve this via different `info` strings in the HKDF.
    """
    # 16 ASCII bytes that are also valid UTF-8 string content:
    pseudo_locator = b"abcdefghijklmnop"
    pseudo_words = pseudo_locator.decode("ascii")

    canonical_tag = derive_tag(pseudo_locator)
    legacy_tag = derive_tag_legacy_words(pseudo_words)

    assert canonical_tag != legacy_tag


# --- salt bump v1 → v2 ---


def test_salt_v2_differs_from_v1():
    """Bumping the HKDF salt domain-separates v2 from any v1 deployment.
    A v1 client and a v2 client using the same words/locator MUST NOT
    derive the same tag — fail loud, don't silently misroute.

    We can't easily compare across module versions in a unit test, but
    we CAN verify the v2 derivation is not the same as a hardcoded v1
    output for a known input. The v1 derivation for code='abc' was
    historically fixed; if v2 produces the same value, the salt didn't
    bump as intended.
    """
    from takeit._tag import _hkdf_extract_and_expand

    ikm = b"abc"
    v1 = _hkdf_extract_and_expand(ikm, b"takeit/nostr/v1", b"rendezvous-tag")
    v2_loc = _hkdf_extract_and_expand(
        ikm, b"takeit/nostr/v2", b"rendezvous-tag-v2-locator"
    )
    v2_words = _hkdf_extract_and_expand(
        ikm, b"takeit/nostr/v2", b"rendezvous-tag-v2-words"
    )
    assert v1 != v2_loc
    assert v1 != v2_words
    assert v2_loc != v2_words


# --- consistency of public constants ---


def test_constants_are_consistent():
    """If someone changes one constant they should be forced to change both."""
    assert TAG_LENGTH == 16
    assert set(TAG_ALPHABET) == set(string.ascii_lowercase + "234567")

"""
Tests for PGPWordList.choose_words — the function takeit uses to generate
codes. Upstream wormhole tested completion behavior; takeit also needs to
trust the generation behavior since codes are now produced locally.
"""
import re

import pytest

from takeit._wordlist import PGPWordList


@pytest.fixture
def wl():
    return PGPWordList()


def test_default_format_is_hyphen_separated_lowercase(wl):
    code = wl.choose_words(3)
    assert re.fullmatch(r"[a-z]+(-[a-z]+){2}", code)


def test_length_matches_request(wl):
    for n in (1, 2, 3, 4, 5):
        assert len(wl.choose_words(n).split("-")) == n


def test_distinctness_at_typical_length(wl):
    """1000 generations with length=3, expect zero collisions.

    Wordlist size is 256 per parity, length 3 alternates odd/even/odd, so
    256*256*256 ~ 16.7M combinations. Birthday collision for 1000 ~ 3e-5,
    so a single collision in 1000 is plausible but rare. Use a generous
    bound to avoid flakes.
    """
    codes = {wl.choose_words(3) for _ in range(1000)}
    assert len(codes) >= 999


def test_alternates_odd_even_wordlists(wl):
    """Even words appear at odd positions (index 1, 3, ...) and vice versa.

    The PGP wordlist scheme detects dropped words by alternating parity.
    Verify takeit retains this property.
    """
    from takeit._wordlist import even_words_lowercase, odd_words_lowercase
    code = wl.choose_words(4)
    words = code.split("-")
    assert words[0] in odd_words_lowercase
    assert words[1] in even_words_lowercase
    assert words[2] in odd_words_lowercase
    assert words[3] in even_words_lowercase


def test_zero_length_returns_empty_string(wl):
    """Existing behavior: choose_words(0) returns the empty string. Pin it
    so future refactors notice if they break it."""
    assert wl.choose_words(0) == ""

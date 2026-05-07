"""
Routing-tag derivation for the Nostr rendezvous.

The Nostr `t` tag is the public handle two takeit clients use to find each
other on a relay. Post-HYP-406, the tag is derived from a high-entropy
random LOCATOR (128 bits, fresh per transfer) — NOT from the user-typed
words. This decouples the public tag from the SPAKE2 password and closes
the offline-tag-oracle attack identified in the 2026-05-07 audit.

Two derivation paths:

- ``derive_tag(locator)`` — canonical. Uses info ``rendezvous-tag-v2-locator``.
  Words alone are useless to a relay; you'd have to brute-force 128 bits
  of locator entropy to find a match.

- ``derive_tag_legacy_words(words)`` — for users who handed off only the
  words (no QR / no full-code). Uses info ``rendezvous-tag-v2-words`` for
  domain separation from the canonical path. This path PRESERVES the
  original oracle vulnerability (24-bit codes are precomputable);
  callers MUST require ``--verify`` to make it MITM-resistant.

Both paths share salt ``takeit/nostr/v2`` (bumped from v1 so a relay that
recorded v1 codes can't replay them).
"""

import base64
import string

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ._code_format import LOCATOR_BYTES

# RFC 4648 base32 lowercase alphabet (no padding).
TAG_ALPHABET = string.ascii_lowercase + "234567"

# 16 base32 chars = 80 bits of derived tag material. Birthday collisions
# across concurrent tags are negligible (~1e-12 at a million concurrent
# transfers).
TAG_LENGTH = 16

_TAG_BYTES = 10  # 10 bytes -> 16 base32 chars (no padding).
_HKDF_SALT = b"takeit/nostr/v2"
_HKDF_INFO_LOCATOR = b"rendezvous-tag-v2-locator"
_HKDF_INFO_LEGACY_WORDS = b"rendezvous-tag-v2-words"


def _hkdf_extract_and_expand(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int = _TAG_BYTES,
) -> bytes:
    """RFC 5869 HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def _format_tag(okm: bytes) -> str:
    """10 bytes → 16 lowercase base32 chars without padding."""
    return base64.b32encode(okm).decode("ascii").lower()


def derive_tag(locator: bytes) -> str:
    """Derive the public Nostr routing tag from a 16-byte locator.

    The canonical path. Words / SPAKE2 password are NOT inputs — a relay
    that observes the tag and knows the words gains no information about
    the locator beyond brute-forcing 128 bits.
    """
    if not isinstance(locator, (bytes, bytearray)):
        raise TypeError(f"locator must be bytes, got {type(locator).__name__}")
    if len(locator) != LOCATOR_BYTES:
        raise ValueError(
            f"locator must be exactly {LOCATOR_BYTES} bytes, got {len(locator)}"
        )
    okm = _hkdf_extract_and_expand(bytes(locator), _HKDF_SALT, _HKDF_INFO_LOCATOR)
    return _format_tag(okm)


def derive_tag_legacy_words(words: str) -> str:
    """Derive a routing tag from words for legacy words-only handoff.

    This path PRESERVES the oracle vulnerability — a malicious relay
    can precompute every 3-word → tag mapping (~16M entries) and recover
    the words. Callers MUST require ``--verify`` to make this path
    MITM-resistant.

    Domain-separated from `derive_tag(locator)` via a different HKDF
    `info` so a relay can't cross-replay between modes.
    """
    if not isinstance(words, str):
        raise TypeError(f"words must be str, got {type(words).__name__}")
    if not words:
        raise ValueError("words must not be empty")
    if any(c.isspace() for c in words):
        raise ValueError("words must not contain whitespace")
    okm = _hkdf_extract_and_expand(
        words.encode("utf-8"), _HKDF_SALT, _HKDF_INFO_LEGACY_WORDS
    )
    return _format_tag(okm)

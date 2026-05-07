"""
takeit code format: how the user-typed string maps to (locator, words).

Post-HYP-406 a takeit code is one of two shapes:

1. Canonical: ``<base32-locator>:<words>``
   - locator is 16 bytes (128 bits), random per transfer, base32-encoded
     without padding (26 chars). Carries the public Nostr routing tag.
   - words is the SPAKE2 password (PGP-wordlist-derived).
   The colon (`:`) separates the two halves; words use `-` internally
   so there's no ambiguity.

2. Legacy words-only: ``<words>``
   - For backwards-compat with words-only handoff. Tag is derived from
     words via a domain-separated HKDF path (see _tag.py); requires
     ``--verify`` to be MITM-resistant.

`parse_code` is the canonical splitter. `generate_locator` and
`encode_locator` are the helpers callers use to mint and serialize
the locator half. The actual tag derivation lives in _tag.py.

Why a separate module: keeps "what's the wire shape of the code"
distinct from "how do we derive a tag from a locator." Both are
imported by Boss / Code state machine / cli.
"""

import base64
import secrets

# 16 bytes = 128 bits of locator entropy. Birthday-collision rate is
# negligible across the lifetime of the project. Encodes as exactly
# 26 base32 characters with no padding (ceil(16 * 8 / 5) = 26).
LOCATOR_BYTES = 16
LOCATOR_B32_LEN = 26


def generate_locator() -> bytes:
    """Return a fresh 16-byte locator. Use once per transfer."""
    return secrets.token_bytes(LOCATOR_BYTES)


def encode_locator(locator: bytes) -> str:
    """Encode a 16-byte locator as 26 lowercase base32 chars (no padding).

    Inverse of the locator-decode step inside `parse_code`.
    """
    if not isinstance(locator, (bytes, bytearray)):
        raise TypeError(f"locator must be bytes, got {type(locator).__name__}")
    if len(locator) != LOCATOR_BYTES:
        raise ValueError(
            f"locator must be exactly {LOCATOR_BYTES} bytes, got {len(locator)}"
        )
    # b32encode produces uppercase; lowercase for consistency with
    # how takeit displays codes elsewhere.
    return base64.b32encode(bytes(locator)).decode("ascii").rstrip("=").lower()


def parse_code(code: str) -> tuple[bytes | None, str]:
    """Split a user-typed code into (locator_bytes_or_None, words_str).

    - ``<26-char-base32>:<words>`` → (locator_bytes, words)
    - ``<words>`` (no colon) → (None, words)  legacy words-only mode
    - anything else → ValueError with a clear message

    Whitespace anywhere in the code is rejected (always a typo, never
    intentional). The locator portion is case-insensitive (RFC 4648
    base32 supports both); words preserve their case.
    """
    if not isinstance(code, str):
        raise TypeError(f"code must be str, got {type(code).__name__}")
    if not code:
        raise ValueError("code must not be empty")
    if any(c.isspace() for c in code):
        raise ValueError("code must not contain whitespace")
    if code.count(":") > 1:
        raise ValueError(
            "code has too many colons (expected at most one separating "
            "locator from words)"
        )

    if ":" not in code:
        # Legacy words-only handoff. Caller is responsible for warning
        # the user about the security implications.
        return None, code

    loc_part, words = code.split(":", 1)
    if not loc_part:
        raise ValueError("code has empty locator section before ':'")
    if not words:
        raise ValueError("code has empty words section after ':'")
    if len(loc_part) != LOCATOR_B32_LEN:
        raise ValueError(
            f"locator section must be exactly {LOCATOR_B32_LEN} base32 "
            f"characters, got {len(loc_part)}"
        )
    # base64.b32decode is case-sensitive (uppercase only) and requires
    # padding. Normalize before decoding.
    padded = loc_part.upper() + "=" * ((8 - len(loc_part) % 8) % 8)
    try:
        locator = base64.b32decode(padded)
    except Exception as e:
        raise ValueError(f"locator is not valid base32: {e}")
    if len(locator) != LOCATOR_BYTES:
        raise ValueError(
            f"locator decoded to {len(locator)} bytes, expected {LOCATOR_BYTES}"
        )
    return locator, words

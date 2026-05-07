"""
Routing-tag derivation for the Nostr rendezvous.

The Nostr `t` tag is the public handle two takeit clients use to find each
other on a relay. Both sides derive it from the shared code via HKDF-SHA256
(RFC 5869). The salt embeds a protocol-version string so that a future wire
break is a one-character salt change rather than an in-band negotiation.

The code itself is the SPAKE2 password and stays secret. The tag is public —
it appears on the wire and is visible to relay operators. Tag length and
charset are chosen to be human-readable in logs and case-insensitive.
"""

import base64
import string

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# RFC 4648 base32 lowercase alphabet (no padding).
TAG_ALPHABET = string.ascii_lowercase + "234567"

# 16 base32 chars = 80 bits of derived material. Birthday collisions across
# concurrent tags are negligible (1e-12 at a million concurrent codes).
TAG_LENGTH = 16

_TAG_BYTES = 10  # 10 bytes -> 16 base32 chars (no padding).
_HKDF_SALT = b"takeit/nostr/v1"
_HKDF_INFO = b"rendezvous-tag"


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


def derive_tag(code: str) -> str:
    """Derive a public Nostr routing tag from a takeit code.

    The output is 16 lowercase base32 characters with no padding, suitable
    for use as the value of a Nostr `t` tag (NIP-01 single-letter tag).
    """
    if not isinstance(code, str):
        raise TypeError(f"code must be str, got {type(code).__name__}")
    if not code:
        raise ValueError("code must not be empty")
    if any(ch.isspace() for ch in code):
        raise ValueError("code must not contain whitespace")

    okm = _hkdf_extract_and_expand(code.encode("utf-8"), _HKDF_SALT, _HKDF_INFO)
    # base32 encoding of 10 bytes is exactly 16 chars with no padding.
    return base64.b32encode(okm).decode("ascii").lower()

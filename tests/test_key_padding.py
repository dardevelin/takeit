"""
Tests for HYP-426: rendezvous control-message ciphertexts are padded
to fixed-length buckets so a relay observing event content size cannot
infer plaintext length.

The wire shape: encrypt_data(key, plaintext) returns
SecretBox(nonce || ciphertext) where ciphertext = enc(length_prefix ||
plaintext || zero_pad). length_prefix is 4 bytes big-endian; zero_pad
fills to the next bucket size. decrypt_data unwraps the bucket back
to the original plaintext.

Threat model (from the 5th-pass audit):
> "relays do not see plaintext, but they do see phase, timing, event
> count, and approximate plaintext length."

Padding closes the "approximate plaintext length" leak: now the relay
sees only which BUCKET the message belonged to, not its length
within that bucket.
"""

import pytest
from nacl.exceptions import CryptoError

from takeit._key import (
    _PADDING_BUCKETS,
    _PADDING_LENGTH_PREFIX_BYTES,
    decrypt_data,
    encrypt_data,
)

KEY = b"\x00" * 32


def test_round_trip_short_message():
    plaintext = b"hello"
    ct = encrypt_data(KEY, plaintext)
    assert decrypt_data(KEY, ct) == plaintext


def test_round_trip_empty_message():
    plaintext = b""
    ct = encrypt_data(KEY, plaintext)
    assert decrypt_data(KEY, ct) == plaintext


def test_round_trip_at_each_bucket_boundary():
    # Each bucket size minus the length prefix is the largest plaintext
    # that fits in that bucket without spilling into the next.
    for bucket in _PADDING_BUCKETS:
        plaintext = b"x" * (bucket - _PADDING_LENGTH_PREFIX_BYTES)
        ct = encrypt_data(KEY, plaintext)
        assert decrypt_data(KEY, ct) == plaintext


def test_round_trip_one_byte_short_of_each_bucket():
    for bucket in _PADDING_BUCKETS:
        if bucket == _PADDING_BUCKETS[0]:
            continue  # "one short" doesn't fit a smaller plaintext
        plaintext = b"x" * (bucket - _PADDING_LENGTH_PREFIX_BYTES - 1)
        ct = encrypt_data(KEY, plaintext)
        assert decrypt_data(KEY, ct) == plaintext


def test_ciphertext_length_constant_within_bucket():
    """The whole point of HYP-426: a relay observing two events with
    plaintexts of WIDELY different lengths but in the same bucket must
    see ciphertexts of IDENTICAL length."""
    short = b"x"
    long = b"y" * 200
    ct_short = encrypt_data(KEY, short)
    ct_long = encrypt_data(KEY, long)
    # Both fit in the smallest (256-byte) bucket.
    assert len(ct_short) == len(ct_long), (
        f"ciphertext length leak: {len(ct_short)} vs {len(ct_long)} "
        f"for plaintexts of {len(short)} vs {len(long)} bytes"
    )


def test_ciphertext_length_jumps_at_bucket_boundary():
    """Crossing a bucket boundary jumps the ciphertext to the next
    bucket size. This is the size leak that's left — the relay can
    distinguish 'small' from 'medium' from 'large', but no more."""
    sizes = [_PADDING_BUCKETS[0] // 2, _PADDING_BUCKETS[1] // 2]
    cts = [encrypt_data(KEY, b"x" * s) for s in sizes]
    assert len(cts[0]) < len(cts[1])


def test_ciphertext_length_at_smallest_bucket_for_each_distinct_short_size():
    """Plaintexts from 0 bytes through (256 - 4) bytes all share the
    smallest bucket → identical ciphertext length. This is the
    main-line case for control phases (pake, version)."""
    samples = [
        b"",
        b"x",
        b"x" * 50,
        b"x" * 100,
        b"x" * (_PADDING_BUCKETS[0] - _PADDING_LENGTH_PREFIX_BYTES),
    ]
    cts = [encrypt_data(KEY, s) for s in samples]
    sizes = {len(c) for c in cts}
    assert len(sizes) == 1, f"expected 1 ciphertext size, got {sizes}"


def test_too_large_plaintext_rejected():
    """Plaintexts larger than the largest bucket cannot be padded; we
    refuse rather than silently corrupt."""
    too_big = b"x" * (_PADDING_BUCKETS[-1] - _PADDING_LENGTH_PREFIX_BYTES + 1)
    with pytest.raises(ValueError, match="exceeds largest padding bucket"):
        encrypt_data(KEY, too_big)


def test_decrypt_rejects_truncated_ciphertext():
    plaintext = b"hello"
    ct = encrypt_data(KEY, plaintext)
    # Truncate inside the SecretBox envelope; decrypt must raise rather
    # than return garbage.
    with pytest.raises(CryptoError):
        decrypt_data(KEY, ct[:-10])


def test_decrypt_rejects_bad_length_prefix():
    """A ciphertext that decrypts but has a length prefix larger than
    its padded plaintext is malformed. We refuse rather than slice
    out-of-bounds."""
    from nacl import utils
    from nacl.secret import SecretBox

    box = SecretBox(KEY)
    # Forge a padded payload claiming length 999 inside a 256-byte
    # bucket. The receiver should refuse.
    bogus_padded = (999).to_bytes(_PADDING_LENGTH_PREFIX_BYTES, "big") + b"\x00" * (
        _PADDING_BUCKETS[0] - _PADDING_LENGTH_PREFIX_BYTES
    )
    nonce = utils.random(SecretBox.NONCE_SIZE)
    ct = box.encrypt(bogus_padded, nonce)
    with pytest.raises(ValueError, match="length prefix"):
        decrypt_data(KEY, ct)


def test_padding_buckets_monotonic_and_under_rendezvous_cap():
    """Buckets must be strictly increasing so bucket selection is
    well-defined, and the largest bucket plus SecretBox overhead must
    fit inside the rendezvous inbound cap (64 KiB)."""
    from nacl.secret import SecretBox

    from takeit._rendezvous_nostr import MAX_INBOUND_EVENT_CONTENT_BYTES

    assert list(_PADDING_BUCKETS) == sorted(_PADDING_BUCKETS)
    assert all(a < b for a, b in zip(_PADDING_BUCKETS, _PADDING_BUCKETS[1:]))
    secretbox_overhead = SecretBox.NONCE_SIZE + SecretBox.MACBYTES
    largest_ciphertext = _PADDING_BUCKETS[-1] + secretbox_overhead
    assert largest_ciphertext <= MAX_INBOUND_EVENT_CONTENT_BYTES, (
        f"largest bucket ({_PADDING_BUCKETS[-1]}) + SecretBox overhead "
        f"({secretbox_overhead}) = {largest_ciphertext} exceeds rendezvous cap "
        f"({MAX_INBOUND_EVENT_CONTENT_BYTES})"
    )


def test_padding_buckets_cover_text_payload():
    """The largest bucket must accommodate a JSON-wrapped MAX_TEXT_BYTES
    payload (the largest legitimate plaintext we send)."""
    from takeit.cli._protocol import MAX_TEXT_BYTES

    # Worst-case JSON wrapper around a max text + transfer_id + kind:
    # ~120 bytes of overhead is generous.
    JSON_OVERHEAD = 256
    needed = MAX_TEXT_BYTES + JSON_OVERHEAD + _PADDING_LENGTH_PREFIX_BYTES
    assert _PADDING_BUCKETS[-1] >= needed, (
        f"largest bucket ({_PADDING_BUCKETS[-1]}) cannot hold a max-size "
        f"text payload (need {needed})"
    )


def test_distinct_calls_produce_distinct_ciphertexts():
    """Sanity: SecretBox uses a random nonce, so two encrypts of the
    same plaintext produce different ciphertexts (otherwise our
    padding scheme might have accidentally fixed the nonce)."""
    plaintext = b"hello"
    a = encrypt_data(KEY, plaintext)
    b = encrypt_data(KEY, plaintext)
    assert a != b
    assert decrypt_data(KEY, a) == plaintext
    assert decrypt_data(KEY, b) == plaintext

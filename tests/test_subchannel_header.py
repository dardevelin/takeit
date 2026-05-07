"""
Tests for the dilation-subchannel header exchange (HYP-392).

The subchannel-header protocol moves chunk_hashes off the rendezvous-
visible offer (where ciphertext length leaks file size to the relay)
onto the peer-to-peer dilation subchannel. New on the wire:

  - Sender → receiver: subchannel_header carrying chunk_hashes.
  - Receiver → sender: chunks_have reply (after hashing the partial).
  - Sender → receiver: chunk frames (existing).

All header messages are length-prefixed JSON (4-byte big-endian length
+ UTF-8 JSON bytes). MAX_HEADER_BYTES caps the prefix so a hostile
peer can't claim a 4 GiB body and OOM us.
"""

import base64
import hashlib
import json
import struct

import pytest

from takeit.cli._protocol import (
    MAX_CHUNK_COUNT,
    MAX_HEADER_BYTES,
    LengthPrefixedDecoder,
    ProtocolError,
    build_chunks_have,
    build_subchannel_header,
    encode_length_prefixed,
    parse_chunks_have,
    parse_subchannel_header,
)

# --- length-prefixed framing ---


def test_encode_length_prefixed_round_trips():
    body = b'{"hello": "world"}'
    framed = encode_length_prefixed(body)
    assert framed[:4] == struct.pack(">I", len(body))
    assert framed[4:] == body


def test_decoder_reassembles_split_buffers():
    """The subchannel may deliver bytes in arbitrarily small pieces;
    the decoder buffers until a full message is ready."""
    body = b'{"chunk_hashes": ["..."]}'
    framed = encode_length_prefixed(body)
    decoder = LengthPrefixedDecoder()
    # Feed one byte at a time.
    out = []
    for byte in framed:
        out.extend(decoder.feed(bytes([byte])))
    assert out == [body]


def test_decoder_yields_multiple_messages_in_one_buffer():
    a = encode_length_prefixed(b'{"a": 1}')
    b = encode_length_prefixed(b'{"b": 2}')
    decoder = LengthPrefixedDecoder()
    msgs = list(decoder.feed(a + b))
    assert msgs == [b'{"a": 1}', b'{"b": 2}']


def test_decoder_rejects_oversized_length():
    """A peer claiming a 4 GiB-class body must be refused before we
    allocate the buffer."""
    bogus = struct.pack(">I", MAX_HEADER_BYTES + 1)
    decoder = LengthPrefixedDecoder()
    with pytest.raises(ProtocolError, match="exceeds"):
        list(decoder.feed(bogus))


def test_decoder_rejects_zero_length():
    """Empty bodies are rejected — every protocol message has content."""
    bogus = struct.pack(">I", 0)
    decoder = LengthPrefixedDecoder()
    with pytest.raises(ProtocolError, match="zero|empty"):
        list(decoder.feed(bogus))


def test_decoder_partial_then_complete():
    body = b'{"x": "y"}'
    framed = encode_length_prefixed(body)
    decoder = LengthPrefixedDecoder()
    # Feed prefix + first byte of body
    out = list(decoder.feed(framed[:5]))
    assert out == []  # not yet complete
    out = list(decoder.feed(framed[5:]))
    assert out == [body]


# --- subchannel_header (sender → receiver, carries chunk_hashes) ---


def _deframe_one(framed):
    """Helper: feed the length-prefixed bytes through the decoder and
    return the single body it yields. Tests round-trip via the same
    path the receiver uses on the wire."""
    decoder = LengthPrefixedDecoder()
    bodies = list(decoder.feed(framed))
    assert len(bodies) == 1
    return bodies[0]


def test_build_subchannel_header_round_trips():
    chunk_hashes = [
        hashlib.blake2b(f"chunk-{i}".encode(), digest_size=32).digest()
        for i in range(5)
    ]
    framed = build_subchannel_header(chunk_hashes)
    body = _deframe_one(framed)
    parsed = parse_subchannel_header(body)
    assert parsed == chunk_hashes


def test_parse_subchannel_header_rejects_non_json():
    with pytest.raises(ProtocolError, match="JSON"):
        parse_subchannel_header(b"not json at all")


def test_parse_subchannel_header_rejects_missing_field():
    payload = json.dumps({"other": "fields"}).encode()
    with pytest.raises(ProtocolError, match="chunk_hashes"):
        parse_subchannel_header(payload)


def test_parse_subchannel_header_rejects_bad_hash_length():
    """Each hash must be exactly 32 bytes."""
    payload = json.dumps(
        {
            "chunk_hashes": [base64.b64encode(b"\x00" * 16).decode()],
        }
    ).encode()
    with pytest.raises(ProtocolError, match="32 bytes"):
        parse_subchannel_header(payload)


def test_parse_subchannel_header_rejects_too_many_hashes():
    """Same MAX_CHUNK_COUNT cap as the offer — bound memory."""
    payload = json.dumps(
        {
            "chunk_hashes": [base64.b64encode(b"\x00" * 32).decode()]
            * (MAX_CHUNK_COUNT + 1),
        }
    ).encode()
    with pytest.raises(ProtocolError, match="exceeds"):
        parse_subchannel_header(payload)


# --- chunks_have (receiver → sender, after partial-file verification) ---


def test_build_and_parse_chunks_have():
    framed = build_chunks_have([5, 0, 2])
    body = _deframe_one(framed)
    out = parse_chunks_have(body)
    # Sorted on the wire so the sender doesn't have to re-sort.
    assert out == [0, 2, 5]


def test_build_chunks_have_empty():
    """Fresh (non-resumed) transfers send an empty list."""
    framed = build_chunks_have([])
    body = _deframe_one(framed)
    assert parse_chunks_have(body) == []


def test_parse_chunks_have_rejects_negative_int():
    payload = json.dumps({"chunks_have": [-1]}).encode()
    with pytest.raises(ProtocolError):
        parse_chunks_have(payload)


def test_parse_chunks_have_rejects_non_int():
    payload = json.dumps({"chunks_have": ["zero"]}).encode()
    with pytest.raises(ProtocolError):
        parse_chunks_have(payload)


def test_parse_chunks_have_rejects_missing_field():
    payload = json.dumps({"other": []}).encode()
    with pytest.raises(ProtocolError, match="chunks_have|missing"):
        parse_chunks_have(payload)

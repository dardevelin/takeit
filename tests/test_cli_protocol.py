"""
Pure-logic tests for the takeit file-transfer protocol module.

Coverage: file hashing (whole + per-chunk), transfer_id, offer build/parse
including chunk_hashes, answer build/parse including chunks_have, frame
encode/decode, FrameDecoder buffer-split robustness.
"""

import base64
import hashlib
import json
import os
import struct

import pytest

from takeit._key import encrypt_data
from takeit._rendezvous_nostr import MAX_INBOUND_EVENT_CONTENT_BYTES
from takeit.cli._protocol import (
    DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_COUNT,
    MAX_FILENAME_BYTES,
    MAX_OFFER_SIZE,
    MAX_TEXT_BYTES,
    SUBCHANNEL_NAME,
    TRANSFER_ID_BYTES,
    FrameDecoder,
    ProtocolError,
    build_answer,
    build_complete,
    build_done,
    build_offer_directory,
    build_offer_file,
    build_offer_text,
    chunk_hashes_for_file,
    compute_transfer_id,
    encode_message,
    expected_chunk_count,
    frame,
    hash_file,
    parse_answer,
    parse_offer,
    parse_simple_flag,
    verify_chunk,
)

# --- file hashing ---


def test_hash_file_matches_blake2b_of_contents(tmp_path):
    path = tmp_path / "f.bin"
    path.write_bytes(b"some content here")
    size, digest = hash_file(str(path))
    assert size == len(b"some content here")
    expected = hashlib.blake2b(b"some content here", digest_size=32).digest()
    assert digest == expected


def test_hash_file_streams_large_files(tmp_path):
    path = tmp_path / "big.bin"
    payload = os.urandom(4 << 20)
    path.write_bytes(payload)
    size, digest = hash_file(str(path))
    assert size == len(payload)
    assert digest == hashlib.blake2b(payload, digest_size=32).digest()


def test_hash_file_handles_empty_file(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    size, digest = hash_file(str(path))
    assert size == 0
    assert digest == hashlib.blake2b(b"", digest_size=32).digest()


# --- chunk hashing ---


def test_chunk_hashes_for_file_round_trips(tmp_path):
    path = tmp_path / "f.bin"
    payload = os.urandom(2_500_000)  # 2.5 chunks at 1 MiB
    path.write_bytes(payload)
    size, content_hash, chunk_hashes = chunk_hashes_for_file(
        str(path), chunk_size=1 << 20
    )
    assert size == len(payload)
    assert content_hash == hashlib.blake2b(payload, digest_size=32).digest()
    # Reconstruct chunk hashes manually
    expected = []
    for i in range(0, len(payload), 1 << 20):
        ch = payload[i : i + (1 << 20)]
        expected.append(hashlib.blake2b(ch, digest_size=32).digest())
    assert chunk_hashes == expected


def test_chunk_hashes_for_empty_file_yields_no_chunks(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    size, content_hash, chunk_hashes = chunk_hashes_for_file(str(path))
    assert size == 0
    assert chunk_hashes == []


def test_expected_chunk_count():
    assert expected_chunk_count(0, 100) == 0
    assert expected_chunk_count(1, 100) == 1
    assert expected_chunk_count(100, 100) == 1
    assert expected_chunk_count(101, 100) == 2
    assert expected_chunk_count(250, 100) == 3


def test_verify_chunk():
    chunk = b"some data"
    h = hashlib.blake2b(chunk, digest_size=32).digest()
    assert verify_chunk(chunk, h)
    assert not verify_chunk(chunk, b"\x00" * 32)
    assert not verify_chunk(b"different data", h)


# --- transfer_id ---


def test_transfer_id_is_deterministic():
    h = b"\x00" * 32
    a = compute_transfer_id("file", 100, "file.txt", h)
    b = compute_transfer_id("file", 100, "file.txt", h)
    assert a == b
    assert len(a) == TRANSFER_ID_BYTES


def test_transfer_id_changes_on_kind_size_name_or_hash():
    h1 = b"\x00" * 32
    h2 = b"\x01" * 32
    base = compute_transfer_id("file", 100, "file.txt", h1)
    assert compute_transfer_id("file", 101, "file.txt", h1) != base
    assert compute_transfer_id("file", 100, "other.txt", h1) != base
    assert compute_transfer_id("file", 100, "file.txt", h2) != base
    # Same size/name/hash but different kind must produce different id —
    # otherwise (file "x", directory "x") would collide.
    assert compute_transfer_id("directory", 100, "file.txt", h1) != base


# --- offer building ---


def test_build_offer_round_trips():
    payload = b"x" * 2_500_000
    h_all = hashlib.blake2b(payload, digest_size=32).digest()
    msg = build_offer_file("doc.pdf", len(payload), h_all)
    parsed = parse_offer(encode_message(msg))
    assert parsed["kind"] == "file"
    assert parsed["filename"] == "doc.pdf"
    assert parsed["size"] == len(payload)
    assert parsed["chunk_size"] == DEFAULT_CHUNK_SIZE
    assert parsed["_content_hash_bytes"] == h_all
    assert len(parsed["_transfer_id_bytes"]) == TRANSFER_ID_BYTES
    # chunk_hashes are NO LONGER in the offer (HYP-392): they ride
    # the dilation subchannel so the relay can't infer file size from
    # offer ciphertext length.
    assert "chunk_hashes" not in parsed
    assert "_chunk_hashes_bytes" not in parsed


def test_offer_size_is_independent_of_file_size():
    """The whole point of HYP-392: offer ciphertext length must NOT
    grow with file size. We approximate by checking the JSON length
    of two offers for very different file sizes is roughly equal."""
    h = b"\x00" * 32
    small = encode_message(build_offer_file("a.txt", 1024, h))
    huge = encode_message(build_offer_file("a.txt", 1 << 35, h))  # 32 GiB
    # The only field that varies with size is the int's decimal width
    # (~6 digits for 1024 vs ~12 for 32 GiB) — within 10 bytes.
    assert abs(len(small) - len(huge)) < 20, (
        f"offer length differs by {abs(len(small) - len(huge))} bytes "
        "for two wildly different file sizes — chunk_hashes is leaking "
        "size information again"
    )


def test_build_offer_rejects_path_traversal():
    h = b"\x00" * 32
    for bad in ("a/b.txt", "..", ".", "", "x\\y"):
        with pytest.raises(ValueError):
            build_offer_file(bad, 0, h)


def test_build_offer_rejects_negative_size():
    with pytest.raises(ValueError):
        build_offer_file("a.txt", -1, b"\x00" * 32)


def test_build_offer_rejects_non_positive_chunk_size():
    with pytest.raises(ValueError):
        build_offer_file("a.txt", 0, b"\x00" * 32, chunk_size=0)


def test_build_offer_rejects_excessive_chunk_count():
    with pytest.raises(ValueError, match="requires .* chunks"):
        too_many_chunks_size = (MAX_CHUNK_COUNT + 1) * 1024
        build_offer_file("a.txt", too_many_chunks_size, b"\x00" * 32, chunk_size=1024)


def test_parse_offer_rejects_chunk_hashes_field():
    """chunk_hashes used to live in the offer but moved to the
    subchannel header (HYP-392). A peer sending the old shape is on a
    pre-HYP-392 protocol — refuse rather than silently misinterpret."""
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    msg = json.dumps(
        {
            "offer": {
                "kind": "file",
                "transfer_id": tid_b64,
                "filename": "a.txt",
                "size": 1024,
                "content_hash": h_b64,
                "chunk_size": 1 << 20,
                "chunk_hashes": [base64.b64encode(b"\x00" * 32).decode()],
            }
        }
    ).encode()
    with pytest.raises(ProtocolError, match="chunk_hashes"):
        parse_offer(msg)


def test_parse_offer_rejects_excessive_chunk_count():
    huge_size = (MAX_CHUNK_COUNT + 1) * 1024
    msg = _serializable_offer(size=huge_size, chunk_size=1024)
    with pytest.raises(ProtocolError, match="more than 1048576 chunks"):
        parse_offer(msg)


# --- offer parsing ---


def _serializable_offer(
    size=1,
    chunk_size=1024,
    filename="a.txt",
    transfer_id_bytes=None,
    content_hash_bytes=None,
):
    """Build a JSON-serializable offer payload for negative tests.

    Post-HYP-392 the offer no longer carries chunk_hashes — those moved
    to the dilation subchannel. Post-HYP-431 transfer_id must match
    compute_transfer_id(kind, size, name, content_hash); this helper
    defaults to the matching value so callers exercising OTHER negative
    paths don't trip the transfer_id check. Pass
    `transfer_id_bytes=b"\\xff" * 16` to force a mismatch."""
    if content_hash_bytes is None:
        content_hash_bytes = b"\x00" * 32
    if transfer_id_bytes is None:
        from takeit.cli._protocol import KIND_FILE, compute_transfer_id

        transfer_id_bytes = compute_transfer_id(
            KIND_FILE, size, filename, content_hash_bytes
        )
    return json.dumps(
        {
            "offer": {
                "kind": "file",
                "transfer_id": base64.b64encode(transfer_id_bytes).decode(),
                "filename": filename,
                "size": size,
                "content_hash": base64.b64encode(content_hash_bytes).decode(),
                "chunk_size": chunk_size,
            }
        }
    ).encode()


def test_parse_offer_rejects_non_json():
    with pytest.raises(ProtocolError, match="JSON"):
        parse_offer(b"not json at all")


def test_parse_offer_rejects_non_utf8():
    with pytest.raises(ProtocolError, match="UTF-8"):
        parse_offer(b"\xff\xfe not utf-8")


def test_parse_offer_rejects_wrong_envelope():
    with pytest.raises(ProtocolError, match="offer"):
        parse_offer(b'{"answer": {"accept": true}}')


def test_parse_offer_rejects_missing_field():
    minimal = json.dumps({"offer": {"kind": "file", "filename": "a"}}).encode()
    with pytest.raises(ProtocolError, match="missing"):
        parse_offer(minimal)


def test_parse_offer_rejects_path_traversal():
    bad_filenames = ["foo/bar.txt", "..", ".", "", "..\\nope", ".hidden", "/etc/passwd"]
    for fn in bad_filenames:
        msg = _serializable_offer(filename=fn)
        with pytest.raises(ProtocolError):
            parse_offer(msg)


def test_parse_offer_rejects_invalid_transfer_id_base64():
    msg = json.dumps(
        {
            "offer": {
                "kind": "file",
                "transfer_id": "not@@@base64!",
                "filename": "a.txt",
                "size": 1,
                "content_hash": base64.b64encode(b"\x00" * 32).decode(),
                "chunk_size": 1024,
            }
        }
    ).encode()
    with pytest.raises(ProtocolError, match="bad base64 in transfer_id"):
        parse_offer(msg)


def test_parse_offer_rejects_invalid_content_hash_base64():
    msg = json.dumps(
        {
            "offer": {
                "kind": "file",
                "transfer_id": base64.b64encode(b"\x00" * 16).decode(),
                "filename": "a.txt",
                "size": 1,
                "content_hash": "bad+base64!!",
                "chunk_size": 1024,
            }
        }
    ).encode()
    with pytest.raises(ProtocolError, match="bad base64 in content_hash"):
        parse_offer(msg)


# --- HYP-431: receiver-side transfer_id verification ---


def test_parse_offer_rejects_forged_transfer_id_for_file():
    """A malicious sender can put any 16-byte value as transfer_id.
    Receiver must recompute compute_transfer_id(kind, size, name,
    content_hash) and reject mismatches so resume state can't be
    polluted by attacker-chosen identities."""
    msg = _serializable_offer(transfer_id_bytes=b"\xff" * 16)
    with pytest.raises(ProtocolError, match="transfer_id does not match"):
        parse_offer(msg)


def test_parse_offer_accepts_matching_transfer_id_for_file():
    """Round-trip: an honest sender's compute_transfer_id matches and
    the offer parses without error."""
    msg = _serializable_offer()  # default transfer_id is the matching one
    parsed = parse_offer(msg)
    assert parsed["kind"] == "file"


def test_parse_offer_rejects_forged_transfer_id_for_directory():
    """Same protection for directory offers."""
    from takeit.cli._protocol import KIND_DIRECTORY, build_offer_directory

    h = b"\x11" * 32
    msg = build_offer_directory("docs", 1024, h, num_files=2, num_bytes=512)
    parsed_dict = json.loads(encode_message(msg).decode())
    # Sanity-check the helper applies to dirs too: build_offer_directory
    # produces a transfer_id matching compute_transfer_id of the same
    # fields, so the round-trip path passes.
    expected = compute_transfer_id(KIND_DIRECTORY, 1024, "docs", h)
    assert base64.b64decode(parsed_dict["offer"]["transfer_id"]) == expected
    # Forge the transfer_id.
    parsed_dict["offer"]["transfer_id"] = base64.b64encode(b"\xff" * 16).decode()
    forged = json.dumps(parsed_dict).encode()
    with pytest.raises(ProtocolError, match="transfer_id does not match"):
        parse_offer(forged)


def test_parse_offer_rejects_forged_transfer_id_for_text():
    """Text offers compute_text_transfer_id from the text alone; same
    protection."""
    from takeit.cli._protocol import build_offer_text

    msg = build_offer_text("hello world")
    parsed_dict = json.loads(encode_message(msg).decode())
    parsed_dict["offer"]["transfer_id"] = base64.b64encode(b"\xff" * 16).decode()
    forged = json.dumps(parsed_dict).encode()
    with pytest.raises(ProtocolError, match="transfer_id does not match"):
        parse_offer(forged)


def test_parse_offer_round_trip_with_build_offer_file_works():
    """Regression guard for HYP-431: an honest build_offer_file →
    parse_offer round-trip continues to succeed (the helpers compute a
    matching transfer_id, so the check passes)."""
    h = b"\x42" * 32
    msg = build_offer_file("readme.txt", 1024, h)
    parsed = parse_offer(encode_message(msg))
    assert parsed["filename"] == "readme.txt"
    assert parsed["size"] == 1024


# Pre-HYP-392 tests covered chunk_hashes count/length validation in
# parse_offer; those guards moved to parse_subchannel_header (see
# tests/test_subchannel_header.py).


# --- answer ---


def test_build_and_parse_answer_accept():
    """Post-HYP-392, the answer is just accept/reject — chunks_have
    moved to the dilation-subchannel reply (see test_subchannel_header)."""
    payload = encode_message(build_answer(True))
    accepted, reason = parse_answer(payload)
    assert accepted is True
    assert reason is None


def test_build_and_parse_answer_reject():
    payload = encode_message(build_answer(False, "user said no"))
    accepted, reason = parse_answer(payload)
    assert accepted is False
    assert reason == "user said no"


def test_parse_answer_rejects_wrong_envelope():
    with pytest.raises(ProtocolError):
        parse_answer(b'{"offer": {}}')


# --- complete / done flag ---


def test_parse_complete_accepts_true():
    parse_simple_flag(encode_message(build_complete()), "complete")


def test_parse_done_accepts_true():
    parse_simple_flag(encode_message(build_done()), "done")


def test_parse_simple_flag_rejects_other_keys():
    with pytest.raises(ProtocolError):
        parse_simple_flag(b'{"complete": false}', "complete")
    with pytest.raises(ProtocolError):
        parse_simple_flag(b'{"done": true}', "complete")


# --- frame / FrameDecoder ---


def test_frame_round_trip_via_decoder():
    chunks = [(0, b"hello"), (2, b"world!"), (1, b"\x00\x01\x02")]
    stream = b"".join(frame(i, c) for i, c in chunks)
    # All these chunks are sub-chunk-size; only the last one (idx 2) gets
    # to be short. Use chunk_size large enough to fit all 3 as full chunks.
    dec = FrameDecoder(chunk_size=6, total_chunks=3)
    out = list(dec.feed(stream))
    assert out == chunks


def test_frame_decoder_reassembles_split_buffers():
    payload = frame(0, b"abcdef") + frame(1, b"xyz")
    dec = FrameDecoder(chunk_size=6, total_chunks=2)
    out = []
    for byte in payload:
        out.extend(dec.feed(bytes([byte])))
    assert out == [(0, b"abcdef"), (1, b"xyz")]


def test_frame_decoder_rejects_zero_length_frame():
    """The new frame format reserves zero-length as malformed (a non-empty
    chunk is the only valid payload)."""
    bad = struct.pack(">II", 0, 0)
    dec = FrameDecoder(chunk_size=10, total_chunks=1)
    with pytest.raises(ProtocolError, match="zero-length"):
        list(dec.feed(bad))


# --- HYP-409: length-cap and bounds checks ---


def test_frame_decoder_rejects_oversized_chunk_length():
    """A peer that's accepted (post-handshake) shouldn't be able to
    declare a 4 GiB frame and OOM us. Cap declared length at chunk_size."""
    # Hand-craft a frame header claiming length=1024 with chunk_size=512.
    bogus = struct.pack(">II", 0, 1024)
    dec = FrameDecoder(chunk_size=512, total_chunks=1)
    with pytest.raises(ProtocolError, match="exceeds chunk_size|length"):
        list(dec.feed(bogus))


def test_frame_decoder_rejects_chunk_index_out_of_range():
    """Chunk index >= total_chunks is malformed (no such chunk exists
    in the offer's expected set)."""
    bogus = frame(5, b"hello")
    dec = FrameDecoder(chunk_size=10, total_chunks=3)
    with pytest.raises(ProtocolError, match="index|range"):
        list(dec.feed(bogus))


def test_frame_decoder_accepts_correct_last_chunk_short_length():
    """The last chunk of a transfer can be shorter than chunk_size.
    e.g. size=25, chunk_size=10 → last chunk index 2 has length 5."""
    last = frame(2, b"01234")  # 5 bytes, expected last-chunk length
    dec = FrameDecoder(chunk_size=10, total_chunks=3, total_size=25)
    out = list(dec.feed(last))
    assert out == [(2, b"01234")]


def test_frame_decoder_rejects_wrong_last_chunk_length():
    """Last chunk must be EXACTLY (size - 1) % chunk_size + 1 bytes
    (or chunk_size if size is a multiple). A peer sending a different
    length on the last chunk is misbehaving — refuse before write."""
    # size=25, chunk_size=10, last chunk should be exactly 5 bytes.
    # We declare 6 bytes which is wrong.
    wrong = frame(2, b"012345")  # 6 bytes
    dec = FrameDecoder(chunk_size=10, total_chunks=3, total_size=25)
    with pytest.raises(ProtocolError, match="last chunk|length"):
        list(dec.feed(wrong))


def test_frame_decoder_rejects_short_non_last_chunk():
    """Non-last chunks must be EXACTLY chunk_size bytes. A peer
    sending a partial frame for a non-last index is misbehaving."""
    # size=25, chunk_size=10. Non-last chunks (0, 1) must be 10 bytes.
    short = frame(0, b"01234")  # 5 bytes on a non-last chunk
    dec = FrameDecoder(chunk_size=10, total_chunks=3, total_size=25)
    with pytest.raises(ProtocolError, match="length|chunk_size"):
        list(dec.feed(short))


def test_frame_decoder_size_multiple_of_chunk_size_last_is_full():
    """When total_size is an exact multiple of chunk_size, the last
    chunk is also full chunk_size — not zero, not short."""
    # size=20, chunk_size=10, total_chunks=2. Last chunk is 10 bytes.
    last_full = frame(1, b"0123456789")
    dec = FrameDecoder(chunk_size=10, total_chunks=2, total_size=20)
    out = list(dec.feed(last_full))
    assert out == [(1, b"0123456789")]


def test_frame_decoder_size_zero_total_chunks_zero():
    """An empty transfer has zero chunks. Any frame received is
    malformed — there's nothing to receive."""
    dec = FrameDecoder(chunk_size=10, total_chunks=0, total_size=0)
    with pytest.raises(ProtocolError, match="index|range"):
        list(dec.feed(frame(0, b"x")))


def test_frame_rejects_zero_length_chunk():
    with pytest.raises(ValueError, match="zero-length"):
        frame(0, b"")


def test_frame_rejects_oversized_chunk():
    huge = b"x" * (1 << 32)
    with pytest.raises(ValueError, match="chunk too large"):
        frame(0, huge)


def test_frame_rejects_negative_chunk_index():
    with pytest.raises(ValueError, match="chunk_index"):
        frame(-1, b"data")


def test_subchannel_name_versioned():
    """The subchannel name should encode the protocol version so future
    incompatible changes don't accidentally cross-talk."""
    assert SUBCHANNEL_NAME.endswith("-v1")


# --- A6: offer caps ---


def test_build_offer_rejects_oversized_size():
    """Sender refuses to advertise files above MAX_OFFER_SIZE."""
    h = b"\x00" * 32
    with pytest.raises(ValueError, match="exceeds max"):
        build_offer_file("a.txt", MAX_OFFER_SIZE + 1, h)


def test_parse_offer_rejects_oversized_size():
    """Receiver refuses to accept offers above MAX_OFFER_SIZE."""
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    msg = json.dumps(
        {
            "offer": {
                "kind": "file",
                "transfer_id": tid_b64,
                "filename": "a.txt",
                "size": MAX_OFFER_SIZE + 1,
                "content_hash": h_b64,
                "chunk_size": 1 << 20,
            }
        }
    ).encode()
    with pytest.raises(ProtocolError, match="exceeds max"):
        parse_offer(msg)


def test_offer_at_max_size_accepted():
    """An offer at MAX_OFFER_SIZE must still be accepted post-HYP-392
    (chunk_count caps now live on the subchannel header)."""
    msg = build_offer_file("big.bin", MAX_OFFER_SIZE, b"\x00" * 32, chunk_size=1 << 20)
    parsed = parse_offer(encode_message(msg))
    assert parsed["size"] == MAX_OFFER_SIZE


# --- B1: filename hardening ---


def _make_offer_with_filename(filename):
    """Helper for building a syntactically-valid offer with a specific
    filename, to exercise parse_offer's filename validation. Computes
    a matching transfer_id (HYP-431) so that positive-path tests that
    pass a valid filename reach the filename check rather than failing
    on transfer_id mismatch first; for negative tests, the filename
    check fires before the transfer_id check anyway."""
    from takeit.cli._protocol import KIND_FILE, compute_transfer_id

    h = b"\x00" * 32
    tid = compute_transfer_id(KIND_FILE, 0, filename, h)
    return json.dumps(
        {
            "offer": {
                "kind": "file",
                "transfer_id": base64.b64encode(tid).decode(),
                "filename": filename,
                "size": 0,
                "content_hash": base64.b64encode(h).decode(),
                "chunk_size": 1024,
            }
        }
    ).encode()


def test_filename_rejects_nul_and_control_chars():
    for bad in (
        "auth.log\x00.txt",
        "a\x01b",
        "a\x1fb",
        "a\x7fb",
        "line1\nline2",
        "carriage\rreturn",
    ):
        with pytest.raises(ProtocolError):
            parse_offer(_make_offer_with_filename(bad))


def test_filename_rejects_windows_reserved_names():
    """`CON.txt` opens the console on Windows regardless of extension. We
    refuse on every platform so transferred files are portable."""
    for bad in (
        "CON",
        "con",
        "Con.txt",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "com9",
        "Com5.dat",
        "LPT1",
        "LPT9.txt",
    ):
        with pytest.raises(ProtocolError):
            parse_offer(_make_offer_with_filename(bad))


def test_filename_rejects_trailing_dot_or_space():
    """Windows strips trailing `.` and ` ` → namespace collision."""
    for bad in ("hello.", "hello ", "hello..", "hello   "):
        with pytest.raises(ProtocolError):
            parse_offer(_make_offer_with_filename(bad))


def test_filename_rejects_rtl_override():
    """U+202E (RIGHT-TO-LEFT OVERRIDE) reverses subsequent characters in
    the rendering layer — used to disguise extensions."""
    bad = "harmless‮txt.exe"
    with pytest.raises(ProtocolError):
        parse_offer(_make_offer_with_filename(bad))


def test_filename_rejects_oversized():
    """255 UTF-8 bytes is the practical NAME_MAX on common filesystems."""
    bad = "a" * (MAX_FILENAME_BYTES + 1)
    with pytest.raises(ProtocolError, match="exceeds"):
        parse_offer(_make_offer_with_filename(bad))


def test_filename_accepts_at_max_length():
    fn = "a" * MAX_FILENAME_BYTES
    parsed = parse_offer(_make_offer_with_filename(fn))
    assert parsed["filename"] == fn


def test_filename_accepts_emoji():
    """NFC-normalized emoji-bearing names are fine."""
    fn = "hello-🌍.txt"
    parsed = parse_offer(_make_offer_with_filename(fn))
    assert parsed["filename"] == fn


def test_build_offer_rejects_same_filenames_as_parse():
    """Sender-side validation must reject the same set as receiver-side
    so the sender doesn't accidentally craft an offer the peer will reject."""
    for bad in (
        "CON",
        "auth.log\x00.txt",
        "trailing.",
        "a" * (MAX_FILENAME_BYTES + 1),
        "hello‮evil",
    ):
        with pytest.raises(ValueError):
            build_offer_file(bad, 0, b"\x00" * 32)


# --- HYP-387: kind discriminator + per-kind builders ---


def test_parse_offer_rejects_missing_kind():
    """Every offer MUST carry a `kind` field. takeit owns both ends of the
    wire — there are no legacy peers to be lenient with."""
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    msg = json.dumps(
        {
            "offer": {
                # no "kind"
                "transfer_id": tid_b64,
                "filename": "a.txt",
                "size": 0,
                "content_hash": h_b64,
                "chunk_size": 1024,
            }
        }
    ).encode()
    with pytest.raises(ProtocolError, match="kind"):
        parse_offer(msg)


def test_parse_offer_rejects_unknown_kind():
    """Unknown kinds are a forward-compat trap: we'd rather refuse loudly
    than silently misinterpret a future format."""
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    msg = json.dumps(
        {
            "offer": {
                "kind": "stream",  # not a recognized kind
                "transfer_id": tid_b64,
                "filename": "a.txt",
                "size": 0,
                "content_hash": h_b64,
                "chunk_size": 1024,
            }
        }
    ).encode()
    with pytest.raises(ProtocolError, match="kind"):
        parse_offer(msg)


def test_build_offer_file_emits_kind_field():
    msg = build_offer_file("a.txt", 0, b"\x00" * 32)
    assert msg["offer"]["kind"] == "file"


# --- directory kind ---


def test_build_offer_directory_round_trips():
    """Directory offers carry dir_name + the deterministic-zip stream's
    size/content_hash, plus advisory num_files/num_bytes. chunk_hashes
    no longer ride here (HYP-392); they go on the dilation subchannel."""
    payload = b"a" * 1_500_000  # the streamed-zip bytes
    h_all = hashlib.blake2b(payload, digest_size=32).digest()
    msg = build_offer_directory(
        "my_project", len(payload), h_all, num_files=23, num_bytes=14_300_000
    )
    parsed = parse_offer(encode_message(msg))
    assert parsed["kind"] == "directory"
    assert parsed["dir_name"] == "my_project"
    assert parsed["size"] == len(payload)
    assert parsed["num_files"] == 23
    assert parsed["num_bytes"] == 14_300_000


def test_build_offer_directory_rejects_path_traversal_in_dir_name():
    h = b"\x00" * 32
    for bad in ("a/b", "..", ".", "", "x\\y", "CON", ".hidden"):
        with pytest.raises(ValueError):
            build_offer_directory(bad, 0, h, num_files=0, num_bytes=0)


def test_build_offer_directory_rejects_negative_num_files_or_num_bytes():
    h = b"\x00" * 32
    with pytest.raises(ValueError):
        build_offer_directory("ok", 0, h, num_files=-1, num_bytes=0)
    with pytest.raises(ValueError):
        build_offer_directory("ok", 0, h, num_files=0, num_bytes=-1)


def test_parse_offer_directory_rejects_missing_num_files():
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    msg = json.dumps(
        {
            "offer": {
                "kind": "directory",
                "transfer_id": tid_b64,
                "dir_name": "my_project",
                "size": 0,
                "content_hash": h_b64,
                "chunk_size": 1024,
                # no num_files / num_bytes
            }
        }
    ).encode()
    with pytest.raises(ProtocolError, match="num_files|missing"):
        parse_offer(msg)


def test_parse_offer_directory_rejects_filename_field():
    """A directory offer must use dir_name; receiving a `filename` field
    is a wire confusion — refuse rather than silently pick one."""
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    msg = json.dumps(
        {
            "offer": {
                "kind": "directory",
                "transfer_id": tid_b64,
                "filename": "wrong-field-for-dir",
                "size": 0,
                "content_hash": h_b64,
                "chunk_size": 1024,
                "num_files": 0,
                "num_bytes": 0,
            }
        }
    ).encode()
    with pytest.raises(ProtocolError):
        parse_offer(msg)


# --- text kind ---


def test_build_offer_text_round_trips():
    msg = build_offer_text("hello world")
    parsed = parse_offer(encode_message(msg))
    assert parsed["kind"] == "text"
    assert parsed["text"] == "hello world"
    # transfer_id still present and 16 bytes for consistency
    assert len(parsed["_transfer_id_bytes"]) == TRANSFER_ID_BYTES


def test_build_offer_text_rejects_non_string():
    with pytest.raises(ValueError):
        build_offer_text(b"bytes-not-str")  # noqa


def test_build_offer_text_rejects_oversized():
    """Text offers ride inside the takeit control message — cap at
    MAX_TEXT_BYTES UTF-8 bytes to stay well under the layer's payload
    limit and bound memory."""
    too_big = "x" * (MAX_TEXT_BYTES + 1)
    with pytest.raises(ValueError, match="exceeds"):
        build_offer_text(too_big)


def test_build_offer_text_accepts_at_max():
    fn = "x" * MAX_TEXT_BYTES
    msg = build_offer_text(fn)
    parsed = parse_offer(encode_message(msg))
    assert parsed["text"] == fn


def test_text_offer_at_max_fits_rendezvous_inbound_cap():
    payload = encode_message(build_offer_text("x" * MAX_TEXT_BYTES))
    encrypted = encrypt_data(b"\x00" * 32, payload)
    assert len(encrypted) <= MAX_INBOUND_EVENT_CONTENT_BYTES


def test_parse_offer_text_rejects_oversized():
    """Receiver enforces the same cap, regardless of what a peer sends."""
    big = "x" * (MAX_TEXT_BYTES + 1)
    msg = json.dumps(
        {
            "offer": {
                "kind": "text",
                "transfer_id": base64.b64encode(b"\x00" * 16).decode(),
                "text": big,
            }
        }
    ).encode()
    with pytest.raises(ProtocolError, match="exceeds"):
        parse_offer(msg)


def test_parse_offer_text_rejects_missing_text():
    msg = json.dumps(
        {
            "offer": {
                "kind": "text",
                "transfer_id": base64.b64encode(b"\x00" * 16).decode(),
                # no "text"
            }
        }
    ).encode()
    with pytest.raises(ProtocolError, match="text|missing"):
        parse_offer(msg)


def test_parse_offer_text_rejects_non_string_text():
    msg = json.dumps(
        {
            "offer": {
                "kind": "text",
                "transfer_id": base64.b64encode(b"\x00" * 16).decode(),
                "text": 123,
            }
        }
    ).encode()
    with pytest.raises(ProtocolError, match="text"):
        parse_offer(msg)


def test_text_offer_does_not_carry_chunk_fields():
    """A text offer has no chunks — the wire format must not require them.
    A receiver that sees `chunk_hashes` on a text offer should still
    accept (forward-compat ignore) but the canonical builder MUST NOT
    emit them."""
    msg = build_offer_text("hi")
    o = msg["offer"]
    assert "chunk_hashes" not in o
    assert "chunk_size" not in o
    assert "size" not in o
    assert "filename" not in o
    assert "dir_name" not in o

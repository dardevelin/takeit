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

from takeit.cli._protocol import (
    DEFAULT_CHUNK_SIZE, FrameDecoder, MAX_CHUNK_COUNT, MAX_FILENAME_BYTES,
    MAX_OFFER_SIZE, MAX_TEXT_BYTES, ProtocolError, SUBCHANNEL_NAME,
    TRANSFER_ID_BYTES, build_answer, build_complete, build_done,
    build_offer_directory, build_offer_file, build_offer_text,
    chunk_hashes_for_file, compute_transfer_id, encode_message,
    expected_chunk_count, frame, hash_file, parse_answer, parse_offer,
    parse_simple_flag, verify_chunk,
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
        str(path), chunk_size=1 << 20)
    assert size == len(payload)
    assert content_hash == hashlib.blake2b(payload, digest_size=32).digest()
    # Reconstruct chunk hashes manually
    expected = []
    for i in range(0, len(payload), 1 << 20):
        ch = payload[i:i + (1 << 20)]
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
    chunks = [
        hashlib.blake2b(payload[i:i + (1 << 20)], digest_size=32).digest()
        for i in range(0, len(payload), 1 << 20)
    ]
    msg = build_offer_file("doc.pdf", len(payload), h_all, chunks)
    parsed = parse_offer(encode_message(msg))
    assert parsed["kind"] == "file"
    assert parsed["filename"] == "doc.pdf"
    assert parsed["size"] == len(payload)
    assert parsed["chunk_size"] == DEFAULT_CHUNK_SIZE
    assert parsed["_content_hash_bytes"] == h_all
    assert parsed["_chunk_hashes_bytes"] == chunks
    assert len(parsed["_transfer_id_bytes"]) == TRANSFER_ID_BYTES


def test_build_offer_rejects_path_traversal():
    h = b"\x00" * 32
    chunks = []
    for bad in ("a/b.txt", "..", ".", "", "x\\y"):
        with pytest.raises(ValueError):
            build_offer_file(bad, 0, h, chunks)


def test_build_offer_rejects_negative_size():
    with pytest.raises(ValueError):
        build_offer_file("a.txt", -1, b"\x00" * 32, [])


def test_build_offer_rejects_non_positive_chunk_size():
    with pytest.raises(ValueError):
        build_offer_file("a.txt", 0, b"\x00" * 32, [], chunk_size=0)


def test_build_offer_rejects_wrong_chunk_count():
    """If size and chunk_hashes don't match, the offer is incoherent."""
    h = b"\x00" * 32
    # Size 100, chunk_size 50 = 2 chunks needed
    with pytest.raises(ValueError, match="chunk_hashes count"):
        build_offer_file("a.txt", 100, h, [b"\x00" * 32], chunk_size=50)


def test_build_offer_rejects_bad_chunk_hash_size():
    h = b"\x00" * 32
    with pytest.raises(ValueError, match="32 bytes"):
        build_offer_file("a.txt", 1, h, [b"\x00" * 16])


# --- offer parsing ---


def _serializable_offer(size=1, chunk_size=1024, filename="a.txt",
                       transfer_id_bytes=None, content_hash_bytes=None,
                       chunk_hashes_bytes=None):
    """Build a JSON-serializable offer payload for negative tests."""
    if transfer_id_bytes is None:
        transfer_id_bytes = b"\x00" * 16
    if content_hash_bytes is None:
        content_hash_bytes = b"\x00" * 32
    if chunk_hashes_bytes is None:
        n = expected_chunk_count(size, chunk_size)
        chunk_hashes_bytes = [b"\x00" * 32 for _ in range(n)]
    return json.dumps({"offer": {
        "kind": "file",
        "transfer_id": base64.b64encode(transfer_id_bytes).decode(),
        "filename": filename,
        "size": size,
        "content_hash": base64.b64encode(content_hash_bytes).decode(),
        "chunk_size": chunk_size,
        "chunk_hashes": [base64.b64encode(h).decode()
                         for h in chunk_hashes_bytes],
    }}).encode()


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
    bad_filenames = ["foo/bar.txt", "..", ".", "", "..\\nope",
                     ".hidden", "/etc/passwd"]
    for fn in bad_filenames:
        msg = _serializable_offer(filename=fn)
        with pytest.raises(ProtocolError):
            parse_offer(msg)


def test_parse_offer_rejects_wrong_chunk_count():
    """If the offer's chunk_hashes don't cover the size, reject."""
    # Size 100, chunk_size 50 = 2 chunks, but only 1 hash provided
    msg = _serializable_offer(
        size=100, chunk_size=50, chunk_hashes_bytes=[b"\x00" * 32])
    with pytest.raises(ProtocolError, match="chunk_hashes count"):
        parse_offer(msg)


def test_parse_offer_rejects_bad_chunk_hash_length():
    msg = _serializable_offer(
        size=10, chunk_size=10,
        chunk_hashes_bytes=[b"\x00" * 16])  # wrong length
    with pytest.raises(ProtocolError, match="32 bytes"):
        parse_offer(msg)


# --- answer ---


def test_build_and_parse_answer_accept_no_chunks():
    payload = encode_message(build_answer(True))
    accepted, reason, chunks_have = parse_answer(payload)
    assert accepted is True
    assert reason is None
    assert chunks_have == []


def test_build_and_parse_answer_accept_with_resumed_chunks():
    payload = encode_message(build_answer(True, chunks_have=[5, 0, 2]))
    accepted, reason, chunks_have = parse_answer(payload)
    assert accepted is True
    assert reason is None
    # Should be sorted
    assert chunks_have == [0, 2, 5]


def test_build_and_parse_answer_reject():
    payload = encode_message(build_answer(False, "user said no"))
    accepted, reason, chunks_have = parse_answer(payload)
    assert accepted is False
    assert reason == "user said no"
    assert chunks_have == []


def test_parse_answer_rejects_non_int_chunks_have():
    msg = json.dumps({"answer": {
        "accept": True, "chunks_have": ["bad"]}}).encode()
    with pytest.raises(ProtocolError):
        parse_answer(msg)


def test_parse_answer_rejects_negative_chunks_have():
    msg = json.dumps({"answer": {
        "accept": True, "chunks_have": [-1]}}).encode()
    with pytest.raises(ProtocolError):
        parse_answer(msg)


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
    dec = FrameDecoder()
    out = list(dec.feed(stream))
    assert out == chunks


def test_frame_decoder_reassembles_split_buffers():
    payload = frame(0, b"abcdef") + frame(1, b"xyz")
    dec = FrameDecoder()
    out = []
    for byte in payload:
        out.extend(dec.feed(bytes([byte])))
    assert out == [(0, b"abcdef"), (1, b"xyz")]


def test_frame_decoder_rejects_zero_length_frame():
    """The new frame format reserves zero-length as malformed (a non-empty
    chunk is the only valid payload)."""
    bad = struct.pack(">II", 0, 0)
    dec = FrameDecoder()
    with pytest.raises(ProtocolError, match="zero-length"):
        list(dec.feed(bad))


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
        build_offer_file("a.txt", MAX_OFFER_SIZE + 1, h, [])


def test_parse_offer_rejects_oversized_size():
    """Receiver refuses to accept offers above MAX_OFFER_SIZE; this caps
    memory use during chunk_hashes allocation."""
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    msg = json.dumps({"offer": {
        "kind": "file",
        "transfer_id": tid_b64,
        "filename": "a.txt",
        "size": MAX_OFFER_SIZE + 1,
        "content_hash": h_b64,
        "chunk_size": 1 << 20,
        "chunk_hashes": [],
    }}).encode()
    with pytest.raises(ProtocolError, match="exceeds max"):
        parse_offer(msg)


def test_parse_offer_rejects_too_many_chunk_hashes_pre_decode():
    """A list of MAX_CHUNK_COUNT+1 chunk_hashes is rejected BEFORE we try
    to base64-decode them — so a malicious offer with millions of garbage
    strings doesn't even trigger the per-string allocator."""
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    bogus_hash_b64 = base64.b64encode(b"\x00" * 32).decode()
    msg = json.dumps({"offer": {
        "kind": "file",
        "transfer_id": tid_b64,
        "filename": "a.txt",
        "size": 1024,
        "content_hash": h_b64,
        "chunk_size": 1,
        "chunk_hashes": [bogus_hash_b64] * (MAX_CHUNK_COUNT + 1),
    }}).encode()
    with pytest.raises(ProtocolError, match="exceeds max"):
        parse_offer(msg)


def test_parse_offer_rejects_implied_chunk_count_overflow():
    """size=1 GiB / chunk_size=1 → 2^30 implied chunks → reject before
    allocating a list of that size."""
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    msg = json.dumps({"offer": {
        "kind": "file",
        "transfer_id": tid_b64,
        "filename": "a.txt",
        "size": 1 << 30,  # 1 GiB
        "content_hash": h_b64,
        "chunk_size": 1,  # 2^30 chunks expected
        "chunk_hashes": [],
    }}).encode()
    with pytest.raises(ProtocolError, match="exceeds max"):
        parse_offer(msg)


def test_offer_at_max_size_with_max_chunks_accepted():
    """An offer with size = MAX_OFFER_SIZE and chunk_size sized so that
    the chunk count equals MAX_CHUNK_COUNT must be accepted."""
    chunk_size = MAX_OFFER_SIZE // MAX_CHUNK_COUNT  # exactly MAX_CHUNK_COUNT chunks
    chunks = [b"\x00" * 32] * MAX_CHUNK_COUNT
    msg = build_offer_file("big.bin", MAX_OFFER_SIZE,
                      b"\x00" * 32, chunks, chunk_size=chunk_size)
    parsed = parse_offer(encode_message(msg))
    assert parsed["size"] == MAX_OFFER_SIZE


# --- B1: filename hardening ---


def _make_offer_with_filename(filename):
    """Helper for building a syntactically-valid offer with a specific
    filename, to exercise parse_offer's filename validation."""
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    return json.dumps({"offer": {
        "kind": "file",
        "transfer_id": tid_b64,
        "filename": filename,
        "size": 0,
        "content_hash": h_b64,
        "chunk_size": 1024,
        "chunk_hashes": [],
    }}).encode()


def test_filename_rejects_nul_and_control_chars():
    for bad in ("auth.log\x00.txt", "a\x01b", "a\x1fb", "a\x7fb",
                "line1\nline2", "carriage\rreturn"):
        with pytest.raises(ProtocolError):
            parse_offer(_make_offer_with_filename(bad))


def test_filename_rejects_windows_reserved_names():
    """`CON.txt` opens the console on Windows regardless of extension. We
    refuse on every platform so transferred files are portable."""
    for bad in ("CON", "con", "Con.txt", "PRN", "AUX", "NUL",
                "COM1", "com9", "Com5.dat", "LPT1", "LPT9.txt"):
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
    for bad in ("CON", "auth.log\x00.txt", "trailing.",
                "a" * (MAX_FILENAME_BYTES + 1), "hello‮evil"):
        with pytest.raises(ValueError):
            build_offer_file(bad, 0, b"\x00" * 32, [])


# --- HYP-387: kind discriminator + per-kind builders ---


def test_parse_offer_rejects_missing_kind():
    """Every offer MUST carry a `kind` field. takeit owns both ends of the
    wire — there are no legacy peers to be lenient with."""
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    msg = json.dumps({"offer": {
        # no "kind"
        "transfer_id": tid_b64,
        "filename": "a.txt",
        "size": 0,
        "content_hash": h_b64,
        "chunk_size": 1024,
        "chunk_hashes": [],
    }}).encode()
    with pytest.raises(ProtocolError, match="kind"):
        parse_offer(msg)


def test_parse_offer_rejects_unknown_kind():
    """Unknown kinds are a forward-compat trap: we'd rather refuse loudly
    than silently misinterpret a future format."""
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    msg = json.dumps({"offer": {
        "kind": "stream",  # not a recognized kind
        "transfer_id": tid_b64,
        "filename": "a.txt",
        "size": 0,
        "content_hash": h_b64,
        "chunk_size": 1024,
        "chunk_hashes": [],
    }}).encode()
    with pytest.raises(ProtocolError, match="kind"):
        parse_offer(msg)


def test_build_offer_file_emits_kind_field():
    msg = build_offer_file("a.txt", 0, b"\x00" * 32, [])
    assert msg["offer"]["kind"] == "file"


# --- directory kind ---


def test_build_offer_directory_round_trips():
    """Directory offers carry dir_name + the deterministic-zip stream's
    size/content_hash/chunk_hashes, plus advisory num_files/num_bytes."""
    payload = b"a" * 1_500_000  # the streamed-zip bytes
    h_all = hashlib.blake2b(payload, digest_size=32).digest()
    chunks = [
        hashlib.blake2b(payload[i:i + (1 << 20)], digest_size=32).digest()
        for i in range(0, len(payload), 1 << 20)
    ]
    msg = build_offer_directory(
        "my_project", len(payload), h_all, chunks,
        num_files=23, num_bytes=14_300_000)
    parsed = parse_offer(encode_message(msg))
    assert parsed["kind"] == "directory"
    assert parsed["dir_name"] == "my_project"
    assert parsed["size"] == len(payload)
    assert parsed["num_files"] == 23
    assert parsed["num_bytes"] == 14_300_000
    assert parsed["_chunk_hashes_bytes"] == chunks


def test_build_offer_directory_rejects_path_traversal_in_dir_name():
    h = b"\x00" * 32
    for bad in ("a/b", "..", ".", "", "x\\y", "CON", ".hidden"):
        with pytest.raises(ValueError):
            build_offer_directory(bad, 0, h, [], num_files=0, num_bytes=0)


def test_build_offer_directory_rejects_negative_num_files_or_num_bytes():
    h = b"\x00" * 32
    with pytest.raises(ValueError):
        build_offer_directory("ok", 0, h, [], num_files=-1, num_bytes=0)
    with pytest.raises(ValueError):
        build_offer_directory("ok", 0, h, [], num_files=0, num_bytes=-1)


def test_parse_offer_directory_rejects_missing_num_files():
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    msg = json.dumps({"offer": {
        "kind": "directory",
        "transfer_id": tid_b64,
        "dir_name": "my_project",
        "size": 0,
        "content_hash": h_b64,
        "chunk_size": 1024,
        "chunk_hashes": [],
        # no num_files / num_bytes
    }}).encode()
    with pytest.raises(ProtocolError, match="num_files|missing"):
        parse_offer(msg)


def test_parse_offer_directory_rejects_filename_field():
    """A directory offer must use dir_name; receiving a `filename` field
    is a wire confusion — refuse rather than silently pick one."""
    h_b64 = base64.b64encode(b"\x00" * 32).decode()
    tid_b64 = base64.b64encode(b"\x00" * 16).decode()
    msg = json.dumps({"offer": {
        "kind": "directory",
        "transfer_id": tid_b64,
        "filename": "wrong-field-for-dir",
        "size": 0,
        "content_hash": h_b64,
        "chunk_size": 1024,
        "chunk_hashes": [],
        "num_files": 0,
        "num_bytes": 0,
    }}).encode()
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
    """Text offers ride inside the wormhole control message — cap at
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


def test_parse_offer_text_rejects_oversized():
    """Receiver enforces the same cap, regardless of what a peer sends."""
    big = "x" * (MAX_TEXT_BYTES + 1)
    msg = json.dumps({"offer": {
        "kind": "text",
        "transfer_id": base64.b64encode(b"\x00" * 16).decode(),
        "text": big,
    }}).encode()
    with pytest.raises(ProtocolError, match="exceeds"):
        parse_offer(msg)


def test_parse_offer_text_rejects_missing_text():
    msg = json.dumps({"offer": {
        "kind": "text",
        "transfer_id": base64.b64encode(b"\x00" * 16).decode(),
        # no "text"
    }}).encode()
    with pytest.raises(ProtocolError, match="text|missing"):
        parse_offer(msg)


def test_parse_offer_text_rejects_non_string_text():
    msg = json.dumps({"offer": {
        "kind": "text",
        "transfer_id": base64.b64encode(b"\x00" * 16).decode(),
        "text": 123,
    }}).encode()
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

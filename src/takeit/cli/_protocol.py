"""
takeit file-transfer protocol — pure logic, no I/O.

Wire format (control over the wormhole's app-message channel; bulk over a
dilation subchannel):

Control messages (JSON, one per app-message):
- Sender → Receiver: ``{"offer": {...}}`` then ``{"complete": true}``
- Receiver → Sender: ``{"answer": {"accept": true, "chunks_have": [...]}}``
  or ``{"answer": {"reject": "reason"}}``, then ``{"done": true}``

Offer fields:
    transfer_id   : str    — base64 of BLAKE2b(size||name||content)[:16]
    filename      : str    — the destination filename (no path traversal)
    size          : int    — total bytes
    content_hash  : str    — base64 of BLAKE2b-256 over the entire file
    chunk_size    : int    — bytes per chunk (default 1 MiB)
    chunk_hashes  : list[str] — base64 BLAKE2b-256 per chunk, in order
    app_version   : str

Bulk format on the dilation subchannel:
    repeated frames of:
        chunk_index  (4 bytes BE)
        chunk_length (4 bytes BE)
        chunk_bytes  (chunk_length bytes)
    The sender writes only the chunks the receiver doesn't already have
    (per `chunks_have` in the answer), in any order, and then closes the
    channel. The receiver tracks which indices arrived and refuses to
    finalize unless ``chunks_have ∪ received == {0..N-1}``.
"""
import base64
import hashlib
import json
import os
import struct
import unicodedata


# Subchannel name for the bulk-transfer protocol. Versioned in the name so
# future incompatible changes can coexist.
SUBCHANNEL_NAME = "takeit-xfer-v1"

# Default chunk size on the bulk subchannel: 1 MiB. Big enough to amortize
# framing overhead, small enough to keep memory bounded.
DEFAULT_CHUNK_SIZE = 1 << 20

# 16-byte transfer-id is enough for collision-free identification in any
# reasonable per-user set of in-flight transfers.
TRANSFER_ID_BYTES = 16

# Hard caps on offer dimensions. A malicious sender could otherwise claim
# size=2**63-1 with chunk_size=1, causing the receiver to allocate ~9e18
# entries in `_chunk_hashes_bytes` and OOM before the user even sees the
# offer prompt. These limits are loose — 1 TiB / 1M chunks covers any
# realistic file — but bounded.
MAX_OFFER_SIZE = 1 << 40         # 1 TiB
MAX_CHUNK_COUNT = 1 << 20        # ~1M chunks (with 1 MiB chunks → 1 TiB)

# Filename length cap. POSIX `NAME_MAX` is 255 on most filesystems; some
# (HFS+, APFS) accept more but limit by codepoints not bytes. We enforce
# UTF-8 bytes ≤ 255 to be portable.
MAX_FILENAME_BYTES = 255

# Windows reserved device names (case-insensitive). On Windows these names
# refer to devices regardless of extension — `CON.txt` opens the console.
# We reject them on every platform so a takeit transfer can be moved to
# Windows without breakage.
_WINDOWS_RESERVED = frozenset({
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5",
    "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
    "LPT6", "LPT7", "LPT8", "LPT9",
})


class ProtocolError(ValueError):
    """Wire-format violation by the peer."""


def _validate_filename(fn):
    """Strict filename validation. Raises ValueError on any issue.

    Defenses against:
    - Path traversal (``/``, ``\\``, ``..``, leading ``.``).
    - Control characters and NUL injection (``< 0x20`` or ``== 0x7F``).
    - Windows reserved device names (case-insensitive, with or without
      extension).
    - Trailing ``.`` or space (Windows strips these → namespace collision).
    - Unicode normalization mismatches (RTL/homoglyph attacks).
    - Excessive length.
    """
    if not isinstance(fn, str):
        raise ValueError(f"filename must be str, got {type(fn).__name__}")
    if not fn:
        raise ValueError("filename must not be empty")
    if len(fn.encode("utf-8")) > MAX_FILENAME_BYTES:
        raise ValueError(
            f"filename exceeds {MAX_FILENAME_BYTES} UTF-8 bytes")
    # Path-component checks
    if "/" in fn or "\\" in fn:
        raise ValueError(f"unsafe filename: separator in {fn!r}")
    if fn in (".", ".."):
        raise ValueError(f"unsafe filename: {fn!r}")
    if fn.startswith("."):
        raise ValueError(f"unsafe filename: leading dot in {fn!r}")
    # Defense in depth: must equal its own basename. Catches a class of
    # exotic separators we might not have thought of.
    if os.path.basename(fn) != fn:
        raise ValueError(f"unsafe filename: not a basename: {fn!r}")
    # Control characters including NUL, CR, LF, ESC, DEL, plus Unicode
    # bidirectional-override codepoints (U+202A–202E, U+2066–2069). Both
    # are used to visually spoof filenames — RTL override can disguise an
    # `.exe` as a `.txt` in directory listings and most editors.
    for c in fn:
        cp = ord(c)
        if cp < 0x20 or cp == 0x7F:
            raise ValueError(
                f"unsafe filename: control character {c!r}")
        if 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
            raise ValueError(
                f"unsafe filename: Unicode bidi-override U+{cp:04X}")
    # Trailing dot or space: Windows silently strips → collision/overwrite.
    if fn.endswith(".") or fn.endswith(" "):
        raise ValueError(
            f"unsafe filename: trailing dot or space in {fn!r}")
    # Windows reserved device stems (CON, COM1, ..., regardless of extension).
    stem = fn.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED:
        raise ValueError(
            f"unsafe filename: Windows reserved name {fn!r}")
    # Unicode normalization mismatch — catches RTL override (U+202E) and
    # homoglyph confusables. The sender should send NFC; if the receiver
    # gets non-NFC, refuse rather than guess.
    if unicodedata.normalize("NFC", fn) != fn:
        raise ValueError(
            f"unsafe filename: not Unicode-normalized (NFC) {fn!r}")


def hash_file(path):
    """Stream a file through BLAKE2b-256 and return (size, digest_bytes)."""
    h = hashlib.blake2b(digest_size=32)
    size = 0
    with open(path, "rb") as f:
        while True:
            buf = f.read(1 << 16)
            if not buf:
                break
            size += len(buf)
            h.update(buf)
    return size, h.digest()


def compute_transfer_id(size, filename, content_hash):
    """16-byte deterministic identifier for this transfer."""
    h = hashlib.blake2b(digest_size=TRANSFER_ID_BYTES)
    h.update(struct.pack(">Q", size))
    h.update(b"|")
    h.update(filename.encode("utf-8"))
    h.update(b"|")
    h.update(content_hash)
    return h.digest()


def build_offer(filename, size, content_hash, chunk_hashes,
                chunk_size=DEFAULT_CHUNK_SIZE, app_version="takeit/0.0.1"):
    """Construct an offer dict, suitable for json.dumps + wormhole send.

    `chunk_hashes` is a list of 32-byte BLAKE2b-256 digests, one per chunk
    in order. The receiver uses these to verify each chunk on arrival and
    to identify reusable chunks across resumed transfers.
    """
    _validate_filename(filename)
    if size < 0:
        raise ValueError(f"negative size: {size}")
    if size > MAX_OFFER_SIZE:
        raise ValueError(
            f"offer size {size} exceeds max {MAX_OFFER_SIZE}")
    if chunk_size <= 0:
        raise ValueError(f"non-positive chunk_size: {chunk_size}")
    expected_count = expected_chunk_count(size, chunk_size)
    if expected_count > MAX_CHUNK_COUNT:
        raise ValueError(
            f"chunk count {expected_count} exceeds max {MAX_CHUNK_COUNT}")
    if len(chunk_hashes) != expected_count:
        raise ValueError(
            f"chunk_hashes count {len(chunk_hashes)} != expected "
            f"{expected_count}")
    for ch in chunk_hashes:
        if not isinstance(ch, (bytes, bytearray)) or len(ch) != 32:
            raise ValueError("each chunk hash must be 32 bytes")
    transfer_id = compute_transfer_id(size, filename, content_hash)
    return {
        "offer": {
            "transfer_id": base64.b64encode(transfer_id).decode("ascii"),
            "filename": filename,
            "size": size,
            "content_hash": base64.b64encode(content_hash).decode("ascii"),
            "chunk_size": chunk_size,
            "chunk_hashes": [
                base64.b64encode(h).decode("ascii") for h in chunk_hashes],
            "app_version": app_version,
        }
    }


def expected_chunk_count(size, chunk_size):
    """Number of chunks needed to cover `size` bytes at `chunk_size`."""
    if size == 0:
        return 0
    return (size + chunk_size - 1) // chunk_size


def parse_offer(payload):
    """Parse an inbound app-message; return the inner offer dict.

    Raises ProtocolError if the message is malformed or not an offer.
    """
    msg = _decode(payload)
    if not isinstance(msg, dict) or "offer" not in msg:
        raise ProtocolError("expected an 'offer' message")
    o = msg["offer"]
    for field in ("transfer_id", "filename", "size", "content_hash",
                  "chunk_size", "chunk_hashes"):
        if field not in o:
            raise ProtocolError(f"offer missing {field!r}")
    if not isinstance(o["filename"], str):
        raise ProtocolError("filename must be str")
    try:
        _validate_filename(o["filename"])
    except ValueError as e:
        raise ProtocolError(str(e))
    if not isinstance(o["size"], int) or o["size"] < 0:
        raise ProtocolError("size must be a non-negative int")
    if o["size"] > MAX_OFFER_SIZE:
        raise ProtocolError(
            f"offer size {o['size']} exceeds max {MAX_OFFER_SIZE}")
    if not isinstance(o["chunk_size"], int) or o["chunk_size"] <= 0:
        raise ProtocolError("chunk_size must be a positive int")
    if not isinstance(o["chunk_hashes"], list):
        raise ProtocolError("chunk_hashes must be a list")
    # Cap chunk count BEFORE base64-decoding the chunk_hashes list. A
    # malicious offer with size=2**40, chunk_size=1 would otherwise allocate
    # ~1e12 entries during decode and OOM the receiver.
    if len(o["chunk_hashes"]) > MAX_CHUNK_COUNT:
        raise ProtocolError(
            f"chunk_hashes count {len(o['chunk_hashes'])} exceeds max "
            f"{MAX_CHUNK_COUNT}")
    expected_count = expected_chunk_count(o["size"], o["chunk_size"])
    if expected_count > MAX_CHUNK_COUNT:
        raise ProtocolError(
            f"expected chunk count {expected_count} exceeds max "
            f"{MAX_CHUNK_COUNT}")
    try:
        o["_transfer_id_bytes"] = base64.b64decode(o["transfer_id"])
        o["_content_hash_bytes"] = base64.b64decode(o["content_hash"])
        o["_chunk_hashes_bytes"] = [
            base64.b64decode(h) for h in o["chunk_hashes"]]
    except Exception as e:
        raise ProtocolError(f"bad base64 in offer: {e}")
    if len(o["_transfer_id_bytes"]) != TRANSFER_ID_BYTES:
        raise ProtocolError("transfer_id must be 16 bytes")
    if len(o["_content_hash_bytes"]) != 32:
        raise ProtocolError("content_hash must be 32 bytes (BLAKE2b-256)")
    if len(o["_chunk_hashes_bytes"]) != expected_count:
        raise ProtocolError(
            f"chunk_hashes count {len(o['_chunk_hashes_bytes'])} != expected "
            f"{expected_count}")
    for h in o["_chunk_hashes_bytes"]:
        if len(h) != 32:
            raise ProtocolError("each chunk hash must be 32 bytes")
    return o


def build_answer(accept, reject_reason=None, chunks_have=None):
    """Receiver's response to the offer.

    `chunks_have` is a list of chunk indices the receiver already has from a
    prior partial transfer. Empty (or omitted) for fresh transfers.
    """
    if accept:
        return {"answer": {
            "accept": True,
            "chunks_have": sorted(chunks_have) if chunks_have else [],
        }}
    return {"answer": {"reject": reject_reason or "rejected"}}


def parse_answer(payload):
    """Returns (accepted: bool, reason: str or None, chunks_have: list[int]).

    For rejected answers, chunks_have is an empty list.
    """
    msg = _decode(payload)
    if not isinstance(msg, dict) or "answer" not in msg:
        raise ProtocolError("expected an 'answer' message")
    a = msg["answer"]
    if a.get("accept") is True:
        chunks_have = a.get("chunks_have", [])
        if not isinstance(chunks_have, list) or \
                not all(isinstance(i, int) and i >= 0 for i in chunks_have):
            raise ProtocolError("chunks_have must be a list of non-negative ints")
        return True, None, chunks_have
    if "reject" in a:
        return False, str(a["reject"]), []
    raise ProtocolError("answer missing 'accept' or 'reject'")


def build_complete():
    return {"complete": True}


def build_done():
    return {"done": True}


def parse_simple_flag(payload, key):
    """Validate a one-shot ``{key: true}`` message (`complete` or `done`)."""
    msg = _decode(payload)
    if not (isinstance(msg, dict) and msg.get(key) is True):
        raise ProtocolError(f"expected {{'{key}': true}}; got {msg!r}")


def _decode(payload):
    if isinstance(payload, (bytes, bytearray)):
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ProtocolError(f"control message not UTF-8: {e}")
    try:
        return json.loads(payload)
    except json.JSONDecodeError as e:
        raise ProtocolError(f"control message not JSON: {e}")


def encode_message(msg):
    """Serialize a control message to bytes, ready for wormhole send."""
    return json.dumps(msg, separators=(",", ":")).encode("utf-8")


# --- bulk-channel framing ---


# 8-byte frame header: 4 bytes BE chunk_index, 4 bytes BE chunk_length.
_FRAME_HDR = struct.Struct(">II")


def frame(chunk_index: int, chunk: bytes) -> bytes:
    """Build a `chunk_index || chunk_length || chunk` frame for the bulk channel."""
    if chunk_index < 0 or chunk_index > 0xFFFFFFFF:
        raise ValueError("chunk_index out of range")
    if len(chunk) > 0xFFFFFFFF:
        raise ValueError("chunk too large for 4-byte length prefix")
    if len(chunk) == 0:
        raise ValueError("zero-length chunks are not allowed")
    return _FRAME_HDR.pack(chunk_index, len(chunk)) + chunk


class FrameDecoder:
    """Buffer incremental bytes from a subchannel and yield complete frames.

    Yields ``(chunk_index, chunk_bytes)`` tuples as frames complete. The
    bulk subchannel doesn't need an explicit end-of-stream marker because
    the receiver knows the expected set of indices from the offer + answer
    handshake; it considers the transfer complete when ``connectionLost``
    arrives AND every expected chunk has been delivered.
    """

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes):
        self._buf.extend(data)
        while True:
            if len(self._buf) < _FRAME_HDR.size:
                return
            chunk_index, length = _FRAME_HDR.unpack(
                bytes(self._buf[:_FRAME_HDR.size]))
            if length == 0:
                raise ProtocolError("zero-length chunk frame is invalid")
            total = _FRAME_HDR.size + length
            if len(self._buf) < total:
                return
            chunk = bytes(self._buf[_FRAME_HDR.size:total])
            del self._buf[:total]
            yield (chunk_index, chunk)


def chunk_hashes_for_file(path, chunk_size=DEFAULT_CHUNK_SIZE):
    """Stream a file and produce (size, content_hash, chunk_hashes).

    Returns the size, the BLAKE2b-256 over the whole file, and a list of
    BLAKE2b-256 digests, one per chunk in order. Reads each chunk into
    memory exactly once (sized at most `chunk_size`).
    """
    h_all = hashlib.blake2b(digest_size=32)
    chunk_hashes = []
    size = 0
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk_size)
            if not buf:
                break
            size += len(buf)
            h_all.update(buf)
            chunk_hashes.append(
                hashlib.blake2b(buf, digest_size=32).digest())
    return size, h_all.digest(), chunk_hashes


def verify_chunk(chunk_bytes, expected_hash):
    """True if BLAKE2b-256(chunk_bytes) matches expected_hash exactly."""
    return hashlib.blake2b(
        chunk_bytes, digest_size=32).digest() == expected_hash

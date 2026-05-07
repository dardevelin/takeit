"""
takeit file-transfer protocol — pure logic, no I/O.

Wire format (control over the wormhole's app-message channel; bulk over a
dilation subchannel):

Rendezvous-visible control messages (JSON, one per app-message):
- Sender → Receiver: ``{"offer": {...}}`` then ``{"complete": true}``
- Receiver → Sender: ``{"answer": {"accept": true}}`` or
  ``{"answer": {"reject": "reason"}}``, then ``{"done": true}``

The offer carries a `kind` discriminator: "file", "directory", or "text".
Per-kind offer shapes:

- kind="file": transfer_id, filename, size, content_hash, chunk_size,
  app_version. Chunks stream over the dilation subchannel.
- kind="directory": transfer_id, dir_name, size (of the deterministic-zip
  byte stream), content_hash, chunk_size, num_files, num_bytes
  (uncompressed totals — advisory, for receiver UX), app_version.
  Same subchannel; receiver expands the stream after verification.
- kind="text": transfer_id, text (≤ MAX_TEXT_BYTES UTF-8 bytes), app_version.
  No subchannel — the offer IS the payload. The receiver prints it.

The offer DOES NOT carry chunk_hashes. Including them would leak the file
size to a Nostr-relay observer through ciphertext-length analysis. Instead,
chunk_hashes ride the dilation subchannel — peer-to-peer, never seen by a
relay. Likewise, `chunks_have` (resume) moves out of the answer onto the
subchannel reply.

Subchannel framing (file/directory; bulk):
    1. Sender → Receiver: length-prefixed JSON ``{"chunk_hashes": [...]}``.
       (4-byte big-endian length, then UTF-8 JSON bytes.)
    2. Receiver → Sender: length-prefixed JSON ``{"chunks_have": [...]}``.
       Empty list for fresh transfers; non-empty if resuming.
    3. Sender → Receiver: chunk frames for indices NOT in chunks_have.
       Frame: 4-byte BE chunk_index, 4-byte BE chunk_length, chunk_bytes.
       Frames may arrive in any order. The subchannel close signals
       "all frames sent."
    4. Receiver finalizes when ``chunks_have ∪ received == {0..N-1}``.
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
MAX_OFFER_SIZE = 1 << 40  # 1 TiB
MAX_CHUNK_COUNT = 1 << 20  # ~1M chunks (with 1 MiB chunks → 1 TiB)

# Filename length cap. POSIX `NAME_MAX` is 255 on most filesystems; some
# (HFS+, APFS) accept more but limit by codepoints not bytes. We enforce
# UTF-8 bytes ≤ 255 to be portable.
MAX_FILENAME_BYTES = 255

# Cap on inline text-mode payload. Text rides inside the wormhole control
# message (one app-message), not the bulk subchannel. 64 KiB is well under
# every reasonable framing limit and keeps memory bounded against a peer
# that crafts a hostile offer.
MAX_TEXT_BYTES = 1 << 16  # 64 KiB

# Cap on subchannel-header body length (length-prefixed JSON between
# sender and receiver before chunk frames). MAX_CHUNK_COUNT × 32-byte
# hashes × 4/3 base64 expansion + JSON overhead ≈ 32 MiB. A peer claiming
# a 4 GiB header is malicious — we refuse before allocating.
MAX_HEADER_BYTES = 64 * (1 << 20)  # 64 MiB ceiling, generous

# Offer kinds. New kinds get added here; parse_offer rejects anything else.
KIND_FILE = "file"
KIND_DIRECTORY = "directory"
KIND_TEXT = "text"
KNOWN_KINDS = frozenset({KIND_FILE, KIND_DIRECTORY, KIND_TEXT})

# Windows reserved device names (case-insensitive). On Windows these names
# refer to devices regardless of extension — `CON.txt` opens the console.
# We reject them on every platform so a takeit transfer can be moved to
# Windows without breakage.
_WINDOWS_RESERVED = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }
)


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
        raise ValueError(f"filename exceeds {MAX_FILENAME_BYTES} UTF-8 bytes")
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
            raise ValueError(f"unsafe filename: control character {c!r}")
        if 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
            raise ValueError(f"unsafe filename: Unicode bidi-override U+{cp:04X}")
    # Trailing dot or space: Windows silently strips → collision/overwrite.
    if fn.endswith(".") or fn.endswith(" "):
        raise ValueError(f"unsafe filename: trailing dot or space in {fn!r}")
    # Windows reserved device stems (CON, COM1, ..., regardless of extension).
    stem = fn.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED:
        raise ValueError(f"unsafe filename: Windows reserved name {fn!r}")
    # Unicode normalization mismatch — catches RTL override (U+202E) and
    # homoglyph confusables. The sender should send NFC; if the receiver
    # gets non-NFC, refuse rather than guess.
    if unicodedata.normalize("NFC", fn) != fn:
        raise ValueError(f"unsafe filename: not Unicode-normalized (NFC) {fn!r}")


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


def compute_transfer_id(kind, size, name, content_hash):
    """16-byte deterministic identifier, scoped by kind.

    Domain separation by kind ensures (file "x", directory "x") never collide.
    Text offers use compute_text_transfer_id (no size/hash inputs).
    """
    if kind not in KNOWN_KINDS:
        raise ValueError(f"unknown kind: {kind!r}")
    h = hashlib.blake2b(digest_size=TRANSFER_ID_BYTES)
    h.update(kind.encode("ascii"))
    h.update(b"|")
    h.update(struct.pack(">Q", size))
    h.update(b"|")
    h.update(name.encode("utf-8"))
    h.update(b"|")
    h.update(content_hash)
    return h.digest()


def compute_text_transfer_id(text):
    """16-byte deterministic id for a text offer (kind-scoped, no size/hash)."""
    h = hashlib.blake2b(digest_size=TRANSFER_ID_BYTES)
    h.update(b"text|")
    h.update(text.encode("utf-8"))
    return h.digest()


def _validate_chunked_offer(size, chunk_size):
    """Shared validation for file/directory offers (both stream chunked
    payloads). Post-HYP-392 chunk_hashes no longer ride the offer — only
    size/chunk_size are validated here."""
    if size < 0:
        raise ValueError(f"negative size: {size}")
    if size > MAX_OFFER_SIZE:
        raise ValueError(f"offer size {size} exceeds max {MAX_OFFER_SIZE}")
    if chunk_size <= 0:
        raise ValueError(f"non-positive chunk_size: {chunk_size}")


def build_offer_file(
    filename,
    size,
    content_hash,
    chunk_size=DEFAULT_CHUNK_SIZE,
    app_version="takeit/0.0.1",
):
    """Build a `kind="file"` offer.

    chunk_hashes are NOT part of the offer (HYP-392); they ride the
    dilation subchannel via build_subchannel_header so the relay can't
    infer file size from the offer's encrypted length.
    """
    _validate_filename(filename)
    _validate_chunked_offer(size, chunk_size)
    transfer_id = compute_transfer_id(KIND_FILE, size, filename, content_hash)
    return {
        "offer": {
            "kind": KIND_FILE,
            "transfer_id": base64.b64encode(transfer_id).decode("ascii"),
            "filename": filename,
            "size": size,
            "content_hash": base64.b64encode(content_hash).decode("ascii"),
            "chunk_size": chunk_size,
            "app_version": app_version,
        }
    }


def build_offer_directory(
    dir_name,
    size,
    content_hash,
    num_files,
    num_bytes,
    chunk_size=DEFAULT_CHUNK_SIZE,
    app_version="takeit/0.0.1",
):
    """Build a `kind="directory"` offer.

    `num_files` and `num_bytes` are advisory totals over the uncompressed
    source tree — the receiver shows them in the accept prompt. The
    deterministic-zip byte stream itself is described by `size` and
    `content_hash`; chunk_hashes ride the subchannel header (HYP-392).
    """
    _validate_filename(dir_name)  # same rules apply: NUL, traversal, length
    _validate_chunked_offer(size, chunk_size)
    if not isinstance(num_files, int) or num_files < 0:
        raise ValueError(f"num_files must be a non-negative int: {num_files!r}")
    if not isinstance(num_bytes, int) or num_bytes < 0:
        raise ValueError(f"num_bytes must be a non-negative int: {num_bytes!r}")
    transfer_id = compute_transfer_id(KIND_DIRECTORY, size, dir_name, content_hash)
    return {
        "offer": {
            "kind": KIND_DIRECTORY,
            "transfer_id": base64.b64encode(transfer_id).decode("ascii"),
            "dir_name": dir_name,
            "size": size,
            "content_hash": base64.b64encode(content_hash).decode("ascii"),
            "chunk_size": chunk_size,
            "num_files": num_files,
            "num_bytes": num_bytes,
            "app_version": app_version,
        }
    }


def build_offer_text(text, app_version="takeit/0.0.1"):
    """Build a `kind="text"` offer. The text rides inside the offer message
    itself; there's no chunked payload."""
    if not isinstance(text, str):
        raise ValueError(f"text must be str, got {type(text).__name__}")
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ValueError(f"text exceeds {MAX_TEXT_BYTES} UTF-8 bytes")
    transfer_id = compute_text_transfer_id(text)
    return {
        "offer": {
            "kind": KIND_TEXT,
            "transfer_id": base64.b64encode(transfer_id).decode("ascii"),
            "text": text,
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

    Dispatches on the `kind` field: file, directory, or text.
    Raises ProtocolError if the message is malformed or not an offer.
    """
    msg = _decode(payload)
    if not isinstance(msg, dict) or "offer" not in msg:
        raise ProtocolError("expected an 'offer' message")
    o = msg["offer"]
    if "kind" not in o:
        raise ProtocolError("offer missing 'kind'")
    kind = o["kind"]
    if kind not in KNOWN_KINDS:
        raise ProtocolError(f"unknown offer kind: {kind!r}")
    # Every kind carries transfer_id; decode once here.
    if "transfer_id" not in o:
        raise ProtocolError("offer missing 'transfer_id'")
    try:
        o["_transfer_id_bytes"] = base64.b64decode(o["transfer_id"])
    except Exception as e:
        raise ProtocolError(f"bad base64 in transfer_id: {e}")
    if len(o["_transfer_id_bytes"]) != TRANSFER_ID_BYTES:
        raise ProtocolError("transfer_id must be 16 bytes")
    if kind == KIND_FILE:
        _parse_chunked_offer(o, name_field="filename")
    elif kind == KIND_DIRECTORY:
        _parse_chunked_offer(o, name_field="dir_name")
        for field in ("num_files", "num_bytes"):
            if field not in o:
                raise ProtocolError(f"offer missing {field!r}")
            if not isinstance(o[field], int) or o[field] < 0:
                raise ProtocolError(f"{field} must be a non-negative int")
        # Reject filename on a directory offer to prevent wire confusion.
        if "filename" in o:
            raise ProtocolError(
                "directory offer must not carry 'filename'; use 'dir_name'"
            )
    elif kind == KIND_TEXT:
        if "text" not in o:
            raise ProtocolError("text offer missing 'text'")
        if not isinstance(o["text"], str):
            raise ProtocolError("text must be str")
        if len(o["text"].encode("utf-8")) > MAX_TEXT_BYTES:
            raise ProtocolError(f"text exceeds {MAX_TEXT_BYTES} UTF-8 bytes")
    return o


def _parse_chunked_offer(o, name_field):
    """Validate the shared chunked-stream fields for file and directory
    offers. `name_field` is "filename" for file offers and "dir_name" for
    directory offers; both have identical hardening.

    Post-HYP-392 the offer no longer carries chunk_hashes — those ride
    the dilation subchannel. A peer including chunk_hashes here is on a
    stale protocol; refuse rather than silently misinterpret.
    """
    if "chunk_hashes" in o:
        raise ProtocolError(
            "offer must not carry 'chunk_hashes' (moved to dilation subchannel)"
        )
    for field in (name_field, "size", "content_hash", "chunk_size"):
        if field not in o:
            raise ProtocolError(f"offer missing {field!r}")
    if not isinstance(o[name_field], str):
        raise ProtocolError(f"{name_field} must be str")
    try:
        _validate_filename(o[name_field])
    except ValueError as e:
        raise ProtocolError(str(e))
    if not isinstance(o["size"], int) or o["size"] < 0:
        raise ProtocolError("size must be a non-negative int")
    if o["size"] > MAX_OFFER_SIZE:
        raise ProtocolError(f"offer size {o['size']} exceeds max {MAX_OFFER_SIZE}")
    if not isinstance(o["chunk_size"], int) or o["chunk_size"] <= 0:
        raise ProtocolError("chunk_size must be a positive int")
    try:
        o["_content_hash_bytes"] = base64.b64decode(o["content_hash"])
    except Exception as e:
        raise ProtocolError(f"bad base64 in content_hash: {e}")
    if len(o["_content_hash_bytes"]) != 32:
        raise ProtocolError("content_hash must be 32 bytes (BLAKE2b-256)")


def build_answer(accept, reject_reason=None):
    """Receiver's response to the offer. Post-HYP-392 the answer is just
    accept/reject — chunks_have moved to the dilation-subchannel reply
    so the receiver has the chunk_hashes it needs to compute it."""
    if accept:
        return {"answer": {"accept": True}}
    return {"answer": {"reject": reject_reason or "rejected"}}


def parse_answer(payload):
    """Returns (accepted: bool, reason: str or None)."""
    msg = _decode(payload)
    if not isinstance(msg, dict) or "answer" not in msg:
        raise ProtocolError("expected an 'answer' message")
    a = msg["answer"]
    if a.get("accept") is True:
        return True, None
    if "reject" in a:
        return False, str(a["reject"])
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

    Bounds (HYP-409, audit #5): a peer that's already been accepted
    (post-SPAKE2) shouldn't be able to declare a 4 GiB frame and OOM us.
    The decoder caps each frame's declared length at `chunk_size`,
    refuses chunk indices `>= total_chunks`, and validates the last
    chunk's exact short length against `total_size` if given.
    """

    def __init__(self, chunk_size, total_chunks, total_size=None):
        if chunk_size <= 0:
            raise ValueError(f"chunk_size must be positive: {chunk_size}")
        if total_chunks < 0:
            raise ValueError(f"total_chunks must be >= 0: {total_chunks}")
        self._buf = bytearray()
        self._chunk_size = chunk_size
        self._total_chunks = total_chunks
        # Last-chunk exact length, derived from total_size if available.
        # When None, the last-chunk-length check degrades to "<= chunk_size"
        # rather than "exactly N", which is still a real cap (just
        # slightly looser).
        if total_size is None:
            self._last_chunk_length = None
        elif total_size == 0:
            self._last_chunk_length = 0  # zero-byte transfer; no chunks
        else:
            # last chunk's length = ((total_size - 1) % chunk_size) + 1.
            # This works even when total_size is a multiple of chunk_size
            # (gives chunk_size, the full-chunk case).
            self._last_chunk_length = ((total_size - 1) % chunk_size) + 1

    def feed(self, data: bytes):
        self._buf.extend(data)
        while True:
            if len(self._buf) < _FRAME_HDR.size:
                return
            chunk_index, length = _FRAME_HDR.unpack(bytes(self._buf[: _FRAME_HDR.size]))
            if length == 0:
                raise ProtocolError("zero-length chunk frame is invalid")
            if chunk_index >= self._total_chunks:
                raise ProtocolError(
                    f"chunk index {chunk_index} out of range "
                    f"(total_chunks={self._total_chunks})"
                )
            if length > self._chunk_size:
                raise ProtocolError(
                    f"declared chunk length {length} exceeds chunk_size "
                    f"{self._chunk_size}"
                )
            # Length-vs-position validation requires total_size. When
            # total_size is None (test/legacy mode) we only enforce the
            # `length <= chunk_size` cap above, which is still a real
            # OOM defense, just not a strict-equals check.
            if self._last_chunk_length is not None:
                is_last = chunk_index == self._total_chunks - 1
                if is_last:
                    if length != self._last_chunk_length:
                        raise ProtocolError(
                            f"last chunk length {length} != expected "
                            f"{self._last_chunk_length}"
                        )
                elif length != self._chunk_size:
                    raise ProtocolError(
                        f"non-last chunk length {length} != chunk_size "
                        f"{self._chunk_size}"
                    )
            total = _FRAME_HDR.size + length
            if len(self._buf) < total:
                return
            chunk = bytes(self._buf[_FRAME_HDR.size : total])
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
            chunk_hashes.append(hashlib.blake2b(buf, digest_size=32).digest())
    return size, h_all.digest(), chunk_hashes


def verify_chunk(chunk_bytes, expected_hash):
    """True if BLAKE2b-256(chunk_bytes) matches expected_hash exactly."""
    return hashlib.blake2b(chunk_bytes, digest_size=32).digest() == expected_hash


# --- subchannel framing (HYP-392) ---


# 4-byte big-endian length prefix for subchannel control messages.
_LEN_HDR = struct.Struct(">I")


def encode_length_prefixed(body):
    """Frame a body as `[4-byte BE length][body bytes]` for the
    dilation subchannel. Used for chunk_hashes header (sender→receiver)
    and chunks_have reply (receiver→sender) before chunk frames."""
    if len(body) > MAX_HEADER_BYTES:
        raise ValueError(f"body length {len(body)} exceeds max {MAX_HEADER_BYTES}")
    return _LEN_HDR.pack(len(body)) + body


class LengthPrefixedDecoder:
    """Buffer incremental subchannel bytes and yield complete bodies.

    Caps body length at MAX_HEADER_BYTES so a hostile peer claiming a
    4 GiB body can't make us preallocate. Empty (zero-length) bodies
    are rejected — every protocol message has content."""

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data):
        self._buf.extend(data)
        while True:
            if len(self._buf) < _LEN_HDR.size:
                return
            (length,) = _LEN_HDR.unpack(bytes(self._buf[: _LEN_HDR.size]))
            if length == 0:
                raise ProtocolError("zero-length subchannel message")
            if length > MAX_HEADER_BYTES:
                raise ProtocolError(
                    f"subchannel message length {length} exceeds max {MAX_HEADER_BYTES}"
                )
            total = _LEN_HDR.size + length
            if len(self._buf) < total:
                return
            body = bytes(self._buf[_LEN_HDR.size : total])
            del self._buf[:total]
            yield body


def build_subchannel_header(chunk_hashes):
    """Build the sender's subchannel header carrying chunk_hashes.
    Returns the length-prefixed bytes ready to write to the subchannel."""
    body = json.dumps(
        {
            "chunk_hashes": [base64.b64encode(h).decode("ascii") for h in chunk_hashes],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return encode_length_prefixed(body)


def parse_subchannel_header(payload):
    """Parse the receiver's view of the sender's subchannel header.
    Returns the list of 32-byte chunk-hash bytes."""
    msg = _decode(payload)
    if not isinstance(msg, dict) or "chunk_hashes" not in msg:
        raise ProtocolError("subchannel header missing 'chunk_hashes'")
    chunk_hashes_b64 = msg["chunk_hashes"]
    if not isinstance(chunk_hashes_b64, list):
        raise ProtocolError("chunk_hashes must be a list")
    if len(chunk_hashes_b64) > MAX_CHUNK_COUNT:
        raise ProtocolError(
            f"chunk_hashes count {len(chunk_hashes_b64)} exceeds max {MAX_CHUNK_COUNT}"
        )
    try:
        chunk_hashes = [base64.b64decode(h) for h in chunk_hashes_b64]
    except Exception as e:
        raise ProtocolError(f"bad base64 in chunk_hashes: {e}")
    for h in chunk_hashes:
        if len(h) != 32:
            raise ProtocolError("each chunk hash must be 32 bytes")
    return chunk_hashes


def build_chunks_have(chunks_have):
    """Build the receiver's subchannel reply listing already-have indices.
    Empty list for fresh transfers; the sender skips those indices."""
    body = json.dumps(
        {
            "chunks_have": sorted(chunks_have) if chunks_have else [],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return encode_length_prefixed(body)


def parse_chunks_have(payload):
    """Parse the sender's view of the receiver's chunks_have reply."""
    msg = _decode(payload)
    if not isinstance(msg, dict) or "chunks_have" not in msg:
        raise ProtocolError("subchannel reply missing 'chunks_have'")
    chunks_have = msg["chunks_have"]
    if not isinstance(chunks_have, list):
        raise ProtocolError("chunks_have must be a list")
    if not all(isinstance(i, int) and i >= 0 for i in chunks_have):
        raise ProtocolError("chunks_have must be a list of non-negative ints")
    return chunks_have

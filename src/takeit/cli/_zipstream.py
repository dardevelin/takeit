"""
Deterministic streaming zip for directory transfers.

Determinism is load-bearing: takeit's resume identifies a transfer by
``BLAKE2b(zip_stream)``. If the same source directory produced different
bytes across runs (different mtimes, different walk order, compression
quirks), the transfer_id would change and a partial would be discarded
on the receive side. We pin every wobble:

- File entries are sorted lexicographically (POSIX path order).
- Every entry's date_time is fixed at (1980, 1, 1, 0, 0, 0) — the zip
  format's epoch and the only value not subject to local-tz drift.
- compress_type is ZIP_STORED. Compressors are not byte-stable across
  zlib versions/levels; STORED is. Also faster.
- external_attr is fixed (0o600 for files, 0o755 | dir-bit for dirs).
- Symlinks are NOT followed across the source-root boundary; symlinks
  pointing within the root are dereferenced (the reader sees a normal
  file in the zip), matching wormhole's behavior.

The receive-side helper extract_zip_safely defends against the standard
"zip-slip" class of attacks by validating each entry's resolved path
falls under realpath(dest), and rejects symlink entries (which would
otherwise be a footgun for follow-up writes).

This module avoids the third-party `zipstream-ng` dependency. It does
not expose mtime override on its public API, and the underlying
`time.localtime()` default is timezone-dependent. The stdlib `zipfile`
module gives us full control via `ZipInfo.date_time=`.
"""
import hashlib
import io
import os
import stat
import zipfile

# Fixed mtime for every entry. (1980, 1, 1, 0, 0, 0) is the zip format's
# minimum valid date — earlier dates can't be encoded. We're not trying
# to convey any meaningful time; we're trying to convey "no information."
_FIXED_MTIME = (1980, 1, 1, 0, 0, 0)

# External-attr layouts. Upper 16 bits hold POSIX mode; lower 16 hold
# DOS attributes. We pin both so the zip is byte-identical regardless of
# what the source filesystem reports.
_EXTERNAL_ATTR_FILE = 0o600 << 16
_EXTERNAL_ATTR_DIR = (0o755 << 16) | 0x10  # MS-DOS directory bit

# Read buffer for streaming source files. 64 KiB amortizes syscalls
# without bloating peak memory; matches what `chunk_hashes_for_file`
# uses for whole-file hashing.
_READ_CHUNK = 1 << 16


def walk_directory(root):
    """Walk `root`, returning (sorted_file_paths, num_files, num_bytes).

    Sorting is lexicographic on POSIX-style relative paths. Symlinks
    are categorized:
    - Targets within `root` (after realpath) are followed and included.
    - Targets outside `root` are refused with ValueError. Silently
      following them would exfiltrate files the user didn't intend
      to include in the transfer.
    """
    root_real = os.path.realpath(root)
    if not os.path.isdir(root_real):
        raise ValueError(f"not a directory: {root!r}")
    files = []
    num_bytes = 0
    for dirpath, dirnames, filenames in os.walk(root_real, followlinks=False):
        # Sort in place so os.walk descends in deterministic order.
        dirnames.sort()
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            # If the entry is a symlink, ensure its target falls inside
            # the source root. Otherwise refuse — rather than silently
            # follow it (privacy risk) or silently drop it (surprising).
            if os.path.islink(full):
                target = os.path.realpath(full)
                # commonpath raises on different drives (Windows); we
                # use prefix-with-sep to be portable.
                if not (target == root_real or
                        target.startswith(root_real + os.sep)):
                    raise ValueError(
                        f"symlink {full!r} points outside the source "
                        f"directory ({target!r}); refusing")
            files.append(full)
            try:
                num_bytes += os.path.getsize(full)
            except OSError as e:
                raise ValueError(f"cannot stat {full!r}: {e}")
    return files, len(files), num_bytes


class _StreamSink(io.RawIOBase):
    """A write-only file-like that buffers `write()` calls into a list
    of byte chunks for a generator to drain.

    `zipfile.ZipFile` calls `write()` on its underlying file object and
    `tell()` to record entry offsets in the central directory. The sink
    accepts both; chunks are drained between zip operations so the
    generator can yield them upstream without the whole archive ever
    sitting in memory.
    """

    def __init__(self):
        self._pos = 0
        self.chunks = []

    def writable(self):
        return True

    def write(self, b):
        # ZipFile passes both bytes and memoryview; normalize.
        if not isinstance(b, (bytes, bytearray)):
            b = bytes(b)
        self.chunks.append(bytes(b))
        n = len(b)
        self._pos += n
        return n

    def tell(self):
        return self._pos

    def flush(self):
        pass

    def drain(self):
        """Yield buffered chunks and clear the buffer."""
        while self.chunks:
            yield self.chunks.pop(0)


def deterministic_directory_zip(root):
    """Yield a byte-stable zip of `root` chunk-by-chunk.

    The total stream is byte-identical for any two runs over the same
    logical input (same names, same contents, same structure), regardless
    of on-disk mtime or filesystem permission noise. transfer_id derived
    from BLAKE2b over this stream is therefore stable across runs.

    Errors during walking (out-of-root symlinks, unreadable entries) are
    raised before any bytes are yielded.
    """
    files, _num_files, _num_bytes = walk_directory(root)
    root_real = os.path.realpath(root)
    sink = _StreamSink()
    # allowZip64=True: future-proof against >4 GiB directories without
    # changing the wire format.
    zf = zipfile.ZipFile(sink, "w", allowZip64=True)
    try:
        for full in files:
            rel = os.path.relpath(full, root_real)
            # Zip entry names are always forward-slash, regardless of OS.
            arcname = rel.replace(os.sep, "/")
            zinfo = zipfile.ZipInfo(arcname, date_time=_FIXED_MTIME)
            zinfo.compress_type = zipfile.ZIP_STORED
            zinfo.external_attr = _EXTERNAL_ATTR_FILE
            with open(full, "rb") as src:
                with zf.open(zinfo, "w") as dst:
                    while True:
                        buf = src.read(_READ_CHUNK)
                        if not buf:
                            break
                        dst.write(buf)
                        yield from sink.drain()
            yield from sink.drain()
    finally:
        zf.close()
    yield from sink.drain()


def materialize_and_hash(root, out_path, chunk_size):
    """Stream `root` through deterministic_directory_zip, writing the
    bytes to `out_path` AND computing the per-chunk + whole-stream
    BLAKE2b-256 hashes in a single pass.

    Returns (size, content_hash, chunk_hashes).

    This is the sender's prepare step for a directory transfer: rather
    than hash twice (once for the offer, once during transfer), we
    materialize the zip once and re-use the resulting file for the
    chunked-stream send. The temp-file cost is unavoidable for byte-
    indexed resume — chunk-index → byte-offset only works if the
    sender can seek into the stream.
    """
    h_all = hashlib.blake2b(digest_size=32)
    chunk_hashes = []
    size = 0
    pending = bytearray()
    with open(out_path, "wb") as out:
        for piece in deterministic_directory_zip(root):
            out.write(piece)
            h_all.update(piece)
            size += len(piece)
            pending.extend(piece)
            # Drain full chunks from `pending` into chunk_hashes. The
            # generator's pieces are not chunk-aligned, so we accumulate.
            while len(pending) >= chunk_size:
                chunk = bytes(pending[:chunk_size])
                chunk_hashes.append(
                    hashlib.blake2b(chunk, digest_size=32).digest())
                del pending[:chunk_size]
        # Flush the trailing partial chunk (if any).
        if pending:
            chunk_hashes.append(
                hashlib.blake2b(bytes(pending), digest_size=32).digest())
    return size, h_all.digest(), chunk_hashes


def extract_zip_safely(blob_or_file, dest):
    """Extract a zip blob/file into `dest`, defending against zip-slip
    and symlink footguns.

    `blob_or_file` may be bytes, a BytesIO, or any seekable file-like.
    `dest` must already exist and be a directory; entries are extracted
    into it. Subdirectories are created as needed.

    Defenses:
    - Each entry's filename is resolved against `realpath(dest)`; if
      the resolved path doesn't fall within dest, the extract is
      aborted with ValueError before any disk write happens.
    - Symlink entries (POSIX mode 0xA000) are refused — a malicious
      sender could otherwise plant a symlink to an attacker-chosen
      target, then a benign-looking subsequent file write through the
      symlink would overwrite the target.
    - Absolute paths inside the zip are refused early (a stricter form
      of the zip-slip check; matches the user's mental model of "this
      should land inside dest").
    """
    if isinstance(blob_or_file, (bytes, bytearray)):
        blob_or_file = io.BytesIO(blob_or_file)
    dest_real = os.path.realpath(dest)
    if not os.path.isdir(dest_real):
        raise ValueError(f"destination is not a directory: {dest!r}")
    with zipfile.ZipFile(blob_or_file) as zf:
        # Validate ALL entries before extracting any — partial extracts
        # on a malicious zip would leave the user with attacker-chosen
        # file fragments on disk.
        for zinfo in zf.infolist():
            _validate_zinfo(zinfo, dest_real)
        for zinfo in zf.infolist():
            target = os.path.join(dest_real, zinfo.filename)
            if zinfo.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(zinfo) as src, open(target, "wb") as dst:
                while True:
                    buf = src.read(_READ_CHUNK)
                    if not buf:
                        break
                    dst.write(buf)


def _validate_zinfo(zinfo, dest_real):
    """Reject zip-slip, absolute paths, and symlink entries."""
    name = zinfo.filename
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        # Unix absolute or Windows drive-prefixed
        raise ValueError(
            f"absolute path in zip entry: {name!r} (zip-slip attempt)")
    # Resolve where the entry would land and ensure it's under dest.
    target = os.path.realpath(os.path.join(dest_real, name))
    if not (target == dest_real or
            target.startswith(dest_real + os.sep)):
        raise ValueError(
            f"zip entry escapes destination (zip-slip): {name!r}")
    # Reject symlink entries. The POSIX mode lives in the upper 16 bits
    # of external_attr; S_IFLNK == 0xA000.
    upper = zinfo.external_attr >> 16
    if stat.S_ISLNK(upper):
        raise ValueError(
            f"zip entry encodes a symlink ({name!r}); refusing")

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
- external_attr is fixed (0o600 for files, 0o700 | dir-bit for dirs).
- Symlinks are refused. This avoids exfiltrating out-of-tree files and
  closes the validate-then-open race where a symlink target changes after
  the directory walk.

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
import sys
import zipfile

# Fixed mtime for every entry. (1980, 1, 1, 0, 0, 0) is the zip format's
# minimum valid date — earlier dates can't be encoded. We're not trying
# to convey any meaningful time; we're trying to convey "no information."
_FIXED_MTIME = (1980, 1, 1, 0, 0, 0)

# External-attr layouts. Upper 16 bits hold POSIX mode; lower 16 hold
# DOS attributes. We pin both so the zip is byte-identical regardless of
# what the source filesystem reports.
_EXTERNAL_ATTR_FILE = 0o600 << 16
_EXTERNAL_ATTR_DIR = (0o700 << 16) | 0x10  # MS-DOS directory bit

# Read buffer for streaming source files. 64 KiB amortizes syscalls
# without bloating peak memory; matches what `chunk_hashes_for_file`
# uses for whole-file hashing.
_READ_CHUNK = 1 << 16


def walk_directory(root, *, ignore_unsendable=False):
    """Walk `root`, returning (sorted_file_paths, num_files, num_bytes).

    Sorting is lexicographic on POSIX-style relative paths. Symlinks are
    refused even when they point inside `root`: the zip writer must reopen
    files later, and following symlinks would leave a validate-then-open
    TOCTOU window. This refusal is NOT optional — `ignore_unsendable=True`
    does NOT relax it (symlinks are a privacy/race concern, not a routine
    IO/permission concern).

    `ignore_unsendable=True`: when an entry can't be stat'd
    (PermissionError, FileNotFoundError on race, etc.), skip it with
    a stderr warning instead of raising. Use for trees that contain
    routinely-unreadable noise (e.g. `.git/objects/` owned by another
    UID, mounted volumes that disappear).
    """
    root_real = os.path.realpath(root)
    if not os.path.isdir(root_real):
        raise ValueError(f"not a directory: {root!r}")
    files = []
    num_bytes = 0
    for dirpath, dirnames, filenames in os.walk(root_real, followlinks=False):
        # Sort in place so os.walk descends in deterministic order.
        dirnames.sort()
        for dn in list(dirnames):
            full = os.path.join(dirpath, dn)
            if os.path.islink(full):
                raise ValueError(f"symlink {full!r}; refusing")
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                raise ValueError(f"symlink {full!r}; refusing")
            try:
                st = os.lstat(full)
            except OSError as e:
                if ignore_unsendable:
                    # Print to stderr; keep this module click-free so
                    # it stays importable from non-CLI code.
                    print(
                        f"Skipping unreadable entry: {full!r} ({e})",
                        file=sys.stderr,
                    )
                    continue
                raise ValueError(f"cannot stat {full!r}: {e}")
            if not stat.S_ISREG(st.st_mode):
                if ignore_unsendable:
                    print(
                        f"Skipping non-regular entry: {full!r}",
                        file=sys.stderr,
                    )
                    continue
                raise ValueError(f"not a regular file: {full!r}")
            files.append(full)
            num_bytes += st.st_size
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


def deterministic_directory_zip(root, *, ignore_unsendable=False):
    """Yield a byte-stable zip of `root` chunk-by-chunk.

    The total stream is byte-identical for any two runs over the same
    logical input (same names, same contents, same structure), regardless
    of on-disk mtime or filesystem permission noise. transfer_id derived
    from BLAKE2b over this stream is therefore stable across runs.

    Errors during walking (symlinks, unreadable entries) are
    raised before any bytes are yielded — unless `ignore_unsendable=True`,
    which skips IO-failing entries with a stderr warning (privacy-failing
    symlinks still hard-refuse).
    """
    files, _num_files, _num_bytes = walk_directory(
        root, ignore_unsendable=ignore_unsendable
    )
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
            fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError(f"not a regular file: {full!r}")
                src = os.fdopen(fd, "rb")
                fd = None
                with src:
                    with zf.open(zinfo, "w") as dst:
                        while True:
                            buf = src.read(_READ_CHUNK)
                            if not buf:
                                break
                            dst.write(buf)
                            yield from sink.drain()
            finally:
                if fd is not None:
                    os.close(fd)
            yield from sink.drain()
    finally:
        zf.close()
    yield from sink.drain()


def materialize_and_hash(root, out_path, chunk_size, *, ignore_unsendable=False):
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

    `ignore_unsendable=True` is forwarded to the underlying walk; see
    `walk_directory` for semantics.
    """
    h_all = hashlib.blake2b(digest_size=32)
    chunk_hashes = []
    size = 0
    pending = bytearray()
    # O_CREAT|O_EXCL|O_NOFOLLOW + 0o600: refuse if the path exists
    # (defeats pre-creation race), refuse if it IS a symlink (defeats
    # symlink-to-target tricks), and pin 0o600 mode regardless of
    # umask (no world-readable confidentiality window). HYP-407,
    # audit #3.
    fd = os.open(
        out_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(fd, "wb") as out:
        for piece in deterministic_directory_zip(
            root, ignore_unsendable=ignore_unsendable
        ):
            out.write(piece)
            h_all.update(piece)
            size += len(piece)
            pending.extend(piece)
            # Drain full chunks from `pending` into chunk_hashes. The
            # generator's pieces are not chunk-aligned, so we accumulate.
            while len(pending) >= chunk_size:
                chunk = bytes(pending[:chunk_size])
                chunk_hashes.append(hashlib.blake2b(chunk, digest_size=32).digest())
                del pending[:chunk_size]
        # Flush the trailing partial chunk (if any).
        if pending:
            chunk_hashes.append(
                hashlib.blake2b(bytes(pending), digest_size=32).digest()
            )
    return size, h_all.digest(), chunk_hashes


def extract_zip_safely(blob_or_file, dest, *, num_files=None, num_bytes=None):
    """Extract a zip blob/file into `dest`, defending against zip-slip,
    symlink footguns, and zip-bomb attempts.

    `blob_or_file` may be bytes, a BytesIO, or any seekable file-like.
    `dest` must already exist and be a directory; entries are extracted
    into it. Subdirectories are created as needed.

    `num_files` / `num_bytes` (HYP-438): if both are passed, they MUST
    equal the central directory's totals (file-entry count and the sum
    of `file_size` across non-directory entries). Mismatch raises
    before any write. Receiver call sites pass these from the offer to
    promote them from advisory-UX to enforced-bound. Library callers
    that don't have an offer can omit them; the format invariants
    below still fire.

    Format invariants always enforced (HYP-438), independent of the
    totals kwargs:
    - Every entry's `compress_type` must be `ZIP_STORED`. Takeit-
      issued archives are STORED-only by spec; a DEFLATED entry on
      the wire is either a sender bug or a zip-bomb attempt (small
      compressed offer, hash matches, expands large during read).
    - For STORED entries, `compress_size` must equal `file_size`. A
      mismatch is corrupt or forged; the central directory's
      `file_size` is what bounds the read.

    Defenses (existing):
    - Each entry's filename is resolved against `realpath(dest)`; if
      the resolved path doesn't fall within dest, the extract is
      aborted with ValueError before any disk write happens.
    - Symlink entries (POSIX mode 0xA000) are refused — a malicious
      sender could otherwise plant a symlink to an attacker-chosen
      target, then a benign-looking subsequent file write through the
      symlink would overwrite the target.
    - Existing targets are refused, including dangling symlinks.
    - Extracted directories are mode 0700 and files are mode 0600.
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
        targets = set()
        entries = []
        cd_file_count = 0
        cd_byte_total = 0
        for zinfo in zf.infolist():
            # HYP-438: format invariants. Run before path/symlink
            # validation because a wrong compress_type is a stronger
            # rejection signal than a path issue (the latter could be
            # ambiguous across OSes; this is a flat protocol violation).
            if zinfo.compress_type != zipfile.ZIP_STORED:
                raise ValueError(
                    f"zip entry uses non-stored compression "
                    f"({zinfo.filename!r}, compress_type="
                    f"{zinfo.compress_type}); takeit archives are "
                    f"ZIP_STORED-only"
                )
            if not zinfo.is_dir() and zinfo.compress_size != zinfo.file_size:
                raise ValueError(
                    f"stored zip entry has compress_size "
                    f"{zinfo.compress_size} != file_size "
                    f"{zinfo.file_size} ({zinfo.filename!r})"
                )
            target = _validate_zinfo(zinfo, dest_real)
            if target in targets:
                raise ValueError(f"duplicate zip entry target: {zinfo.filename!r}")
            for prior_target, prior_is_dir in entries:
                if target.startswith(prior_target + os.sep) and not prior_is_dir:
                    raise ValueError(
                        f"zip entry descends through file target: {zinfo.filename!r}"
                    )
                if prior_target.startswith(target + os.sep) and not zinfo.is_dir():
                    raise ValueError(
                        f"zip entry conflicts with child target: {zinfo.filename!r}"
                    )
            targets.add(target)
            entries.append((target, zinfo.is_dir()))
            if os.path.lexists(target):
                raise ValueError(
                    f"zip entry target already exists ({zinfo.filename!r}); refusing"
                )
            if not zinfo.is_dir():
                cd_file_count += 1
                cd_byte_total += zinfo.file_size

        # HYP-438: enforce offer-stated totals against the central
        # directory. Mirrors the consent prompt the user already saw
        # ("12 files, 4 MiB"); a sender lying here would expand the
        # transfer past what the user agreed to.
        if num_files is not None and cd_file_count != num_files:
            raise ValueError(
                f"zip num_files mismatch: central directory has "
                f"{cd_file_count}, offer claimed {num_files}"
            )
        if num_bytes is not None and cd_byte_total != num_bytes:
            raise ValueError(
                f"zip num_bytes mismatch: central directory totals "
                f"{cd_byte_total}, offer claimed {num_bytes}"
            )
        for zinfo in zf.infolist():
            target = _safe_target_path(zinfo.filename, dest_real)
            if zinfo.is_dir():
                _makedirs_private(target, dest_real)
                continue
            _makedirs_private(os.path.dirname(target), dest_real)
            fd = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as dst:
                    fd = None
                    with zf.open(zinfo) as src:
                        while True:
                            buf = src.read(_READ_CHUNK)
                            if not buf:
                                break
                            dst.write(buf)
            except Exception:
                if fd is not None:
                    os.close(fd)
                raise


def _validate_zinfo(zinfo, dest_real):
    """Reject zip-slip, absolute paths, and symlink entries."""
    name = zinfo.filename
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        # Unix absolute or Windows drive-prefixed
        raise ValueError(f"absolute path in zip entry: {name!r} (zip-slip attempt)")
    target = _safe_target_path(name, dest_real)
    symlink_component = _first_symlink_component(target, dest_real)
    if symlink_component is not None:
        raise ValueError(
            f"zip entry crosses existing symlink {symlink_component!r}; refusing"
        )
    real_target = os.path.realpath(target)
    if not (real_target == dest_real or real_target.startswith(dest_real + os.sep)):
        raise ValueError(f"zip entry escapes destination (zip-slip): {name!r}")
    # Reject symlink entries. The POSIX mode lives in the upper 16 bits
    # of external_attr; S_IFLNK == 0xA000.
    upper = zinfo.external_attr >> 16
    if stat.S_ISLNK(upper):
        raise ValueError(f"zip entry encodes a symlink ({name!r}); refusing")
    return target


def _safe_target_path(name, dest_real):
    return os.path.normpath(os.path.join(dest_real, name))


def _first_symlink_component(path, dest_real):
    rel = os.path.relpath(path, dest_real)
    cur = dest_real
    for part in rel.split(os.sep):
        if not part or part == ".":
            continue
        cur = os.path.join(cur, part)
        if os.path.islink(cur):
            return cur
    return None


def _makedirs_private(path, dest_real):
    if path == dest_real:
        return
    os.makedirs(path, mode=0o700, exist_ok=True)
    cur = dest_real
    rel = os.path.relpath(path, dest_real)
    for part in rel.split(os.sep):
        if not part or part == ".":
            continue
        cur = os.path.join(cur, part)
        if cur != dest_real:
            os.chmod(cur, 0o700)

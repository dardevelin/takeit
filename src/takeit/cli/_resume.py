"""
Sidecar files for resumable takeit transfers.

Two files per in-flight transfer (receiver-side):
    <filename>.takeit-partial         raw bytes, sparse-written by chunk index
    <filename>.takeit-partial.meta    JSON sidecar (transfer_id, chunk_size,
                                      chunk_hashes, chunks_have, size)

One file per recently-sent file (sender-side):
    <filename>.takeit-sent.meta       JSON cache of (size, mtime_ns, inode,
                                      chunk_size, content_hash, chunk_hashes)
                                      so a re-send doesn't recompute hashes
                                      from scratch when the file is unchanged.

All paths use ``os.replace`` for atomic rename of the meta file (writes go
to ``<meta>.tmp`` first), so a crash mid-write never leaves a corrupt JSON
parse failure.
"""

import base64
import hashlib
import json
import os
import time

# Filename suffixes — kept here so callers don't pun strings.
PARTIAL_SUFFIX = ".takeit-partial"
META_SUFFIX = ".takeit-partial.meta"
SENT_META_SUFFIX = ".takeit-sent.meta"


def _atomic_write_json(target_path, payload):
    """HYP-436: write `payload` (JSON-serializable) to `target_path`
    atomically via a `.tmp` file, hardened against symlink swaps and
    permissive umasks. The pattern mirrors HYP-407's sender-zip
    hardening:

    - O_EXCL refuses to overwrite a pre-existing tmp (which a local
      attacker could have laid there as a symlink to a victim path).
    - O_NOFOLLOW refuses to traverse a tmp that's a symlink (defense
      in depth alongside O_EXCL).
    - 0o600 bypasses the user's umask so the sidecar isn't
      world-readable. Sidecars carry chunk_hashes (BLAKE2b digests of
      file chunks) which fingerprint the file content; not secret per
      se but unnecessary to leak.

    On failure, the partial tmp is unlinked so a stale .tmp doesn't
    block future writes (subsequent O_EXCL would fail). os.replace is
    atomic on POSIX and Windows, so a crash between fsync and replace
    leaves the prior sidecar intact."""
    tmp = target_path + ".tmp"
    fd = os.open(
        tmp,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    os.replace(tmp, target_path)


# ---- receiver-side sidecar ----


def receiver_paths(dest_path):
    """Returns (partial_path, meta_path) for a destination file."""
    return dest_path + PARTIAL_SUFFIX, dest_path + META_SUFFIX


def load_receiver_state(meta_path):
    """Load and lightly validate a receiver sidecar. Returns the dict, or
    None if the file is absent or unreadable.

    Returning None on JSON-parse error is intentional: a corrupt sidecar
    means we can't trust any partial bytes either, so the caller should
    treat it as "no resume possible" and start fresh.
    """
    if not os.path.exists(meta_path):
        return None
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    for key in ("transfer_id", "chunk_size", "size", "chunk_hashes", "chunks_have"):
        if key not in data:
            return None
    return data


def save_receiver_state(
    meta_path, transfer_id_b64, size, chunk_size, chunk_hashes_b64, chunks_have
):
    """Write receiver sidecar atomically and hardened (O_EXCL|O_NOFOLLOW
    + 0o600). See `_atomic_write_json` for rationale."""
    payload = {
        "transfer_id": transfer_id_b64,
        "size": size,
        "chunk_size": chunk_size,
        "chunk_hashes": chunk_hashes_b64,
        "chunks_have": sorted(set(chunks_have)),
    }
    _atomic_write_json(meta_path, payload)


def can_resume_with(
    state, offer_transfer_id_b64, offer_size, offer_chunk_size, offer_chunk_hashes_b64
):
    """Can we resume from this sidecar given a fresh offer?

    Resumability requires the *exact* same transfer: matching transfer_id,
    matching size, matching chunk_size, matching per-chunk hashes. Any
    mismatch means the sender's file has changed (or it's a different file
    entirely) and we must NOT concatenate old and new bytes.
    """
    if state.get("transfer_id") != offer_transfer_id_b64:
        return False
    if state.get("size") != offer_size:
        return False
    if state.get("chunk_size") != offer_chunk_size:
        return False
    if state.get("chunk_hashes") != offer_chunk_hashes_b64:
        return False
    return True


def cleanup_receiver(partial_path, meta_path):
    """Remove the partial+meta pair after successful finalize or abort."""
    for path in (partial_path, meta_path):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


# ---- sender-side cache ----


def sender_cache_path(source_path):
    return source_path + SENT_META_SUFFIX


def load_sender_cache(cache_path, source_path):
    """Load a sender-side cache, returning the dict only if `source_path`
    looks unchanged (size + mtime_ns + inode all match). Otherwise None.

    The (size, mtime, inode) triple is conservative: if the file was
    edited, it almost certainly has a different mtime. If it was renamed
    over (atomic replace), inode changes. Both invalidate the cache.
    """
    if not os.path.exists(cache_path):
        return None
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        st = os.stat(source_path)
    except OSError:
        return None
    if data.get("size") != st.st_size:
        return None
    if data.get("mtime_ns") != st.st_mtime_ns:
        return None
    if data.get("inode") != st.st_ino:
        return None
    for key in ("chunk_size", "content_hash", "chunk_hashes"):
        if key not in data:
            return None
    return data


def save_sender_cache(
    cache_path, source_path, chunk_size, content_hash_b64, chunk_hashes_b64
):
    """Write sender cache atomically and hardened (O_EXCL|O_NOFOLLOW
    + 0o600), stamped with the file's stat. See `_atomic_write_json`
    for rationale.

    The cache is best-effort: if `_atomic_write_json` raises (e.g.
    a stale .tmp from a prior crash, or a hostile pre-created
    symlink), we swallow and skip rather than fail the parent
    command. The user re-hashes the file next time."""
    try:
        st = os.stat(source_path)
    except OSError:
        return
    payload = {
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "inode": st.st_ino,
        "chunk_size": chunk_size,
        "content_hash": content_hash_b64,
        "chunk_hashes": chunk_hashes_b64,
    }
    try:
        _atomic_write_json(cache_path, payload)
    except OSError:
        # Sidecar write failures are non-fatal — re-hash next run.
        return


# ---- helpers ----


def b64(b):
    return base64.b64encode(b).decode("ascii")


def b64d(s):
    return base64.b64decode(s)


# ---- A5: verify resume bytes against chunk_hashes ----


def verify_chunks_have(
    partial_path, total_size, chunk_size, chunk_hashes_bytes, claimed_chunks_have
):
    """Re-hash each claimed chunk index from disk and return verified set.

    A same-user attacker can pre-stage a malicious sidecar whose
    ``chunks_have`` claims indices the receiver hasn't actually got. The
    sidecar's ``transfer_id`` is deterministic (BLAKE2b of size, name,
    content_hash — all knowable to anyone with the file), so the cheap
    sidecar check ``can_resume_with`` cannot detect a forgery. The
    receiver MUST re-hash each claimed chunk from disk against the
    offer's ``chunk_hashes`` before telling the sender to skip them.

    Indices outside ``range(len(chunk_hashes_bytes))`` are silently
    dropped. Indices whose on-disk bytes don't hash to the expected
    value are silently dropped — the sender will re-send them.
    Returns a ``set[int]`` of indices that verified.

    If ``partial_path`` doesn't exist, returns the empty set — the
    caller should treat this as "no resume possible, start fresh."
    """
    if not os.path.exists(partial_path):
        return set()
    n_chunks = len(chunk_hashes_bytes)
    verified = set()
    try:
        with open(partial_path, "rb") as f:
            for idx in claimed_chunks_have:
                if idx < 0 or idx >= n_chunks:
                    continue  # sender bug or attacker; drop silently
                # Last chunk may be short.
                start = idx * chunk_size
                end = min(start + chunk_size, total_size)
                expected_len = end - start
                f.seek(start)
                data = f.read(expected_len)
                if len(data) != expected_len:
                    continue  # truncated partial; drop
                if (
                    hashlib.blake2b(data, digest_size=32).digest()
                    == chunk_hashes_bytes[idx]
                ):
                    verified.add(idx)
    except OSError:
        return set()
    return verified


# ---- B4: orphan .tmp cleanup ----


def cleanup_orphan_tmp_files(directory):
    """Remove ``*.takeit-partial.meta.tmp`` orphans in ``directory``.

    `save_receiver_state` writes a `.tmp` then `os.replace`s it. If the
    process dies between, the `.tmp` leaks forever. This is a best-
    effort sweep to call on receive startup; never raises.
    """
    try:
        entries = list(os.scandir(directory))
    except (OSError, NotADirectoryError):
        return
    for entry in entries:
        if entry.name.endswith(".takeit-partial.meta.tmp"):
            try:
                os.unlink(entry.path)
            except OSError:
                pass


# ---- A3: receiver-state throttle ----


class ReceiverStateThrottle:
    """Throttles sidecar persistence to bound write amplification.

    The immutable parts of the receiver state (transfer_id, size,
    chunk_size, chunk_hashes) are written ONCE on `initialize()`. The
    mutable `chunks_have` set is persisted at most every ``interval``
    seconds; intermediate updates are buffered in memory. `flush()`
    forces a write regardless of throttle and should be called on
    connectionLost.

    Trade-off: a process kill between throttled writes loses up to
    ``interval`` seconds of `chunks_have` updates — those chunks will be
    re-requested on resume. Acceptable: every chunk is hash-verified
    anyway, so re-receiving is bandwidth waste, not correctness loss.

    Without this, the receiver fsync's after every chunk: for a 10 GB
    file at 1 MiB chunks, that's 10,240 atomic-rename'd JSON writes,
    each of which re-serializes the full chunk_hashes list (~320 KiB).
    Total: ~320 MB of redundant disk writes plus 10K fsyncs.
    """

    def __init__(
        self,
        meta_path,
        transfer_id_b64,
        size,
        chunk_size,
        chunk_hashes_b64,
        interval=2.0,
        clock=None,
    ):
        self._meta_path = meta_path
        self._transfer_id_b64 = transfer_id_b64
        self._size = size
        self._chunk_size = chunk_size
        self._chunk_hashes_b64 = chunk_hashes_b64
        self._interval = interval
        self._clock = clock or time.monotonic
        self._last_write = None
        self._latest_chunks_have = None

    def initialize(self, chunks_have):
        """Force-write the initial state. Call once on receive start."""
        self._latest_chunks_have = set(chunks_have)
        self._write_now()

    def update(self, chunks_have):
        """Update chunks_have. Writes through if `interval` elapsed since
        the last write; otherwise records the new value to flush later.
        """
        self._latest_chunks_have = set(chunks_have)
        if self._last_write is None:
            self._write_now()
            return
        if self._clock() - self._last_write >= self._interval:
            self._write_now()

    def flush(self):
        """Force-write the latest chunks_have, regardless of interval.
        Call on connectionLost."""
        if self._latest_chunks_have is not None:
            self._write_now()

    def _write_now(self):
        save_receiver_state(
            self._meta_path,
            transfer_id_b64=self._transfer_id_b64,
            size=self._size,
            chunk_size=self._chunk_size,
            chunk_hashes_b64=self._chunk_hashes_b64,
            chunks_have=self._latest_chunks_have or set(),
        )
        self._last_write = self._clock()

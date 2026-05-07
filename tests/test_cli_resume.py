"""
Tests for the resume sidecar module.
"""
import hashlib
import json
import os

import pytest

from takeit.cli._resume import (
    META_SUFFIX, PARTIAL_SUFFIX, ReceiverStateThrottle, SENT_META_SUFFIX,
    b64, can_resume_with, cleanup_orphan_tmp_files, cleanup_receiver,
    load_receiver_state, load_sender_cache, receiver_paths,
    save_receiver_state, save_sender_cache, sender_cache_path,
    verify_chunks_have,
)


# --- path helpers ---


def test_receiver_paths_appends_suffixes():
    p, m = receiver_paths("/tmp/foo.bin")
    assert p == "/tmp/foo.bin" + PARTIAL_SUFFIX
    assert m == "/tmp/foo.bin" + META_SUFFIX


def test_sender_cache_path_appends_suffix():
    assert sender_cache_path("/tmp/x.bin") == "/tmp/x.bin" + SENT_META_SUFFIX


# --- receiver-side sidecar ---


def test_save_then_load_round_trips(tmp_path):
    meta_path = str(tmp_path / "f.meta")
    save_receiver_state(
        meta_path,
        transfer_id_b64="dGlk",
        size=100,
        chunk_size=50,
        chunk_hashes_b64=["aGFzaDA=", "aGFzaDE="],
        chunks_have=[0])
    state = load_receiver_state(meta_path)
    assert state["transfer_id"] == "dGlk"
    assert state["size"] == 100
    assert state["chunk_size"] == 50
    assert state["chunk_hashes"] == ["aGFzaDA=", "aGFzaDE="]
    assert state["chunks_have"] == [0]


def test_load_returns_none_on_missing_file(tmp_path):
    assert load_receiver_state(str(tmp_path / "absent.meta")) is None


def test_load_returns_none_on_corrupt_json(tmp_path):
    """A corrupt sidecar is treated as 'no resume' rather than crashing.

    This is a deliberate trade-off: a power loss mid-write could in theory
    leave a partial JSON, and we'd rather start fresh than refuse the
    transfer. The atomic-rename pattern (write to .tmp, then os.replace)
    is the primary defense; this is just belt-and-suspenders.
    """
    p = str(tmp_path / "f.meta")
    with open(p, "w") as f:
        f.write("not json{")
    assert load_receiver_state(p) is None


def test_load_returns_none_on_missing_required_keys(tmp_path):
    """A sidecar from an older protocol or a malicious one must be
    rejected, not partially trusted."""
    p = str(tmp_path / "f.meta")
    with open(p, "w") as f:
        json.dump({"transfer_id": "x"}, f)  # missing fields
    assert load_receiver_state(p) is None


def test_save_uses_atomic_rename(tmp_path):
    """If the rename step fails, the destination file shouldn't exist."""
    meta_path = str(tmp_path / "f.meta")
    save_receiver_state(meta_path, "tid", 10, 5, ["h0", "h1"], [0])
    # Verify the .tmp scratch file isn't left behind
    assert not os.path.exists(meta_path + ".tmp")
    assert os.path.exists(meta_path)


def test_chunks_have_is_deduped_and_sorted(tmp_path):
    meta_path = str(tmp_path / "f.meta")
    save_receiver_state(meta_path, "tid", 10, 5, ["h0", "h1"], [1, 0, 1, 0])
    state = load_receiver_state(meta_path)
    assert state["chunks_have"] == [0, 1]


# --- can_resume_with ---


def _state(transfer_id="tid", size=100, chunk_size=50,
           chunk_hashes=("h0", "h1"), chunks_have=(0,)):
    return {
        "transfer_id": transfer_id, "size": size, "chunk_size": chunk_size,
        "chunk_hashes": list(chunk_hashes), "chunks_have": list(chunks_have),
    }


def test_can_resume_when_all_match():
    s = _state()
    assert can_resume_with(s, "tid", 100, 50, ["h0", "h1"]) is True


def test_cannot_resume_when_transfer_id_differs():
    s = _state()
    assert can_resume_with(s, "OTHER", 100, 50, ["h0", "h1"]) is False


def test_cannot_resume_when_size_differs():
    s = _state()
    assert can_resume_with(s, "tid", 200, 50, ["h0", "h1"]) is False


def test_cannot_resume_when_chunk_size_differs():
    s = _state()
    assert can_resume_with(s, "tid", 100, 100, ["h0", "h1"]) is False


def test_cannot_resume_when_chunk_hashes_differ():
    """Most important rejection — file content changed since we last
    received any of it. Treating the partial as resumable would mix
    bytes from two different files."""
    s = _state()
    assert can_resume_with(s, "tid", 100, 50, ["DIFFERENT", "h1"]) is False


# --- cleanup ---


def test_cleanup_removes_both_files(tmp_path):
    p = tmp_path / "x.partial"
    m = tmp_path / "x.meta"
    p.write_bytes(b"data")
    m.write_text("{}")
    cleanup_receiver(str(p), str(m))
    assert not p.exists()
    assert not m.exists()


def test_cleanup_tolerates_missing_files(tmp_path):
    """Cleanup should not raise if either file is already gone."""
    cleanup_receiver(str(tmp_path / "absent.partial"),
                     str(tmp_path / "absent.meta"))


# --- sender-side cache ---


def test_sender_cache_round_trips_for_unchanged_file(tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"x" * 100)
    cache = sender_cache_path(str(src))
    save_sender_cache(cache, str(src), 50,
                     content_hash_b64="ch", chunk_hashes_b64=["h0", "h1"])
    loaded = load_sender_cache(cache, str(src))
    assert loaded is not None
    assert loaded["chunk_size"] == 50
    assert loaded["content_hash"] == "ch"
    assert loaded["chunk_hashes"] == ["h0", "h1"]


def test_sender_cache_invalidates_on_size_change(tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"x" * 100)
    cache = sender_cache_path(str(src))
    save_sender_cache(cache, str(src), 50, "ch", ["h0", "h1"])
    src.write_bytes(b"y" * 200)  # different size -> cache invalid
    assert load_sender_cache(cache, str(src)) is None


def test_sender_cache_invalidates_on_mtime_change(tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"x" * 100)
    cache = sender_cache_path(str(src))
    save_sender_cache(cache, str(src), 50, "ch", ["h0", "h1"])
    # Same size, different mtime
    new_atime = src.stat().st_atime + 1000
    new_mtime = src.stat().st_mtime + 1000
    os.utime(str(src), (new_atime, new_mtime))
    assert load_sender_cache(cache, str(src)) is None


def test_sender_cache_returns_none_when_source_missing(tmp_path):
    cache = str(tmp_path / "x.cache")
    # Write a cache for a nonexistent source — load should refuse.
    with open(cache, "w") as f:
        json.dump({
            "size": 1, "mtime_ns": 0, "inode": 0, "chunk_size": 1,
            "content_hash": "x", "chunk_hashes": [],
        }, f)
    assert load_sender_cache(cache, str(tmp_path / "absent.bin")) is None


def test_sender_cache_returns_none_when_cache_missing(tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"x")
    assert load_sender_cache(str(tmp_path / "absent.cache"), str(src)) is None


def test_sender_cache_returns_none_on_corrupt_json(tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"x")
    cache = str(tmp_path / "src.cache")
    with open(cache, "w") as f:
        f.write("not json")
    assert load_sender_cache(cache, str(src)) is None


def test_b64_round_trips():
    from takeit.cli._resume import b64d
    data = b"\x00\x01\x02\xff"
    assert b64d(b64(data)) == data


# --- A5: verify_chunks_have ---


def _h(b):
    return hashlib.blake2b(b, digest_size=32).digest()


def test_verify_chunks_have_returns_all_when_bytes_match(tmp_path):
    chunk_size = 50
    payload = b"abc" * 100  # 300 bytes = 6 chunks of 50
    partial = tmp_path / "f.bin.partial"
    partial.write_bytes(payload)
    chunk_hashes = [_h(payload[i:i + chunk_size])
                    for i in range(0, len(payload), chunk_size)]
    verified = verify_chunks_have(
        str(partial), len(payload), chunk_size,
        chunk_hashes, claimed_chunks_have=[0, 1, 2, 3, 4, 5])
    assert verified == {0, 1, 2, 3, 4, 5}


def test_verify_chunks_have_drops_corrupted_chunk(tmp_path):
    """An attacker pre-stages a partial whose chunk 2 doesn't match the
    expected hash. verify_chunks_have drops index 2 silently."""
    chunk_size = 50
    payload = b"abc" * 100
    chunk_hashes = [_h(payload[i:i + chunk_size])
                    for i in range(0, len(payload), chunk_size)]
    # Corrupt chunk 2 on disk
    corrupted = bytearray(payload)
    corrupted[100:150] = b"X" * 50
    partial = tmp_path / "f.bin.partial"
    partial.write_bytes(bytes(corrupted))
    verified = verify_chunks_have(
        str(partial), len(payload), chunk_size, chunk_hashes,
        claimed_chunks_have=[0, 1, 2, 3])
    assert verified == {0, 1, 3}


def test_verify_chunks_have_drops_out_of_range_indices(tmp_path):
    chunk_size = 50
    payload = b"x" * 100  # 2 chunks
    partial = tmp_path / "f.bin.partial"
    partial.write_bytes(payload)
    chunk_hashes = [_h(payload[:50]), _h(payload[50:])]
    verified = verify_chunks_have(
        str(partial), len(payload), chunk_size, chunk_hashes,
        claimed_chunks_have=[0, 5, -1, 1])
    assert verified == {0, 1}


def test_verify_chunks_have_handles_short_last_chunk(tmp_path):
    """A file whose size isn't a multiple of chunk_size has a short last
    chunk; the hash must be over the actual short bytes, not padded."""
    chunk_size = 50
    payload = b"a" * 50 + b"b" * 30  # 80 bytes, last chunk is 30
    partial = tmp_path / "f.bin.partial"
    partial.write_bytes(payload)
    chunk_hashes = [_h(b"a" * 50), _h(b"b" * 30)]
    verified = verify_chunks_have(
        str(partial), len(payload), chunk_size, chunk_hashes,
        claimed_chunks_have=[0, 1])
    assert verified == {0, 1}


def test_verify_chunks_have_returns_empty_for_missing_partial(tmp_path):
    """Missing partial → empty set, not exception. Caller treats as
    'nothing resumable, start fresh'."""
    chunk_hashes = [_h(b"x")]
    verified = verify_chunks_have(
        str(tmp_path / "absent.partial"), 1, 1, chunk_hashes,
        claimed_chunks_have=[0])
    assert verified == set()


# --- B4: cleanup_orphan_tmp_files ---


def test_cleanup_orphan_tmp_removes_only_tmp_meta_files(tmp_path):
    (tmp_path / "x.takeit-partial.meta.tmp").write_text("partial")
    (tmp_path / "y.takeit-partial.meta.tmp").write_text("also partial")
    (tmp_path / "x.takeit-partial.meta").write_text("legitimate sidecar")
    (tmp_path / "x.takeit-partial").write_bytes(b"data")
    (tmp_path / "unrelated.txt").write_text("keep")
    cleanup_orphan_tmp_files(str(tmp_path))
    remaining = sorted(p.name for p in tmp_path.iterdir())
    assert remaining == ["unrelated.txt", "x.takeit-partial",
                         "x.takeit-partial.meta"]


def test_cleanup_orphan_tmp_handles_missing_directory(tmp_path):
    """No exception when the directory doesn't exist."""
    cleanup_orphan_tmp_files(str(tmp_path / "absent"))


def test_cleanup_orphan_tmp_handles_non_directory(tmp_path):
    """No exception when path is a file, not a directory."""
    p = tmp_path / "file.txt"
    p.write_text("x")
    cleanup_orphan_tmp_files(str(p))


# --- A3: ReceiverStateThrottle ---


class _FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def _read_chunks_have(meta_path):
    with open(meta_path) as f:
        return set(json.load(f)["chunks_have"])


def test_throttle_initialize_writes_immediately(tmp_path):
    meta = str(tmp_path / "f.meta")
    clock = _FakeClock()
    t = ReceiverStateThrottle(meta, "tid", 100, 50, ["h0", "h1"],
                              interval=2.0, clock=clock)
    t.initialize({0})
    assert _read_chunks_have(meta) == {0}


def test_throttle_update_buffers_within_interval(tmp_path):
    meta = str(tmp_path / "f.meta")
    clock = _FakeClock()
    t = ReceiverStateThrottle(meta, "tid", 100, 50, ["h0", "h1"],
                              interval=2.0, clock=clock)
    t.initialize(set())
    # Many updates within interval → only the initial write hit disk
    clock.advance(0.5)
    t.update({0})
    clock.advance(0.5)
    t.update({0, 1})
    clock.advance(0.5)
    t.update({0, 1})
    # Disk still shows the initial state (empty)
    assert _read_chunks_have(meta) == set()


def test_throttle_update_writes_when_interval_elapses(tmp_path):
    meta = str(tmp_path / "f.meta")
    clock = _FakeClock()
    t = ReceiverStateThrottle(meta, "tid", 100, 50, ["h0", "h1"],
                              interval=2.0, clock=clock)
    t.initialize(set())
    clock.advance(2.5)  # past interval
    t.update({0, 1})
    assert _read_chunks_have(meta) == {0, 1}


def test_throttle_flush_writes_regardless_of_interval(tmp_path):
    meta = str(tmp_path / "f.meta")
    clock = _FakeClock()
    t = ReceiverStateThrottle(meta, "tid", 100, 50, ["h0", "h1"],
                              interval=10.0, clock=clock)
    t.initialize(set())
    t.update({0, 1, 2})  # buffered (within interval)
    assert _read_chunks_have(meta) == set()  # not flushed yet
    t.flush()
    assert _read_chunks_have(meta) == {0, 1, 2}


def test_throttle_amortizes_writes_for_long_transfer(tmp_path):
    """Counts disk writes: 1000 chunk updates over 1 simulated second
    with a 2-second throttle should only do the initial write."""
    meta = str(tmp_path / "f.meta")
    clock = _FakeClock()
    write_count = [0]

    real_save = save_receiver_state

    def counting_save(*args, **kwargs):
        write_count[0] += 1
        return real_save(*args, **kwargs)

    import takeit.cli._resume as resume_mod
    monkey_orig = resume_mod.save_receiver_state
    try:
        resume_mod.save_receiver_state = counting_save
        t = ReceiverStateThrottle(meta, "tid", 100, 50, ["h0", "h1"],
                                  interval=2.0, clock=clock)
        t.initialize(set())
        for i in range(1000):
            clock.advance(0.001)  # 1 ms each, total 1 second
            t.update(set(range(i + 1)))
        t.flush()
    finally:
        resume_mod.save_receiver_state = monkey_orig

    # Initial write + final flush = 2 (no intermediate writes within 2 s).
    assert write_count[0] == 2

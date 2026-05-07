"""
Tests for the deterministic directory-zip stream.

Determinism is load-bearing: takeit's resume relies on `transfer_id =
BLAKE2b(stream)`. If the same source directory produced different bytes
across runs, transfer_id would change, and the receiver's partial would
be discarded. These tests pin the invariant.
"""

import hashlib
import io
import os
import struct
import zipfile

import pytest

from takeit.cli._zipstream import (
    deterministic_directory_zip,
    extract_zip_safely,
    materialize_and_hash,
    walk_directory,
)


def _materialize(root, layout):
    """Create a tree under root from a {relpath: bytes} dict. relpaths
    use forward slashes; intermediate directories are auto-created."""
    for rel, content in layout.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(content)


# --- walk_directory ---


def test_walk_directory_returns_stable_order(tmp_path):
    """Order is deterministic across runs (depth-first, sorted within
    each level). The exact order doesn't matter for the on-wire format
    as long as it's identical between runs — that's what makes the zip
    stream byte-stable for resume."""
    _materialize(
        tmp_path,
        {
            "z.txt": b"z",
            "a.txt": b"a",
            "sub/c.txt": b"c",
            "sub/b.txt": b"b",
        },
    )
    paths_a, num_files, num_bytes = walk_directory(str(tmp_path))
    paths_b, _, _ = walk_directory(str(tmp_path))
    assert paths_a == paths_b
    assert num_files == 4
    assert num_bytes == 4  # 1 byte each
    # Within each directory, files appear in lexicographic order.
    rels = [os.path.relpath(p, str(tmp_path)) for p in paths_a]
    top_level = [r for r in rels if "/" not in r]
    assert top_level == sorted(top_level)


def test_walk_directory_handles_empty_dir(tmp_path):
    paths, num_files, num_bytes = walk_directory(str(tmp_path))
    assert paths == []
    assert num_files == 0
    assert num_bytes == 0


def test_walk_directory_refuses_symlink_pointing_outside_root(tmp_path):
    """A symlink whose target resolves outside the source root is a
    privacy/exfiltration risk — refuse loudly rather than silently
    following or silently dropping."""
    outside = tmp_path.parent / "outside.txt"
    outside.write_bytes(b"sensitive")
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_bytes(b"normal")
    (src / "leak").symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        walk_directory(str(src))


def test_walk_directory_follows_symlink_pointing_inside_root(tmp_path):
    """A symlink whose target resolves WITHIN the source root is safe
    to include — the user clearly intends it as part of the tree."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_bytes(b"target")
    (src / "alias").symlink_to(src / "a.txt")
    paths, num_files, num_bytes = walk_directory(str(src))
    rels = sorted(os.path.relpath(p, str(src)) for p in paths)
    assert rels == ["a.txt", "alias"]


# --- deterministic_directory_zip ---


def test_zip_stream_yields_valid_zip(tmp_path):
    _materialize(
        tmp_path,
        {
            "a.txt": b"hello world",
            "sub/b.txt": b"deeper",
        },
    )
    blob = b"".join(deterministic_directory_zip(str(tmp_path)))
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        names = sorted(zi.filename for zi in zf.infolist())
        assert names == ["a.txt", "sub/b.txt"]
        assert zf.read("a.txt") == b"hello world"
        assert zf.read("sub/b.txt") == b"deeper"


def test_zip_stream_byte_identical_across_runs(tmp_path):
    """The crucial determinism invariant: same input → same output.
    If this fails, resume breaks."""
    _materialize(
        tmp_path,
        {
            "a.txt": b"hello",
            "b.txt": b"world",
            "sub/c.txt": b"!",
        },
    )
    a = b"".join(deterministic_directory_zip(str(tmp_path)))
    b = b"".join(deterministic_directory_zip(str(tmp_path)))
    assert a == b


def test_zip_stream_is_independent_of_filesystem_mtime(tmp_path):
    """Two trees with identical names+contents but different on-disk
    mtimes must produce byte-identical zips. Otherwise a `touch *` on
    one side would invalidate a partial on the other side."""
    a_dir = tmp_path / "a"
    b_dir = tmp_path / "b"
    a_dir.mkdir()
    b_dir.mkdir()
    (a_dir / "f.txt").write_bytes(b"same content")
    (b_dir / "f.txt").write_bytes(b"same content")
    # Set different mtimes
    os.utime(a_dir / "f.txt", (1_000_000, 1_000_000))
    os.utime(b_dir / "f.txt", (2_000_000, 2_000_000))
    a = b"".join(deterministic_directory_zip(str(a_dir)))
    b = b"".join(deterministic_directory_zip(str(b_dir)))
    assert a == b


def test_zip_stream_empty_dir_yields_minimal_valid_zip(tmp_path):
    blob = b"".join(deterministic_directory_zip(str(tmp_path)))
    # Even an empty zip is valid and openable
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        assert zf.namelist() == []


def test_zip_stream_uses_stored_compression(tmp_path):
    """We deliberately use STORED (no compression). Compressors
    aren't byte-stable across versions/levels — STORED is."""
    _materialize(tmp_path, {"a.txt": b"highly compressible " * 100})
    blob = b"".join(deterministic_directory_zip(str(tmp_path)))
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for zi in zf.infolist():
            assert zi.compress_type == zipfile.ZIP_STORED


def test_zip_stream_streams_large_file_without_loading_in_memory(tmp_path):
    """The generator must yield chunks as it processes — for a
    big file, sum of yielded sizes ≥ file size, but no single
    yield should be the whole file. We assert: at least 4 yields
    occur for a 4 MiB file (the inner read loop uses 64 KiB
    reads, so we'd expect ~64 yields, but a more lenient bound
    of >=4 lets the implementation evolve)."""
    big = b"x" * (4 << 20)  # 4 MiB
    (tmp_path / "big.bin").write_bytes(big)
    chunks_yielded = 0
    sink = io.BytesIO()
    for chunk in deterministic_directory_zip(str(tmp_path)):
        chunks_yielded += 1
        sink.write(chunk)
    blob = sink.getvalue()
    assert chunks_yielded >= 4, (
        f"expected streaming, got only {chunks_yielded} yield(s)"
    )
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        assert zf.read("big.bin") == big


# --- extract_zip_safely ---


def test_extract_zip_safely_extracts_normal_zip(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _materialize(src, {"a.txt": b"hi", "sub/b.txt": b"there"})
    blob = b"".join(deterministic_directory_zip(str(src)))
    dest = tmp_path / "dest"
    dest.mkdir()
    extract_zip_safely(io.BytesIO(blob), str(dest))
    assert (dest / "a.txt").read_bytes() == b"hi"
    assert (dest / "sub" / "b.txt").read_bytes() == b"there"


def test_extract_zip_safely_rejects_zip_slip_relative(tmp_path):
    """A malicious zip with `../` in entry names tries to escape
    the destination. The receiver must reject."""
    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as zf:
        zi = zipfile.ZipInfo("../escape.txt", date_time=(1980, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_STORED
        zf.writestr(zi, b"pwn")
    bad.seek(0)
    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(ValueError, match="escape|traversal|slip"):
        extract_zip_safely(bad, str(dest))


def test_extract_zip_safely_rejects_zip_slip_absolute(tmp_path):
    """Absolute paths in zip entries — same defense applies."""
    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as zf:
        zi = zipfile.ZipInfo("/tmp/escape.txt", date_time=(1980, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_STORED
        zf.writestr(zi, b"pwn")
    bad.seek(0)
    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(ValueError, match="escape|traversal|slip|absolute"):
        extract_zip_safely(bad, str(dest))


def test_extract_zip_safely_rejects_symlink_entry(tmp_path):
    """A zip entry can encode a symlink by setting external_attr
    bit 0xA000 (S_IFLNK). Refuse — symlinks in extracted trees
    are a footgun (e.g. point to /etc/passwd, then a follow-up
    write through the symlink overwrites it)."""
    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as zf:
        zi = zipfile.ZipInfo("link", date_time=(1980, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_STORED
        # 0xA000 = S_IFLNK in upper 16 bits of external_attr
        zi.external_attr = (0xA1FF) << 16
        zf.writestr(zi, b"/etc/passwd")
    bad.seek(0)
    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(ValueError, match="symlink"):
        extract_zip_safely(bad, str(dest))


def test_extract_zip_safely_rejects_oversized_entry(tmp_path):
    """A hostile peer could advertise a small zip whose central
    directory claims a 1 TiB entry inside. We don't enforce a
    size cap inside the helper itself — the offer-level
    MAX_OFFER_SIZE already bounds the overall stream — but the
    helper must not silently misbehave on a header/body length
    mismatch. Crafting one is intricate; smoke-test with a
    truncated-content zip and assert it raises (zipfile itself
    catches this).
    """
    src = tmp_path / "src"
    src.mkdir()
    _materialize(src, {"a.txt": b"hello"})
    blob = b"".join(deterministic_directory_zip(str(src)))
    truncated = blob[:-30]  # corrupt the central directory tail
    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises((ValueError, zipfile.BadZipFile, struct.error)):
        extract_zip_safely(io.BytesIO(truncated), str(dest))


# --- transfer_id stability across logically-identical trees ---


# --- materialize_and_hash ---


def test_materialize_and_hash_returns_correct_hashes(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _materialize(src, {"a.txt": b"hello", "sub/b.txt": b"world"})
    out = tmp_path / "out.zip"
    size, content_hash, chunk_hashes = materialize_and_hash(
        str(src), str(out), chunk_size=1 << 20
    )
    # The on-disk file must equal the streamed bytes byte-for-byte.
    blob = b"".join(deterministic_directory_zip(str(src)))
    assert out.read_bytes() == blob
    assert size == len(blob)
    assert content_hash == hashlib.blake2b(blob, digest_size=32).digest()
    # One chunk for any blob smaller than the chunk size.
    assert len(chunk_hashes) == 1
    assert chunk_hashes[0] == hashlib.blake2b(blob, digest_size=32).digest()


def test_materialize_and_hash_chunks_correctly_at_boundary(tmp_path):
    """When the stream length crosses a chunk_size boundary, we get
    multiple chunk hashes that exactly cover the stream."""
    src = tmp_path / "src"
    src.mkdir()
    # A pile of files large enough to push the stream past one chunk.
    _materialize(src, {f"f{i:02d}.bin": b"x" * 100_000 for i in range(15)})
    out = tmp_path / "out.zip"
    size, content_hash, chunk_hashes = materialize_and_hash(
        str(src), str(out), chunk_size=1 << 20
    )  # 1 MiB
    assert size == out.stat().st_size
    # Re-stream and re-hash to verify chunk_hashes match the file.
    blob = out.read_bytes()
    expected_chunks = []
    for i in range(0, len(blob), 1 << 20):
        expected_chunks.append(
            hashlib.blake2b(blob[i : i + (1 << 20)], digest_size=32).digest()
        )
    assert chunk_hashes == expected_chunks
    assert content_hash == hashlib.blake2b(blob, digest_size=32).digest()


def test_materialize_and_hash_handles_empty_dir(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    out = tmp_path / "out.zip"
    size, content_hash, chunk_hashes = materialize_and_hash(
        str(src), str(out), chunk_size=1 << 20
    )
    blob = out.read_bytes()
    assert size == len(blob)
    assert content_hash == hashlib.blake2b(blob, digest_size=32).digest()
    # An empty zip is non-empty (it has the central directory record),
    # so we expect exactly one chunk hash.
    assert len(chunk_hashes) == 1


def test_zip_stream_hash_stable_across_logically_identical_trees(tmp_path):
    """Two directories with the same content+structure but built at
    different times produce the same BLAKE2b digest. This is the
    property that makes `transfer_id` stable for resume."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _materialize(a, {"x.txt": b"data", "y/z.txt": b"more"})
    _materialize(b, {"x.txt": b"data", "y/z.txt": b"more"})
    h_a = hashlib.blake2b(digest_size=32)
    for c in deterministic_directory_zip(str(a)):
        h_a.update(c)
    h_b = hashlib.blake2b(digest_size=32)
    for c in deterministic_directory_zip(str(b)):
        h_b.update(c)
    assert h_a.digest() == h_b.digest()

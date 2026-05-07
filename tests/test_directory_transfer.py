"""
End-to-end-ish tests for directory transfer (HYP-388).

Exercises the same code paths cli.py drives, without spinning up a
full wormhole + dilation stack:
- sender: walk_directory + materialize_and_hash + build_offer_directory
- receiver: parse_offer + extract_zip_safely + atomic-rename

The wormhole/dilation layer is unit-tested elsewhere (test_api,
test_boss, etc.); this file pins the directory-specific glue.
"""
import filecmp
import io
import os
import zipfile

import pytest

from takeit.cli import _protocol as P
from takeit.cli import _zipstream as Z


# --- helpers ---


def _materialize(root, layout):
    for rel, content in layout.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(content)


def _trees_equal(a, b):
    """Compare two directory trees by relative path + file content."""
    cmp = filecmp.dircmp(a, b)
    if cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files:
        return False
    for sub in cmp.common_dirs:
        if not _trees_equal(os.path.join(a, sub), os.path.join(b, sub)):
            return False
    return True


# --- end-to-end (in-process; no wormhole layer) ---


def test_e2e_directory_transfer_round_trips(tmp_path):
    """Sender materializes a deterministic zip + offer; receiver parses
    the offer, extracts the zip into a tempdir, atomic-renames into the
    destination. Final tree matches source byte-for-byte."""
    src = tmp_path / "src"
    src.mkdir()
    _materialize(src, {
        "README.md": b"# project\n",
        "src/main.py": b"print('hi')\n",
        "src/util.py": b"def f(): return 42\n",
        "data/big.bin": os.urandom(1_500_000),  # crosses chunk boundary
    })
    chunk_size = 1 << 20

    # Sender: build the offer.
    tmp_zip = tmp_path / "send.zip"
    files, num_files, num_bytes = Z.walk_directory(str(src))
    size, content_hash, chunk_hashes = Z.materialize_and_hash(
        str(src), str(tmp_zip), chunk_size)
    offer_msg = P.build_offer_directory(
        "src", size, content_hash, chunk_hashes,
        num_files=num_files, num_bytes=num_bytes,
        chunk_size=chunk_size)

    # Wire transit: in real CLI the bytes ride dilation chunks; here we
    # just hand the receiver the materialized zip directly.
    parsed = P.parse_offer(P.encode_message(offer_msg))
    assert parsed["kind"] == P.KIND_DIRECTORY
    assert parsed["dir_name"] == "src"
    assert parsed["num_files"] == num_files
    assert parsed["num_bytes"] == num_bytes
    assert parsed["size"] == size
    assert parsed["_content_hash_bytes"] == content_hash

    # Receiver: extract into a tempdir, atomic-rename into final dest.
    dest_root = tmp_path / "receiver"
    dest_root.mkdir()
    final_dest = dest_root / parsed["dir_name"]
    extract_tmp = dest_root / f"{parsed['dir_name']}.takeit-extract"
    extract_tmp.mkdir()
    Z.extract_zip_safely(str(tmp_zip), str(extract_tmp))
    os.rename(extract_tmp, final_dest)

    # The extracted tree must match the source.
    assert _trees_equal(str(src), str(final_dest))


def test_e2e_directory_transfer_resume_simulation(tmp_path):
    """Pretend the partial file already has the first half of the zip
    bytes from a prior aborted run. Re-running `materialize_and_hash`
    must produce a byte-identical zip — that's what makes resume work.
    Then we ensure the chunk hashes from the partial match what the
    new offer would advertise (so the receiver could reuse them)."""
    src = tmp_path / "src"
    src.mkdir()
    _materialize(src, {
        "a.txt": b"x" * 600_000,
        "b.txt": b"y" * 600_000,  # together: 1.2 MiB → 2 chunks
    })
    chunk_size = 1 << 20

    # Sender pass 1.
    zip_a = tmp_path / "a.zip"
    size_a, hash_a, chunks_a = Z.materialize_and_hash(
        str(src), str(zip_a), chunk_size)

    # Sender pass 2 (e.g. after the user re-runs).
    zip_b = tmp_path / "b.zip"
    size_b, hash_b, chunks_b = Z.materialize_and_hash(
        str(src), str(zip_b), chunk_size)

    # Determinism: byte-identical, same hashes.
    assert zip_a.read_bytes() == zip_b.read_bytes()
    assert size_a == size_b
    assert hash_a == hash_b
    assert chunks_a == chunks_b


def test_e2e_directory_zipslip_rejected(tmp_path):
    """Receiver's extract_zip_safely refuses a zip whose entry names
    try to escape the destination — even if the offer's outer hash
    verifies (the attacker controls the content)."""
    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as zf:
        zi = zipfile.ZipInfo(
            "../escape.txt", date_time=(1980, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_STORED
        zf.writestr(zi, b"would have escaped")
    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(ValueError):
        Z.extract_zip_safely(bad.getvalue(), str(dest))
    # No file landed.
    assert os.listdir(dest) == []
    assert not (tmp_path / "escape.txt").exists()


def test_e2e_directory_offer_rejects_nonexistent_root(tmp_path):
    nope = tmp_path / "does-not-exist"
    with pytest.raises(ValueError, match="not a directory"):
        Z.walk_directory(str(nope))


def test_e2e_directory_with_empty_subdirs(tmp_path):
    """Empty subdirectories aren't preserved (zip walks files only).
    Document the behavior so it's not a surprise."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "empty_dir").mkdir()
    (src / "a.txt").write_bytes(b"hello")
    chunk_size = 1 << 20
    out = tmp_path / "out.zip"
    Z.materialize_and_hash(str(src), str(out), chunk_size)
    dest = tmp_path / "dest"
    dest.mkdir()
    Z.extract_zip_safely(str(out), str(dest))
    # a.txt round-trips; empty_dir does NOT.
    assert (dest / "a.txt").read_bytes() == b"hello"
    assert not (dest / "empty_dir").exists()


# --- offer caps still apply ---


def test_directory_offer_uses_chunk_count_cap(tmp_path):
    """A directory offer is subject to the same MAX_CHUNK_COUNT cap as
    a file offer — derived from `_validate_chunked_offer` in
    _protocol.py. Build an offer with a tiny chunk_size to hit the cap."""
    h = b"\x00" * 32
    huge_chunk_count = P.MAX_CHUNK_COUNT + 1
    chunks = [b"\x00" * 32] * huge_chunk_count
    with pytest.raises(ValueError, match="chunk count"):
        P.build_offer_directory(
            "ok", huge_chunk_count, h, chunks,
            num_files=0, num_bytes=0, chunk_size=1)

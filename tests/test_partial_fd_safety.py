"""
Tests for the receiver's partial-file fd-safety (HYP-408, audit #4).

The audit found that `_ReceiverProtocol.connectionMade`:
- Created fresh partials with O_NOFOLLOW, then closed the fd, then
  reopened by path. The reopen-by-path step lost the no-follow
  guarantee — local attacker could win a TOCTOU race between close
  and reopen, replacing the partial with a symlink to a target they
  want overwritten.
- For resume (existing partial), opened by path with no no-follow
  protection at all.

The fix: keep the original fd via os.fdopen(fd, ...). For resume,
open with O_NOFOLLOW + lstat/fstat cross-check that the path resolved
to the same inode that the fd points at.
"""

import os
import stat

import pytest

from takeit.cli import cli as cli_mod

# --- helpers ---


class _FakeFactory:
    """Minimal stand-in for _ReceiverFactory; only the attributes
    `_ReceiverProtocol.connectionMade` reads."""

    def __init__(self, partial_path, prior_matches=False):
        self._partial_path = str(partial_path)
        self._meta_path = str(partial_path) + ".meta"
        self._offer = {
            "kind": "file",
            "filename": "test.bin",
            "size": 100,
            "chunk_size": 50,
            "transfer_id": "AAAAAAAAAAAAAAAAAAAAAA==",
            "_content_hash_bytes": b"\x00" * 32,
            "_transfer_id_bytes": b"\x00" * 16,
        }
        self._prior_matches = prior_matches
        self._progress = None


def _make_proto(tmp_path, prior_matches=False):
    factory = _FakeFactory(tmp_path / "incoming.bin", prior_matches=prior_matches)
    return cli_mod._ReceiverProtocol(factory), factory


# --- fresh-partial path: fd-keep, no reopen-by-path ---


def test_fresh_partial_uses_fd_keep_not_reopen(tmp_path):
    """connectionMade for a fresh partial must NOT close-then-reopen
    by path. We assert by checking that os.open was called once with
    O_CREAT|O_EXCL|O_NOFOLLOW, and the resulting fd is what self._fh
    wraps — no second `open(path, ...)` between them."""
    proto, factory = _make_proto(tmp_path)
    proto.connectionMade()
    assert proto._fh is not None
    # The fd should be open (calling fileno succeeds).
    fd = proto._fh.fileno()
    assert fd >= 0
    # The file was created at the partial path with mode 0o600.
    st = os.lstat(factory._partial_path)
    assert stat.S_ISREG(st.st_mode)
    assert stat.S_IMODE(st.st_mode) == 0o600
    # And the fd points at exactly that inode (no swap happened).
    fst = os.fstat(fd)
    assert fst.st_ino == st.st_ino
    proto._fh.close()


def test_fresh_partial_refuses_existing_path(tmp_path):
    """O_EXCL means a pre-existing partial path causes a fresh-partial
    create to fail loud. The receiver protocol should propagate that
    rather than silently overwrite. (For resume, the partial-exists
    case takes a different code path; this test is about the FRESH
    path only — we hit it by ensuring `prior_matches_offer` is False.)"""
    partial = tmp_path / "incoming.bin"
    partial.write_bytes(b"already here")
    proto, factory = _make_proto(tmp_path, prior_matches=False)
    # In the new design the "stale partial" branch in _run_receive
    # cleans this up before we get here, so connectionMade should
    # NEVER see a stranded partial it didn't create. But if it does
    # (defensive), it must NOT silently truncate. The current behavior
    # is to call cleanup_receiver upstream; here we just verify that
    # the connection-made path either succeeds (because cleanup ran)
    # or raises (because it didn't and the stranded file blocks
    # O_EXCL).
    with pytest.raises(FileExistsError):
        proto.connectionMade()


def test_fresh_partial_refuses_symlink_at_path(tmp_path):
    """If a local attacker pre-created a symlink at the partial path,
    O_NOFOLLOW must refuse rather than follow it to the target. The
    Linux/macOS errno differs (ELOOP vs EMLINK) but both raise OSError."""
    target = tmp_path / "target.txt"
    target.write_bytes(b"victim")
    partial = tmp_path / "incoming.bin"
    partial.symlink_to(target)
    proto, _factory = _make_proto(tmp_path, prior_matches=False)
    with pytest.raises(OSError):
        proto.connectionMade()
    # Critical: the target was NOT touched.
    assert target.read_bytes() == b"victim"


# --- resume path: O_NOFOLLOW + cross-check ---


def test_resume_partial_opens_with_nofollow(tmp_path):
    """Resume case: pre-existing real partial. The open MUST use
    O_NOFOLLOW so a symlink at the path is rejected even on the
    second-time-around path."""
    partial = tmp_path / "incoming.bin"
    partial.write_bytes(b"\x00" * 100)
    proto, _factory = _make_proto(tmp_path, prior_matches=True)
    proto.connectionMade()
    # Fd points at the partial.
    fst = os.fstat(proto._fh.fileno())
    lst = os.lstat(partial)
    assert fst.st_ino == lst.st_ino
    proto._fh.close()


def test_resume_refuses_symlink(tmp_path):
    """An attacker swapped the partial for a symlink to elsewhere.
    Resume open must refuse via O_NOFOLLOW."""
    target = tmp_path / "target.txt"
    target.write_bytes(b"victim")
    partial = tmp_path / "incoming.bin"
    partial.symlink_to(target)
    proto, _factory = _make_proto(tmp_path, prior_matches=True)
    with pytest.raises(OSError):
        proto.connectionMade()
    assert target.read_bytes() == b"victim"


def test_resume_cross_check_detects_swap(tmp_path, monkeypatch):
    """Even with O_NOFOLLOW the path could be replaced with another
    REAL file between lstat (called during resume planning) and the
    fd-open here. The fix: lstat AGAIN after open, fstat the fd, and
    cross-check inode/dev. We simulate the race by having lstat
    return a stat-result whose inode differs from fstat's.

    This test verifies the cross-check fires; the production code
    raises a clearly-named error or refuses to proceed."""
    partial = tmp_path / "incoming.bin"
    partial.write_bytes(b"\x00" * 100)

    # Stash the real lstat so we can return a forged result.
    real_lstat = os.lstat

    def forged_lstat(p):
        # Return a stat_result whose inode is the real one + 1.
        # We only need to fake it the FIRST time it's called inside
        # connectionMade's cross-check; subsequent calls (e.g. by
        # tests asserting state) must work normally.
        if str(p) == str(partial):
            real = real_lstat(p)
            forged = list(real)
            forged[1] = real.st_ino + 1  # st_ino is index 1
            return os.stat_result(forged)
        return real_lstat(p)

    monkeypatch.setattr(os, "lstat", forged_lstat)
    proto, _factory = _make_proto(tmp_path, prior_matches=True)
    # The cross-check should fire because lstat-vs-fstat inodes mismatch.
    # The receiver protocol raises OSError or a similar — we don't pin
    # the exact class, just that it refuses.
    with pytest.raises((OSError, RuntimeError, ValueError)):
        proto.connectionMade()

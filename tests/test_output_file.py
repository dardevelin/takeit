"""
Tests for `takeit receive --output-file PATH` (HYP-398).

Wormhole's `--output-file` accepts EITHER a full path (rename-on-receive)
OR a directory path (use as parent, keep sender's name). Resolution
infers intent from whether the path exists and is a directory.

This module pins the path-resolution helper plus the Click surface.
"""

import os

import pytest
from click.testing import CliRunner

from takeit.cli.cli import _resolve_output_target, cmd_receive

# --- Click flag presence ---


def test_receive_has_output_file_flag():
    runner = CliRunner()
    result = runner.invoke(cmd_receive, ["--help"])
    assert result.exit_code == 0
    assert "--output-file" in result.output
    assert "-o" in result.output


def test_receive_no_longer_has_output_dir():
    """HYP-398 replaces --output-dir with --output-file. The old flag
    is gone — pre-PyPI is the right time to consolidate."""
    runner = CliRunner()
    result = runner.invoke(cmd_receive, ["--help"])
    assert result.exit_code == 0
    assert "--output-dir" not in result.output


# --- _resolve_output_target ---


def test_resolve_default_uses_downloads_or_cwd(tmp_path, monkeypatch):
    """When --output-file is None, default to ~/Downloads (if it exists
    and is writable) else current dir, keeping sender's name."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    downloads = fake_home / "Downloads"
    downloads.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    parent, name = _resolve_output_target(None, "report.pdf")
    assert os.path.realpath(parent) == os.path.realpath(str(downloads))
    assert name == "report.pdf"


def test_resolve_default_falls_back_to_cwd_when_no_downloads(tmp_path, monkeypatch):
    """If ~/Downloads doesn't exist, default to cwd."""
    fake_home = tmp_path / "no_downloads_home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.chdir(tmp_path)
    parent, name = _resolve_output_target(None, "report.pdf")
    assert os.path.realpath(parent) == os.path.realpath(str(tmp_path))
    assert name == "report.pdf"


def test_resolve_existing_dir_uses_it_as_parent(tmp_path):
    """If --output-file points at an existing directory, use it as
    the parent and keep the sender's name."""
    parent_dir = tmp_path / "scratch"
    parent_dir.mkdir()
    parent, name = _resolve_output_target(str(parent_dir), "report.pdf")
    assert os.path.realpath(parent) == os.path.realpath(str(parent_dir))
    assert name == "report.pdf"


def test_resolve_non_existing_path_with_existing_parent_renames(tmp_path):
    """If --output-file points at a non-existing path whose parent
    exists, treat it as a full target path: parent → parent_dir,
    basename → final_name (rename-on-receive)."""
    target = tmp_path / "renamed.pdf"
    parent, name = _resolve_output_target(str(target), "original.pdf")
    assert os.path.realpath(parent) == os.path.realpath(str(tmp_path))
    assert name == "renamed.pdf"


def test_resolve_non_existing_path_with_missing_parent_errors(tmp_path):
    """If neither the path nor its parent exists, error early — we
    refuse to silently mkdir -p; that's a sign of typo or wrong arg."""
    bogus = tmp_path / "does" / "not" / "exist.pdf"
    with pytest.raises(ValueError, match="parent"):
        _resolve_output_target(str(bogus), "ignored.pdf")


def test_resolve_path_pointing_at_existing_file_errors(tmp_path):
    """If --output-file points at an existing FILE (not directory),
    that's collision-territory: refuse rather than silently overwrite.
    The actual final-write code has its own lstat/atomic-rename guard
    too, but failing fast at resolve-time is friendlier."""
    existing = tmp_path / "already_here.pdf"
    existing.write_bytes(b"existing")
    with pytest.raises(ValueError, match="exists"):
        _resolve_output_target(str(existing), "ignored.pdf")


def test_resolve_relative_path_resolves_via_realpath(tmp_path, monkeypatch):
    """A relative --output-file resolves against cwd, then we use the
    realpath so symlinks in the path are pinned at resolve time."""
    monkeypatch.chdir(tmp_path)
    target = "renamed.pdf"  # relative to tmp_path
    parent, name = _resolve_output_target(target, "original.pdf")
    assert os.path.realpath(parent) == os.path.realpath(str(tmp_path))
    assert name == "renamed.pdf"


# --- Click integration: --output-file accepts both shapes ---


def test_output_file_short_alias_o(tmp_path):
    """`-o` short alias is accepted."""
    runner = CliRunner()
    # `--help` exits before any reactor runs, so we just check parsing.
    result = runner.invoke(cmd_receive, ["-o", str(tmp_path), "--help"])
    assert result.exit_code == 0


# --- filename-validation handoff ---


def test_resolve_passes_sender_name_through_unchanged_when_dir_mode(tmp_path):
    """In directory-parent mode, the sender's filename hardening
    (NUL/control/Windows-reserved/RTL etc.) is the only filename
    check. The resolver doesn't second-guess the sender's name."""
    parent_dir = tmp_path / "scratch"
    parent_dir.mkdir()
    parent, name = _resolve_output_target(str(parent_dir), "weird-but-valid-name.pdf")
    assert name == "weird-but-valid-name.pdf"

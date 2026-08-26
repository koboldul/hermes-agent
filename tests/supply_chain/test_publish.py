"""Behavioral tests for archive-member validation and atomic publication.

Archive validation is exercised over ``ArchiveMember`` data so it is
host-independent (no fake host OS). Publication uses real temp directories.
"""

from __future__ import annotations

import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from hermes_cli.supply_chain.errors import VerificationError
from hermes_cli.supply_chain.publish import (
    ArchiveMember,
    atomic_publish,
    compute_sha256,
    iter_tar_members,
    iter_zip_members,
    validate_archive_members,
)


def _dir(name: str) -> ArchiveMember:
    return ArchiveMember(name=name, is_dir=True)


def _file(name: str) -> ArchiveMember:
    return ArchiveMember(name=name, is_file=True)


def _symlink(name: str, target: str) -> ArchiveMember:
    return ArchiveMember(name=name, is_symlink=True, linkname=target)


# --- member validation ----------------------------------------------------

def test_clean_single_root_validates():
    members = [_dir("node-v22/"), _file("node-v22/bin/node"), _file("node-v22/README.md")]
    assert validate_archive_members(members) == "node-v22"


def test_absolute_path_is_rejected():
    with pytest.raises(VerificationError):
        validate_archive_members([_file("/etc/passwd")])


def test_drive_qualified_path_is_rejected():
    with pytest.raises(VerificationError):
        validate_archive_members([_file("C:\\Windows\\system32\\evil.dll")])


def test_parent_traversal_is_rejected():
    with pytest.raises(VerificationError):
        validate_archive_members([_file("node-v22/../../evil")])


def test_multiple_roots_are_rejected():
    with pytest.raises(VerificationError):
        validate_archive_members([_file("node-v22/a"), _file("other/b")])


def test_unexpected_root_is_rejected():
    with pytest.raises(VerificationError):
        validate_archive_members([_file("evil/a")], expected_root="node-v22")


def test_special_file_is_rejected():
    with pytest.raises(VerificationError):
        validate_archive_members([ArchiveMember(name="node-v22/dev", is_special=True)])


def test_hard_link_is_rejected():
    with pytest.raises(VerificationError):
        validate_archive_members([ArchiveMember(name="node-v22/x", is_hardlink=True, linkname="node-v22/y")])


def test_symlink_rejected_when_not_allowed():
    members = [_dir("node-v22/"), _symlink("node-v22/bin/npm", "../lib/node_modules/npm/bin/npm-cli.js")]
    with pytest.raises(VerificationError):
        validate_archive_members(members)


def test_internal_symlink_allowed_when_permitted():
    members = [
        _dir("node-v22/"),
        _dir("node-v22/bin/"),
        _symlink("node-v22/bin/npm", "../lib/node_modules/npm/bin/npm-cli.js"),
    ]
    assert validate_archive_members(members, allow_symlinks=True) == "node-v22"


def test_escaping_symlink_rejected_even_when_allowed():
    members = [_dir("node-v22/"), _symlink("node-v22/bin/x", "../../../../etc/passwd")]
    with pytest.raises(VerificationError):
        validate_archive_members(members, allow_symlinks=True)


def test_absolute_symlink_target_rejected():
    members = [_dir("node-v22/"), _symlink("node-v22/bin/x", "/etc/passwd")]
    with pytest.raises(VerificationError):
        validate_archive_members(members, allow_symlinks=True)


def test_chained_symlink_alias_escape_rejected():
    # root/a -> . aliases the root dir; root/a/b -> ../evil then lexically looks
    # in-root but physically lands in root's parent. Must be rejected.
    members = [
        _dir("root/"),
        _symlink("root/a", "."),
        _symlink("root/a/b", "../evil"),
    ]
    with pytest.raises(VerificationError):
        validate_archive_members(members, allow_symlinks=True)


def test_deep_chained_alias_escape_rejected():
    members = [
        _dir("root/"),
        _symlink("root/a", "."),
        _symlink("root/a/b", "."),
        _symlink("root/a/b/c", "."),
        _symlink("root/a/b/c/d", "../../../etc/cron.d/evil"),
    ]
    with pytest.raises(VerificationError):
        validate_archive_members(members, allow_symlinks=True)


def test_regular_member_under_symlink_dir_rejected():
    members = [
        _dir("root/"),
        _symlink("root/a", "."),
        _file("root/a/payload"),
    ]
    with pytest.raises(VerificationError):
        validate_archive_members(members, allow_symlinks=True)


def test_leaf_symlink_siblings_still_allowed():
    # Node's real shape: symlinks are leaves, never parents of other members.
    members = [
        _dir("node-v22/"),
        _dir("node-v22/bin/"),
        _file("node-v22/bin/node"),
        _symlink("node-v22/bin/npm", "../lib/node_modules/npm/bin/npm-cli.js"),
        _symlink("node-v22/bin/npx", "../lib/node_modules/npm/bin/npx-cli.js"),
    ]
    assert validate_archive_members(members, allow_symlinks=True) == "node-v22"


def test_empty_archive_rejected():
    with pytest.raises(VerificationError):
        validate_archive_members([])


# --- real zip/tar adapters ------------------------------------------------

def test_zip_adapter_and_validation(tmp_path):
    zip_path = tmp_path / "a.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("node-v22/bin/node.exe", "binary")
        zf.writestr("node-v22/npm.cmd", "script")
    with zipfile.ZipFile(zip_path) as zf:
        members = iter_zip_members(zf)
    assert validate_archive_members(members) == "node-v22"


def test_tar_adapter_with_traversal_rejected(tmp_path):
    tar_path = tmp_path / "a.tar"
    with tarfile.open(tar_path, "w") as tf:
        data = tmp_path / "payload"
        data.write_text("x")
        tf.add(data, arcname="../escape")
    with tarfile.open(tar_path) as tf:
        members = iter_tar_members(tf)
    with pytest.raises(VerificationError):
        validate_archive_members(members)


# --- digest ---------------------------------------------------------------

def test_compute_sha256(tmp_path):
    import hashlib

    payload = b"hermes"
    target = tmp_path / "f"
    target.write_bytes(payload)
    assert compute_sha256(target) == hashlib.sha256(payload).hexdigest()


# --- atomic publish -------------------------------------------------------

def _tree(root: Path, marker: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "marker.txt").write_text(marker, encoding="utf-8")
    return root


def test_publish_into_empty_target(tmp_path):
    staged = _tree(tmp_path / "staged", "new")
    target = tmp_path / "live"
    result = atomic_publish(staged, target)
    assert result.published
    assert (target / "marker.txt").read_text() == "new"


def test_publish_swaps_existing_tree(tmp_path):
    staged = _tree(tmp_path / "staged", "new")
    target = _tree(tmp_path / "live", "old")
    result = atomic_publish(staged, target)
    assert result.published
    assert (target / "marker.txt").read_text() == "new"


def test_in_use_defers_and_preserves_live_tree(tmp_path):
    staged = _tree(tmp_path / "staged", "new")
    target = _tree(tmp_path / "live", "old")
    result = atomic_publish(staged, target, in_use=True)
    assert result.deferred and not result.published
    assert (target / "marker.txt").read_text() == "old"  # untouched
    assert not staged.exists()  # staged tree cleaned up


def test_rollback_on_publish_failure_preserves_live_tree(tmp_path, monkeypatch):
    staged = _tree(tmp_path / "staged", "new")
    target = _tree(tmp_path / "live", "old")

    real_replace = os.replace
    calls = {"n": 0}

    def flaky_replace(src, dst):
        calls["n"] += 1
        # First call renames live -> backup (allow). Second call (staged ->
        # target) fails, forcing rollback.
        if calls["n"] == 2:
            raise OSError("simulated rename failure")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)
    result = atomic_publish(staged, target)
    assert result.rolled_back and not result.published
    assert target.exists()
    assert (target / "marker.txt").read_text() == "old"  # rolled back

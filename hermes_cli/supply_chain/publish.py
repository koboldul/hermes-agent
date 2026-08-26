"""Archive-member validation and atomic publication.

Two reusable primitives every extract-and-swap installer needs:

* :func:`validate_archive_members` — a **pure**, host-independent check over a
  normalized member list. It rejects absolute/drive-qualified paths, ``..``
  traversal, unexpected multiple roots, special files, and hard links, and
  permits only relative symlinks whose fully-resolved target stays inside the
  single validated top-level root (Node's POSIX archives need ``bin/npm`` and
  ``bin/npx`` symlinks, so a blanket link ban would break the runtime). Taking
  members as data keeps it testable without fabricating a host OS.
* :func:`atomic_publish` — stage → back up the live tree → swap in the staged
  tree → clean up, rolling back on any failure so an interrupted publish can
  never gut a working install.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

from .errors import VerificationError


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    is_dir: bool = False
    is_file: bool = False
    is_symlink: bool = False
    is_hardlink: bool = False
    is_special: bool = False
    linkname: str | None = None


def iter_zip_members(archive: zipfile.ZipFile) -> list[ArchiveMember]:
    members: list[ArchiveMember] = []
    for info in archive.infolist():
        mode = (info.external_attr >> 16) & 0xFFFF
        is_symlink = bool(mode) and (mode & 0xF000) == 0xA000
        is_dir = info.is_dir()
        members.append(
            ArchiveMember(
                name=info.filename,
                is_dir=is_dir,
                is_file=not is_dir and not is_symlink,
                is_symlink=is_symlink,
                linkname=None,
            )
        )
    return members


def iter_tar_members(archive: tarfile.TarFile) -> list[ArchiveMember]:
    members: list[ArchiveMember] = []
    for info in archive.getmembers():
        members.append(
            ArchiveMember(
                name=info.name,
                is_dir=info.isdir(),
                is_file=info.isfile(),
                is_symlink=info.issym(),
                is_hardlink=info.islnk(),
                is_special=info.ischr() or info.isblk() or info.isfifo() or info.isdev(),
                linkname=info.linkname or None,
            )
        )
    return members


def _is_absolute_or_drive(name: str) -> bool:
    if name.startswith(("/", "\\")):
        return True
    if name.startswith(("\\\\", "//")):  # UNC
        return True
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():  # C:\ / C:/
        return True
    return False


def _relative_parts(name: str) -> list[str]:
    """Split a member name into components, rejecting traversal.

    Raises when the name is absolute/drive-qualified or contains a ``..``
    component. Backslashes are treated as separators so a Windows-style entry
    cannot smuggle traversal past a POSIX split.
    """
    if _is_absolute_or_drive(name):
        raise VerificationError(f"archive member has absolute path: {name!r}")
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise VerificationError(f"archive member escapes tree: {name!r}")
    return parts


def _symlink_escapes_root(member_parts: list[str], linkname: str, root: str) -> bool:
    """Return True when a relative symlink would resolve outside *root*."""
    if _is_absolute_or_drive(linkname):
        return True
    base = PurePosixPath(*member_parts[:-1]) if len(member_parts) > 1 else PurePosixPath()
    resolved: list[str] = list(base.parts)
    for part in linkname.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                return True  # climbs above the archive root
            resolved.pop()
        else:
            resolved.append(part)
    if not resolved:
        return True
    return resolved[0] != root


def validate_archive_members(
    members: Iterable[ArchiveMember],
    *,
    expected_root: str | None = None,
    allow_symlinks: bool = False,
    require_single_root: bool = True,
) -> str | None:
    """Validate archive members and return the single top-level root name.

    Raises :class:`VerificationError` on any disallowed member so the caller
    aborts *before* extraction. With *require_single_root* False a flat archive
    with several top-level entries (e.g. an Electron release ZIP: ``electron``,
    ``resources/``, ``locales/`` …) is permitted — every other safety check
    (absolute/traversal/special/hardlink/symlink-escape) still applies; the
    return value is then the sole root when there is exactly one, else ``None``.
    """
    members = list(members)
    if not members:
        raise VerificationError("archive is empty")

    roots: set[str] = set()
    normalized: list[tuple[ArchiveMember, list[str]]] = []
    for member in members:
        parts = _relative_parts(member.name)
        if not parts:
            continue  # the archive's own root entry ("./")
        if member.is_special:
            raise VerificationError(f"archive contains special file: {member.name!r}")
        if member.is_hardlink:
            raise VerificationError(f"archive contains hard link: {member.name!r}")
        roots.add(parts[0])
        normalized.append((member, parts))

    if not normalized:
        raise VerificationError("archive has no extractable members")
    if require_single_root or expected_root is not None:
        if len(roots) != 1:
            raise VerificationError(f"archive has multiple top-level roots: {sorted(roots)}")
        root = next(iter(roots))
        if expected_root is not None and root != expected_root:
            raise VerificationError(
                f"archive root {root!r} does not match expected {expected_root!r}"
            )
    else:
        root = next(iter(roots)) if len(roots) == 1 else None

    # Reject any member that descends through a symlinked directory. An earlier
    # symlink member can alias its directory anywhere, so a purely lexical target
    # check on a later member is meaningless — a chain of `.`-alias symlinks
    # (root/a -> ., root/a/b -> ../evil) otherwise climbs arbitrarily far above
    # root while each hop "looks" in-root. Legitimate archives (Node's POSIX
    # tree) only ship symlinks as leaf files, never as parents of other members,
    # so this never rejects a supported runtime.
    symlink_prefixes = {tuple(parts) for member, parts in normalized if member.is_symlink}
    if symlink_prefixes:
        for member, parts in normalized:
            for depth in range(1, len(parts)):
                if tuple(parts[:depth]) in symlink_prefixes:
                    raise VerificationError(
                        f"archive member {member.name!r} descends through symlink "
                        f"{'/'.join(parts[:depth])!r}"
                    )

    for member, parts in normalized:
        if not member.is_symlink:
            continue
        if not allow_symlinks:
            raise VerificationError(f"archive contains symlink: {member.name!r}")
        if not member.linkname:
            raise VerificationError(f"symlink has no target: {member.name!r}")
        if _symlink_escapes_root(parts, member.linkname, root):
            raise VerificationError(
                f"symlink {member.name!r} escapes root via {member.linkname!r}"
            )
    return root


def compute_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class PublishResult:
    published: bool
    rolled_back: bool
    deferred: bool
    reason: str | None = None
    backup: str | None = None
    created: bool = False


def atomic_publish(
    staged_dir: str | Path,
    target_dir: str | Path,
    *,
    token: str | None = None,
    in_use: bool = False,
    keep_backup: bool = False,
) -> PublishResult:
    """Swap *staged_dir* into *target_dir* transactionally.

    The live tree is renamed to a sibling backup before the staged tree is
    moved into place; any failure rolls the live tree back. When *in_use* is
    True the swap is deferred and the staged tree removed, leaving the live
    tree untouched (callers translate this into a "try again later" signal).

    When *keep_backup* is True the previous tree's backup is RETAINED (its path
    returned in :attr:`PublishResult.backup`, or :attr:`created` set when there
    was no previous tree) so a caller running a larger transaction can
    :func:`rollback_publish` the swap if a *later* step (e.g. the anti-rollback
    state commit) fails, then :func:`finalize_publish` once that step succeeds.
    With the default *keep_backup* False the backup is cleaned up in place.
    """
    staged = Path(staged_dir)
    target = Path(target_dir)
    token = token or uuid.uuid4().hex[:8]
    backup = target.parent / f"{target.name}.old-{token}"

    if not target.exists():
        try:
            os.replace(str(staged), str(target))
            return PublishResult(published=True, rolled_back=False, deferred=False, created=True)
        except OSError as exc:
            shutil.rmtree(staged, ignore_errors=True)
            return PublishResult(False, False, False, reason=str(exc))

    if in_use:
        shutil.rmtree(staged, ignore_errors=True)
        return PublishResult(False, False, True, reason="target in use")

    try:
        os.replace(str(target), str(backup))
    except OSError as exc:
        # The OS refuses to move the live tree: a running process holds it.
        shutil.rmtree(staged, ignore_errors=True)
        return PublishResult(False, False, True, reason=f"target locked: {exc}")

    try:
        os.utime(backup, None)
    except OSError:
        pass

    try:
        os.replace(str(staged), str(target))
    except OSError as exc:
        try:
            os.replace(str(backup), str(target))  # roll the live tree back
        except OSError:
            pass
        shutil.rmtree(staged, ignore_errors=True)
        return PublishResult(False, True, False, reason=str(exc))

    if keep_backup:
        return PublishResult(published=True, rolled_back=False, deferred=False, backup=str(backup))
    shutil.rmtree(backup, ignore_errors=True)
    return PublishResult(published=True, rolled_back=False, deferred=False)


def finalize_publish(result: PublishResult) -> None:
    """Remove a retained backup after a dependent step (the anti-rollback state
    commit) succeeded — the swap is now permanent. Idempotent/no-op when no
    backup was retained (a fresh publish that created the target)."""
    if result.backup:
        shutil.rmtree(result.backup, ignore_errors=True)


def rollback_publish(result: PublishResult, target_dir: str | Path) -> bool:
    """Undo a ``keep_backup=True`` publish whose dependent step failed.

    Restores the previous tree from the retained backup (a failed commit must
    leave the OLD working install in place), or removes the newly-created target
    when there was no previous install. Returns True when the previous state was
    restored/removed. Never raises — a rollback runs on an error path."""
    target = Path(target_dir)
    if result.created:
        shutil.rmtree(target, ignore_errors=True)
        return True
    if result.backup and Path(result.backup).exists():
        shutil.rmtree(target, ignore_errors=True)
        try:
            os.replace(str(result.backup), str(target))
            return True
        except OSError:
            return False
    return False

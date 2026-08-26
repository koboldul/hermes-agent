"""Managed-artifact provenance markers (WP4 A6).

A binary living in Hermes-managed storage (``$HERMES_HOME/bin`` etc.) may be
EXECUTED only when it carries a *current* provenance marker whose recorded
sha256 matches the file's bytes. The marker is a sidecar written at the moment
Hermes places the binary, recording the component, version, digest, and how it
was obtained (release-verified digest, or an explicit operator compatibility
opt-in).

Enforcement:

* **Unmarked** managed file (legacy — installed before this system, or by some
  other process) → IGNORED. It is never executed. The resolver falls back to a
  separately-resolved operator ``PATH`` binary (used in place), or fails closed
  pending an explicit re-approval.
* **Marked but digest mismatch** (tampered / partially-written / swapped) →
  IGNORED, same as unmarked.
* **Marked and digest matches** → may be used.

This closes the gap where a legacy managed binary with no current provenance is
executed just because it exists on disk.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

from .publish import compute_sha256

MARKER_SUFFIX = ".provenance.json"
_MARKER_SCHEMA = 1


def marker_path(binary: str | Path) -> Path:
    binary = Path(binary)
    return binary.with_name(binary.name + MARKER_SUFFIX)


def write_marker(
    binary: str | Path,
    *,
    component: str,
    version: str,
    provenance: str,
    digest: str | None = None,
    archive_digest: str | None = None,
) -> Path:
    """Record a provenance marker for a managed *binary* (atomic write).

    ``provenance`` describes how the bytes were obtained, e.g.
    ``"release_verified:sha256"`` or ``"operator_compat_opt_in"``. ``digest``
    defaults to the file's current sha256 and is the value re-checked on every
    execution (a swapped/tampered binary no longer matches). ``archive_digest``
    optionally records the sha256 of the source archive the binary was
    extracted from (provenance for tree-style components such as Node), binding
    component/version/archive-digest alongside the executable digest.
    """
    binary = Path(binary)
    payload = {
        "schema": _MARKER_SCHEMA,
        "component": str(component),
        "version": str(version),
        "digest": {"algorithm": "sha256", "value": digest or compute_sha256(binary)},
        "provenance": str(provenance),
        "marked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if archive_digest:
        payload["archive_digest"] = {"algorithm": "sha256", "value": str(archive_digest)}
    target = marker_path(binary)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, target)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return target


def verify_marked(binary: str | Path, *, component: str | None = None) -> tuple[bool, str]:
    """Return ``(ok, reason)``. ``ok`` is True only when *binary* has a current
    marker whose digest matches the file (and component matches if supplied)."""
    binary = Path(binary)
    if not binary.exists():
        return False, "managed binary does not exist"
    mp = marker_path(binary)
    if not mp.exists():
        return False, "unmarked legacy managed artifact (no provenance marker)"
    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"unreadable provenance marker: {exc}"
    recorded = str(((data or {}).get("digest") or {}).get("value") or "")
    if not recorded:
        return False, "provenance marker has no digest"
    try:
        actual = compute_sha256(binary)
    except OSError as exc:
        return False, f"cannot hash managed binary: {exc}"
    if actual.lower() != recorded.lower():
        return False, "managed binary digest does not match its provenance marker (tampered/stale)"
    if component is not None and str(data.get("component")) != str(component):
        return False, f"provenance marker component {data.get('component')!r} != {component!r}"
    return True, "current provenance marker verified"


def managed_ok(binary: str | Path, *, component: str | None = None) -> bool:
    return verify_marked(binary, component=component)[0]


QUARANTINE_SUBDIR = ".sc-quarantine"


def verified_managed_or_none(binary: str | Path, *, component: str) -> Optional[str]:
    """Return ``str(binary)`` only when it exists AND carries a current marker.

    Read-only resolve check (no side effects). An unmarked/tampered managed
    binary yields ``None`` so the caller falls back to an operator-PATH binary
    used in place, or fails closed — it is never executed on existence alone.
    """
    b = Path(binary)
    if b.exists() and managed_ok(b, component=component):
        return str(b)
    return None


def quarantine_unmarked(binary: str | Path, *, component: str) -> Optional[Path]:
    """Move an unmarked/tampered managed *binary* into a quarantine dir so it can
    never be executed, returning the quarantine path.

    Returns ``None`` when the binary is absent or already carries a current
    marker (nothing to quarantine). This is the "refuse the invalid legacy
    target BEFORE the installer fallback" step: an installer must call it before
    any existence-based short-circuit so a stale binary can't be returned or
    executed, and a fresh verified install can take its place.
    """
    b = Path(binary)
    if not b.exists():
        return None
    if managed_ok(b, component=component):
        return None
    qdir = b.parent / QUARANTINE_SUBDIR
    try:
        qdir.mkdir(parents=True, exist_ok=True)
        dest = qdir / f"{b.name}.{component}.{int(time.time())}.{os.getpid()}"
        os.replace(str(b), str(dest))
    except OSError:
        # Best-effort: if the move fails, at least drop any stale marker so the
        # binary cannot be mistaken for verified on a later resolve.
        try:
            mp = marker_path(b)
            if mp.exists():
                mp.unlink()
        except OSError:
            pass
        return None
    # Carry any stale marker sidecar into quarantine too.
    mp = marker_path(b)
    if mp.exists():
        try:
            os.replace(str(mp), str(dest) + MARKER_SUFFIX)
        except OSError:
            pass
    return dest


def resolve_managed_or_operator(
    managed_binary: str | Path | None,
    *,
    component: str,
    operator_probe: Callable[[], Optional[str]] | None = None,
) -> Optional[str]:
    """Resolve an executable for *component*, honouring the A6 policy.

    Order:
      1. A managed binary WITH a current provenance marker → use it.
      2. Otherwise a separately-resolved operator ``PATH`` binary → use in place.
      3. Otherwise ``None`` (caller fails closed / re-approves).

    An unmarked or tampered managed binary is deliberately skipped in favour of
    the operator binary, never executed on the strength of merely existing.
    """
    if managed_binary is not None:
        mb = Path(managed_binary)
        if mb.exists() and managed_ok(mb, component=component):
            return str(mb)
    if operator_probe is not None:
        op = operator_probe()
        if op:
            return op
    return None


# --- managed-alias bypass defence (A6, third re-review) -------------------
#
# An operator/PATH fallback (shutil.which, ~/.local/bin, etc.) can resolve to a
# path that is ACTUALLY a Hermes-managed binary reached via PATH, a symlink, a
# junction, or a Windows case-variant. Executing it as an "operator" binary
# bypasses the marker check. Every operator fallback must canonicalize the
# realpath (case-insensitive on Windows) and, if it lands inside ANY managed
# root, accept it only when the provenance marker verifies.

def _canon(path: str | Path) -> str:
    """Case-normalized realpath (resolves symlinks/junctions)."""
    try:
        return os.path.normcase(os.path.realpath(str(path)))
    except OSError:
        return os.path.normcase(os.path.abspath(str(path)))


# Managed subdirectories inside a single Hermes home where an executable / tool
# environment / browser payload lives. Any binary reached (via PATH, symlink,
# junction, or case alias) inside one of these — for ANY profile — is a managed
# artifact and must present a current provenance marker before it is executed.
_MANAGED_SUBDIRS = ("bin", "uv-tools", "cache", "browsers")


def _managed_subroots(base: Path) -> list[Path]:
    subs = [base / name for name in _MANAGED_SUBDIRS]
    try:
        from hermes_constants import iter_hermes_node_dirs

        subs += list(iter_hermes_node_dirs(base))
    except Exception:
        subs += [base / "node", base / "node" / "bin"]
    return subs


def _hermes_home_bases(active_home=None) -> list[Path]:
    """Every legitimate Hermes home whose managed roots must be trusted-gated.

    Enumerates, independent of the active ``HERMES_HOME``:
      * the active home (may be a custom/Docker path outside the default root);
      * the default root AND every real ``<default_root>/profiles/<name>``;
      * the native platform default home AND its profiles (covers a custom
        active home that still shares the box with native-home profiles).

    Only real, enumerated profile directories are added — no arbitrary path is
    trusted just because it sits under ``profiles/``.
    """
    bases: list[Path] = []

    def _add(p: Path) -> None:
        bases.append(Path(p))

    def _add_root_and_profiles(root: Path) -> None:
        _add(root)
        profiles_dir = Path(root) / "profiles"
        try:
            if profiles_dir.is_dir():
                for child in sorted(profiles_dir.iterdir()):
                    if child.is_dir():
                        _add(child)
        except OSError:
            pass

    try:
        from hermes_constants import get_hermes_home

        _add(Path(active_home) if active_home is not None else get_hermes_home())
    except Exception:
        if active_home is not None:
            _add(Path(active_home))

    for resolver in ("get_default_hermes_root", "_get_platform_default_hermes_home"):
        try:
            import hermes_constants as _hc

            fn = getattr(_hc, resolver, None)
            if fn is not None:
                _add_root_and_profiles(Path(fn()))
        except Exception:
            continue
    return bases


def hermes_managed_roots(home=None) -> list[Path]:
    """Every directory where ANY Hermes profile keeps managed executables.

    Independent of the active ``HERMES_HOME``: includes the default root AND
    every enumerated ``<root>/profiles/<name>`` managed root (bin / node /
    uv-tools / cache / browsers), so a secondary profile can never execute the
    DEFAULT (or a sibling) profile's managed binary — reached via a PATH /
    symlink / junction / case alias — as if it were an operator binary.
    """
    roots: list[Path] = []
    seen: set[str] = set()

    def _push(p: Path) -> None:
        key = _canon(p)
        if key not in seen:
            seen.add(key)
            roots.append(Path(p))

    for base in _hermes_home_bases(home):
        for sub in _managed_subroots(base):
            _push(sub)

    # Explicit uv tool dirs from the active env (may point outside the homes).
    for env_key in ("UV_TOOL_BIN_DIR", "UV_TOOL_DIR"):
        val = os.environ.get(env_key)
        if val:
            _push(Path(val))
    return roots


def is_under_managed_root(path: str | Path, *, home=None) -> bool:
    """True when *path* resolves (realpath, case-insensitive) inside a managed
    root — even via a symlink/junction/PATH/case-variant alias."""
    real = _canon(path)
    for root in hermes_managed_roots(home):
        root_real = _canon(root)
        try:
            if real == root_real or os.path.commonpath([real, root_real]) == root_real:
                return True
        except ValueError:  # different drives on Windows
            continue
    return False


def accept_operator_path(
    candidate: str | Path | None,
    *,
    component: str,
    verify: Callable[[str], bool] | None = None,
    home=None,
) -> Optional[str]:
    """Gate an operator/PATH-resolved executable against the managed-alias
    bypass.

    * ``None``/empty → ``None``.
    * If *candidate* resolves INTO a Hermes-managed root (PATH/symlink/junction/
      case alias), it is a MANAGED binary — return it only when its provenance
      marker verifies (``verify`` override, else :func:`managed_ok` on the real
      path); otherwise reject (``None``).
    * A genuine operator path is returned unchanged.
    """
    if not candidate:
        return None
    if is_under_managed_root(candidate, home=home):
        real = _canon(candidate)
        ok = verify(real) if verify is not None else managed_ok(real, component=component)
        return str(candidate) if ok else None
    return str(candidate)


# --- uv-tool marker: binds the launcher AND the whole tool environment tree ---
#
# `uv tool install X` writes a small launcher in UV_TOOL_BIN_DIR and the actual
# package venv in UV_TOOL_DIR/<tool>. A marker on the launcher alone leaves the
# code that runs (the tool tree) unverified. write_tool_marker/tool_marker_ok
# bind BOTH: the launcher bytes and a deterministic digest over the entire tool
# tree, and the resolver rehashes both.

def compute_tree_digest(tree_dir: str | Path) -> str:
    """Deterministic sha256 over a directory tree: sorted relative paths tagged
    by kind (file digest / symlink target / dir), so any add/remove/edit/relink
    changes the digest. An absent tree is a distinct sentinel.

    Provenance marker sidecars (``*.provenance.json``) and the quarantine subdir
    are EXCLUDED so a tree's digest is independent of its own marker — the node
    tree keeps its marker inside the tree it certifies, which would otherwise be
    circular — and stable across quarantine churn."""
    tree = Path(tree_dir)
    if not tree.is_dir():
        return "sha256:absent"
    h = hashlib.sha256()
    for p in sorted(tree.rglob("*"), key=lambda x: x.relative_to(tree).as_posix()):
        relpath = p.relative_to(tree)
        if p.name.endswith(MARKER_SUFFIX) or QUARANTINE_SUBDIR in relpath.parts:
            continue
        rel = relpath.as_posix().encode("utf-8")
        try:
            if p.is_symlink():
                h.update(b"L\0"); h.update(rel); h.update(b"\0")
                h.update(str(os.readlink(p)).encode("utf-8", "surrogatepass")); h.update(b"\0")
            elif p.is_file():
                h.update(b"F\0"); h.update(rel); h.update(b"\0")
                h.update(compute_sha256(p).encode()); h.update(b"\0")
            elif p.is_dir():
                h.update(b"D\0"); h.update(rel); h.update(b"\0")
        except OSError:
            h.update(b"?\0"); h.update(rel); h.update(b"\0")
    return "sha256:" + h.hexdigest()


def write_tool_marker(
    launcher: str | Path,
    *,
    tree_dir: str | Path,
    component: str,
    version: str,
    provenance: str,
) -> Path:
    """Atomically write a provenance marker on a uv-tool *launcher* that binds
    both the launcher bytes and the entire tool *tree_dir* digest."""
    launcher = Path(launcher)
    payload = {
        "schema": _MARKER_SCHEMA,
        "component": str(component),
        "version": str(version),
        "digest": {"algorithm": "sha256", "value": compute_sha256(launcher)},
        "tool_tree": {"path": str(tree_dir), "digest": compute_tree_digest(tree_dir)},
        "provenance": str(provenance),
        "marked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    target = marker_path(launcher)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, target)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return target


# The full tool environment tree is rehashed on EVERY resolve/execution — there
# is NO caching. A per-process cache keyed by the launcher's size+mtime (the
# previous design) could not see a package file mutated in place while the
# launcher was untouched, so a same-process attacker who swapped a .py inside
# the venv would pass every check after the first. With no filesystem watcher to
# invalidate such a cache on mutation, a whole-venv rehash on each call is the
# only sound guarantee.


def tool_marker_ok(launcher: str | Path, *, tree_dir: str | Path, component: str) -> bool:
    """True only when *launcher* carries a current marker whose launcher digest
    AND recorded tool-tree digest both still verify.

    The entire tool environment tree is rehashed on every call (no cache): an
    in-place mutation of any file in the venv changes :func:`compute_tree_digest`
    and is rejected even within a single process."""
    launcher = Path(launcher)
    ok, _ = verify_marked(launcher, component=component)
    if not ok:
        return False
    mp = marker_path(launcher)
    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    recorded = str(((data or {}).get("tool_tree") or {}).get("digest") or "")
    if not recorded:
        return False
    return compute_tree_digest(tree_dir) == recorded

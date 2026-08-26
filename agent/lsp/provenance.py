"""Provenance markers and mutation rejection for managed LSP binaries.

SEC-AUDIT-002: a language server installed into ``HERMES_HOME/lsp`` must not be
trusted merely because a file exists there.  Every auto-installed binary is
bound to a provenance marker that records the reviewed manifest identity, the
committed lock digest, and a digest of the installed executable.  Resolution
refuses to launch a managed binary unless a marker verifies against the current
manifest and the on-disk executable is byte-for-byte the one that was
installed.

Two trust sources exist:

* ``managed`` — installed by Hermes from the locked manifest.  Verified against
  :func:`agent.lsp.manifest.manifest_identity`.
* ``reapproved`` — an operator explicitly re-approved an exact path.  Bound to
  that exact path and the executable's digest, so any later mutation is
  rejected.

A pre-remediation managed tree carries no marker; it is treated as unverified
and refused in both ``manual`` and ``auto`` modes until reinstalled or
explicitly re-approved.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import errno
import time
from pathlib import Path
from typing import Any, Dict, Optional

from agent.lsp import manifest as _manifest

logger = logging.getLogger("agent.lsp.provenance")

MARKER_SCHEMA_VERSION = 1


def installed_marker_dir() -> Path:
    from hermes_constants import get_hermes_home

    d = get_hermes_home() / "lsp" / "installed"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _marker_path(server_id: str) -> Path:
    safe = server_id.replace("/", "__").replace("@", "at__")
    return installed_marker_dir() / f"{safe}.json"


def file_digest(path: str | os.PathLike[str]) -> Optional[str]:
    """Return ``sha256:<hex>`` of a file's bytes (following symlinks)."""
    try:
        real = os.path.realpath(path)
        h = hashlib.sha256()
        with open(real, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return "sha256:" + h.hexdigest()
    except OSError:
        return None


def read_marker(server_id: str) -> Optional[Dict[str, Any]]:
    p = _marker_path(server_id)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _atomic_write(path: Path, payload: Dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}-{os.urandom(4).hex()}")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    # Retry the publish rename for transient Windows sharing/access errors
    # (antivirus scan of the just-written temp file) so marker publication is
    # not lost after a successful install.
    last: Optional[BaseException] = None
    for i in range(40):
        try:
            os.replace(tmp, path)
            return
        except OSError as e:
            winerr = getattr(e, "winerror", None)
            transient = (
                winerr in {5, 32, 145}
                or isinstance(e, PermissionError)
                or getattr(e, "errno", None) in {errno.EACCES, errno.EPERM}
            )
            if not transient:
                raise
            last = e
            time.sleep(min(0.3, 0.03 * (1.4 ** i)))
    try:
        tmp.unlink()
    except OSError:
        pass
    if last is not None:
        raise last


def write_marker(
    recipe: "_manifest.LSPRecipe",
    bin_path: str,
    *,
    source: str = "managed",
    consent_version: Optional[int] = None,
) -> Dict[str, Any]:
    """Record a provenance marker for a freshly installed managed binary."""
    digest = file_digest(bin_path)
    if digest is None:
        raise RuntimeError(f"cannot digest installed binary at {bin_path}")
    try:
        lock_dig = _manifest.lock_digest(recipe)
    except _manifest.ManifestError:
        lock_dig = None
    payload: Dict[str, Any] = {
        "schema": MARKER_SCHEMA_VERSION,
        "server_id": recipe.server_id,
        "ecosystem": recipe.ecosystem,
        "package": recipe.server_id,
        "version": recipe.version,
        "bin": recipe.bin,
        "bin_path": os.path.abspath(bin_path),
        "bin_digest": digest,
        "lock_digest": lock_dig,
        "manifest_identity": _manifest.manifest_identity(recipe),
        "source": source,
        "consent_version": consent_version,
        "created_at": time.time(),
    }
    _atomic_write(_marker_path(recipe.server_id), payload)
    return payload


def record_reapproval(server_id: str, bin_path: str) -> Dict[str, Any]:
    """Operator explicitly re-approves an exact path, bound to its digest."""
    digest = file_digest(bin_path)
    if digest is None:
        raise RuntimeError(f"cannot digest binary at {bin_path}")
    payload = {
        "schema": MARKER_SCHEMA_VERSION,
        "server_id": server_id,
        "bin_path": os.path.abspath(bin_path),
        "bin_digest": digest,
        "manifest_identity": f"operator-reapproved:{server_id}",
        "source": "reapproved",
        "created_at": time.time(),
    }
    _atomic_write(_marker_path(server_id), payload)
    return payload


def clear_marker(server_id: str) -> None:
    try:
        _marker_path(server_id).unlink()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Compound-artifact re-approval (e.g. PowerShell: host interpreter + PSES
# bootstrap script).  BOTH components must be exact-path + digest bound; any
# mutation of either invalidates the whole marker.
# ---------------------------------------------------------------------------
def record_compound_reapproval(
    server_id: str, components: Dict[str, str]
) -> Dict[str, Any]:
    """Re-approve a compound server: each named component (path) is bound to
    its exact absolute path and current digest."""
    comp: Dict[str, Any] = {}
    for name, path in components.items():
        digest = file_digest(path)
        if digest is None:
            raise RuntimeError(f"cannot digest {name} at {path}")
        comp[name] = {"path": os.path.abspath(path), "digest": digest}
    payload = {
        "schema": MARKER_SCHEMA_VERSION,
        "server_id": server_id,
        "source": "compound-reapproved",
        "components": comp,
        "created_at": time.time(),
    }
    _atomic_write(_marker_path(server_id), payload)
    return payload


def verify_compound_reapproved(server_id: str) -> Optional[Dict[str, str]]:
    """Return ``{name: path}`` iff EVERY compound component still exists and its
    digest is unchanged; ``None`` if the marker is absent or any component was
    moved or mutated."""
    marker = read_marker(server_id)
    if not marker or marker.get("source") != "compound-reapproved":
        return None
    comps = marker.get("components") or {}
    if not comps:
        return None
    resolved: Dict[str, str] = {}
    for name, meta in comps.items():
        path = meta.get("path")
        digest = meta.get("digest")
        if not path or not os.path.exists(path):
            return None
        if file_digest(path) != digest:
            return None  # mutation → reject the whole compound artifact
        resolved[name] = path
    return resolved


def marker_binary_valid(marker: Dict[str, Any]) -> bool:
    """True when the marker's binary exists and its digest is unchanged."""
    bin_path = marker.get("bin_path")
    if not bin_path or not os.path.exists(bin_path):
        return False
    current = file_digest(bin_path)
    return current is not None and current == marker.get("bin_digest")


def verify_managed(recipe: "_manifest.LSPRecipe") -> Optional[str]:
    """Return the managed binary path if a marker verifies, else ``None``.

    Verification requires: a marker exists, its recorded manifest identity
    matches the *current* reviewed manifest, and the on-disk executable digest
    matches the recorded digest (mutation rejection).
    """
    marker = read_marker(recipe.server_id)
    if not marker:
        return None
    if marker.get("source") == "reapproved":
        return marker["bin_path"] if marker_binary_valid(marker) else None
    if marker.get("source") == "compound-reapproved":
        return None  # compound artifacts resolve via verify_compound_reapproved
    if marker.get("manifest_identity") != _manifest.manifest_identity(recipe):
        return None
    if not marker_binary_valid(marker):
        return None
    return marker["bin_path"]


def verify_reapproved(server_id: str) -> Optional[str]:
    """Return an operator-re-approved path if its digest still matches."""
    marker = read_marker(server_id)
    if not marker or marker.get("source") != "reapproved":
        return None
    return marker["bin_path"] if marker_binary_valid(marker) else None


def integrity_state(recipe: "_manifest.LSPRecipe") -> str:
    """Human-facing integrity state for ``hermes lsp status``.

    One of: ``verified``, ``reapproved``, ``mutated``, ``unverified``,
    ``stale-identity``, ``none``.
    """
    return integrity_state_for(recipe.server_id, recipe)


def integrity_state_for(
    server_id: str, recipe: "Optional[_manifest.LSPRecipe]" = None
) -> str:
    marker = read_marker(server_id)
    if not marker:
        return "none"
    source = marker.get("source")
    if source == "compound-reapproved":
        return "reapproved" if verify_compound_reapproved(server_id) else "mutated"
    if source == "reapproved":
        return "reapproved" if marker_binary_valid(marker) else "mutated"
    if recipe is not None and marker.get("manifest_identity") != _manifest.manifest_identity(recipe):
        return "stale-identity"
    if not marker_binary_valid(marker):
        return "mutated"
    return "verified"


__all__ = [
    "MARKER_SCHEMA_VERSION",
    "installed_marker_dir",
    "file_digest",
    "read_marker",
    "write_marker",
    "record_reapproval",
    "clear_marker",
    "record_compound_reapproval",
    "verify_compound_reapproved",
    "marker_binary_valid",
    "verify_managed",
    "verify_reapproved",
    "integrity_state",
    "integrity_state_for",
]

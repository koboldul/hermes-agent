"""Persisted anti-rollback state.

An attacker who can replay a validly-signed *old* manifest, or force an
install of an older-but-vulnerable component version, defeats digest pinning.
The defence is a monotonic high-water mark stored on the machine:

* ``manifest_sequence`` — the highest manifest sequence ever accepted. A
  manifest whose sequence is below this is a replay/downgrade and is rejected.
* ``components`` — the last version published for each component, so a later
  run refuses to publish a strictly older version (below the last install or
  the manifest's security floor).

State is written atomically (temp + ``os.replace``) under the profile's
``HERMES_HOME`` so each profile keeps its own high-water mark.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .errors import StateCorruptError


# ── Cross-process advisory file lock (A9) ──────────────────────────────────
# The anti-rollback commit serializes a read-modify-write across processes with
# a REAL kernel advisory lock (fcntl.flock on POSIX, msvcrt.locking on Windows),
# not an O_CREAT|O_EXCL sentinel file. The kernel owns the lock, so:
#   * a crashed holder is released automatically — there is no stale-file
#     heuristic (the previous code compared time.monotonic() to a filesystem
#     st_mtime, i.e. an uptime clock against a wall-clock epoch, so its stale
#     detection was never valid), and
#   * a live holder is never displaced — the previous finally block unlinked the
#     sentinel unconditionally, including for a timed-out spinner that never
#     owned it, which let a second holder in and lost an update.
# The lock file is created once and is NEVER unlinked while it may be held:
# under flock, unlinking the file would let a new opener acquire a *different*
# inode's lock, producing two live holders. Leaving a tiny <state>.lock file in
# place is the correct, race-free behavior.

if os.name == "nt":  # pragma: no cover - platform-specific
    import msvcrt

    _LOCK_NEEDS_BYTE = True

    def _os_try_lock(fd: int) -> None:
        # Byte-range lock on byte 0 (non-blocking; raises OSError if held).
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _os_unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:  # pragma: no cover - platform-specific
    import fcntl

    _LOCK_NEEDS_BYTE = False

    def _os_try_lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _os_unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


_LOCK_OPEN_FLAGS = os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0)


def default_state_path() -> Path:
    """Return the profile-scoped anti-rollback state file path."""
    from hermes_constants import get_hermes_home

    return get_hermes_home() / "supply-chain" / "state.json"


@dataclass
class RollbackState:
    manifest_sequence: int = 0
    components: dict[str, str] = field(default_factory=dict)
    path: Path | None = field(default=None, compare=False)

    def to_dict(self) -> dict:
        return {
            "manifest_sequence": self.manifest_sequence,
            "components": dict(self.components),
        }


def _parse_state(raw_text: str, target: Path) -> RollbackState:
    raw = json.loads(raw_text)
    if not isinstance(raw, dict):
        raise ValueError("state root is not an object")
    seq = raw.get("manifest_sequence", 0)
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise ValueError("manifest_sequence must be a non-negative integer")
    components = raw.get("components") or {}
    if not isinstance(components, dict):
        raise ValueError("components must be an object")
    return RollbackState(
        manifest_sequence=int(seq),
        components={str(k): str(v) for k, v in components.items() if v is not None},
        path=target,
    )


def load_state(path: str | Path | None = None, *, strict: bool = False) -> RollbackState:
    """Load anti-rollback state.

    A missing file is normal (first run) → a zeroed state. A CORRUPT file is the
    dangerous case: silently zeroing it would reset the high-water mark and
    re-open replay/downgrade. With ``strict=True`` (the verifier's default) a
    corrupt file raises :class:`StateCorruptError` (fail closed, explicit
    recovery via :func:`reset_state`). With ``strict=False`` it degrades to a
    zeroed state for non-security callers.
    """
    target = Path(path) if path is not None else default_state_path()
    try:
        raw_text = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        return RollbackState(path=target)
    except OSError as exc:
        if strict:
            raise StateCorruptError(f"cannot read anti-rollback state {target}: {exc}") from exc
        return RollbackState(path=target)
    try:
        return _parse_state(raw_text, target)
    except (json.JSONDecodeError, ValueError) as exc:
        if strict:
            raise StateCorruptError(
                f"anti-rollback state {target} is corrupt ({exc}); refusing to reset "
                "the replay/downgrade high-water mark silently. Recover explicitly "
                "(remove/repair the file) — see docs/security/supply-chain-trust-root.md."
            ) from exc
        return RollbackState(path=target)


def save_state(state: RollbackState, path: str | Path | None = None) -> None:
    """Atomically persist *state*."""
    target = Path(path) if path is not None else (state.path or default_state_path())
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state.to_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_name, target)
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass


def reset_state(path: str | Path | None = None) -> RollbackState:
    """Explicit recovery: write a fresh zeroed state, replacing a corrupt file.

    The high-water mark starts at zero and can only be *raised* by legitimate
    accepts thereafter, so recovery cannot be used to force a downgrade — the
    next verified manifest re-establishes the mark.
    """
    target = Path(path) if path is not None else default_state_path()
    fresh = RollbackState(path=target)
    save_state(fresh, target)
    return fresh


@contextlib.contextmanager
def _cross_process_lock(target: Path, *, timeout: float = 10.0, poll: float = 0.01):
    """Hold an exclusive advisory lock on ``<state>.lock`` for a read-modify-write
    of the anti-rollback state.

    Uses a real kernel advisory lock (``fcntl.flock`` / ``msvcrt.locking``) so a
    crashed holder is released automatically (no stale-file heuristic) and a live
    holder is never displaced (no unlink-of-a-live-holder race). Acquisition is a
    bounded non-blocking retry; it **fails closed** with :class:`StateCorruptError`
    if the lock cannot be taken within *timeout*, so a commit never proceeds
    unserialized. The lock is released (and the descriptor closed) in ``finally``;
    the lock file itself is intentionally never unlinked.
    """
    lock_path = target.with_suffix(target.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), _LOCK_OPEN_FLAGS, 0o600)
    try:
        if _LOCK_NEEDS_BYTE:
            # msvcrt.locking needs a real byte at the locked offset (byte 0).
            # Only the first opener writes it; a write that races a holder's
            # mandatory lock is harmless (Windows can lock beyond EOF anyway).
            with contextlib.suppress(OSError):
                if os.fstat(fd).st_size < 1:
                    os.write(fd, b"\0")
        deadline = time.monotonic() + timeout
        while True:
            try:
                _os_try_lock(fd)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise StateCorruptError(
                        f"could not acquire anti-rollback state lock {lock_path} "
                        f"within {timeout}s; another process may be committing — retry."
                    ) from None
                time.sleep(poll)
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                _os_unlock(fd)
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


def _version_tuple(version: str) -> tuple:
    parts: list = []
    for chunk in str(version).replace("-", ".").split("."):
        parts.append((0, int(chunk)) if chunk.isdigit() else (1, chunk))
    return tuple(parts)


def _is_below(candidate: str, floor: str) -> bool:
    try:
        return _version_tuple(str(candidate)) < _version_tuple(str(floor))
    except Exception:
        return False


def commit_state(
    *,
    manifest_sequence: int,
    components: dict[str, str] | None = None,
    path: str | Path | None = None,
) -> RollbackState:
    """Atomically raise the anti-rollback high-water mark under a cross-process
    lock (A9). Re-reads the current state under the lock (strict: corrupt fails
    closed), applies a monotonic max on the sequence and per-component version,
    then persists atomically. Returns the committed state.
    """
    target = Path(path) if path is not None else default_state_path()
    with _cross_process_lock(target):
        current = load_state(target, strict=True)
        if manifest_sequence > current.manifest_sequence:
            current.manifest_sequence = manifest_sequence
        for name, version in (components or {}).items():
            prior = current.components.get(name)
            # never lower a recorded version (rollback defence)
            if prior is None or _version_tuple(str(version)) >= _version_tuple(prior):
                current.components[name] = str(version)
        save_state(current, target)
        return current


def recheck_release(
    current: RollbackState,
    *,
    manifest_sequence: int,
    min_sequence: int = 0,
    component: tuple[str, str] | None = None,
    security_floor: str | None = None,
) -> None:
    """Lock-free anti-rollback recheck against an ALREADY-loaded *current* state.

    Raises :class:`ManifestError` on a below-min / replay-downgrade sequence, a
    component below its security floor, or a component rollback below the
    last-installed version. The caller must already hold the cross-process lock
    (this is the recheck half of the A6 publish transaction, run under the lock
    together with the publish + commit)."""
    from .errors import ManifestError

    if manifest_sequence < min_sequence:
        raise ManifestError(
            f"manifest sequence {manifest_sequence} below min {min_sequence}"
        )
    if manifest_sequence < current.manifest_sequence:
        raise ManifestError(
            f"manifest sequence {manifest_sequence} is a replay/downgrade below the "
            f"accepted high-water mark {current.manifest_sequence} (a concurrent "
            "commit advanced past it) — refusing to publish a stale manifest"
        )
    if component is not None:
        name, version = component
        if security_floor and _is_below(version, security_floor):
            raise ManifestError(
                f"{name} {version} is below the security floor {security_floor}"
            )
        prior = current.components.get(name)
        if prior and _is_below(version, prior):
            raise ManifestError(
                f"{name} {version} is a rollback below the last-installed {prior}"
            )


def apply_release_commit(
    current: RollbackState,
    *,
    manifest_sequence: int,
    component: tuple[str, str] | None = None,
) -> None:
    """Lock-free: raise *current*'s high-water sequence + record the component
    version (monotonic max). Does NOT recheck (call :func:`recheck_release`
    first) and does NOT persist. The caller (holding the lock) persists via
    :func:`save_state` after a SUCCESSFUL publish — never before."""
    if manifest_sequence > current.manifest_sequence:
        current.manifest_sequence = manifest_sequence
    if component is not None:
        name, version = component
        prior = current.components.get(name)
        if prior is None or _version_tuple(str(version)) >= _version_tuple(prior):
            current.components[name] = str(version)


def commit_release_state(
    *,
    manifest_sequence: int,
    min_sequence: int = 0,
    component: tuple[str, str] | None = None,
    security_floor: str | None = None,
    path: str | Path | None = None,
) -> RollbackState:
    """Transactional anti-rollback commit for a release-verified publish (A9).

    Under the cross-process lock, in one atomic read-modify-write:

    1. re-read the current state (strict: corrupt fails closed);
    2. RECHECK freshness/high-water *under the lock* — a manifest at/below a
       high-water mark that a concurrent commit advanced past is a
       replay/downgrade and raises :class:`ManifestError` (fail closed), rather
       than being silently ignored;
    3. RECHECK the component is not a rollback below its security floor or the
       last-installed version;
    4. only then raise the high-water mark + record the component and persist.

    This is the commit half of the guard PROCEED transaction: verify (root +
    freshness in :meth:`plan`) → publish (caller) → commit here. Holding the
    lock across the recheck+write closes the TOCTOU where two processes race a
    publish.
    """
    target = Path(path) if path is not None else default_state_path()
    with _cross_process_lock(target):
        current = load_state(target, strict=True)
        recheck_release(
            current,
            manifest_sequence=manifest_sequence,
            min_sequence=min_sequence,
            component=component,
            security_floor=security_floor,
        )
        apply_release_commit(
            current, manifest_sequence=manifest_sequence, component=component
        )
        save_state(current, target)
        return current

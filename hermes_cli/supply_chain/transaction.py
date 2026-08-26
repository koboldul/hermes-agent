"""A6 release-verified publication transaction.

The single correct ordering for publishing a ``release_verified`` artifact so a
concurrent, older-sequence publisher can NEVER overwrite a newer install:

  OUTSIDE the lock (slow, uncontended):
    download the artifact, validate its archive members, extract into a STAGE
    dir, and hash the downloaded bytes.

  UNDER ONE held cross-process advisory lock (fast, serialized):
    1. re-load the anti-rollback state (strict: corrupt fails closed);
    2. re-verify the COMPILED-IN trust root (a downloaded manifest that was not
       attested is refused HERE, never earlier);
    3. re-check freshness / high-water AND the component floor UNDER the lock — a
       sequence at/below a mark a concurrent commit advanced past is a
       replay/downgrade and raises;
    4. verify the staged bytes' sha256 equals the manifest's expected digest;
    5. atomically publish the staged tree into the target WITH rollback;
    6. ONLY on a successful publish, atomically commit the new sequence +
       component high-water — NEVER before the publish.

Invariants: never commit before publish; never publish outside the lock; never
overwrite a newer install (the under-lock recheck fails the stale publisher).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .errors import VerificationError
from .publish import atomic_publish
from .state import (
    _cross_process_lock,
    apply_release_commit,
    default_state_path,
    load_state,
    recheck_release,
    save_state,
)


@dataclass
class PublishTxnResult:
    published: bool
    committed: bool
    deferred: bool = False
    rolled_back: bool = False
    reason: str | None = None
    manifest_sequence: int | None = None


def _artifact_digest(artifact) -> Optional[str]:
    digest = getattr(artifact, "digest", None)
    if digest is not None and getattr(digest, "present", False):
        return str(digest.value)
    return None


def publish_release_verified(
    verifier,
    component,
    artifact,
    *,
    staged_sha256: str,
    stage_dir: str | Path,
    target_dir: str | Path,
    state_path: str | Path | None = None,
    in_use: bool = False,
    _publish: Callable = atomic_publish,
) -> PublishTxnResult:
    """Publish a staged ``release_verified`` artifact under the A6 transaction.

    *staged_sha256* is the sha256 of the downloaded bytes, computed OUTSIDE this
    call (before the lock). *stage_dir* is the staged tree ready to swap into
    *target_dir*. Steps 1-6 above all run under ONE held advisory lock.

    Raises :class:`ManifestError` / :class:`VerificationError` (fail closed) on a
    replay/downgrade, a rollback below floor/last-installed, an untrusted
    downloaded manifest, or a staged-digest mismatch — in every such case the
    target is NOT overwritten and the high-water mark is NOT advanced.
    """
    path = (
        Path(state_path)
        if state_path is not None
        else (verifier.state.path or default_state_path())
    )
    expected = _artifact_digest(artifact)
    seq = verifier.manifest.meta.sequence
    min_seq = verifier.manifest.meta.min_sequence

    with _cross_process_lock(path):
        # 1. reload the anti-rollback state UNDER the lock (corrupt fails closed)
        current = load_state(path, strict=True)
        verifier.state = current  # freshness re-reads the freshly-loaded mark

        # 2. re-verify the compiled-in trust root (raises for a downloaded,
        #    un-attested manifest — no self-declared identity gets here).
        verifier.verify_trust_root()

        # 3. re-check freshness/high-water + component floor UNDER the lock.
        verifier.check_freshness()
        recheck_release(
            current,
            manifest_sequence=seq,
            min_sequence=min_seq,
            component=(component.name, component.version),
            security_floor=getattr(component, "security_floor", None),
        )

        # 4. verify the staged bytes against the manifest's expected digest.
        if not expected:
            raise VerificationError(
                f"{component.name} {component.version}: manifest artifact has no "
                "present digest to verify the staged bytes against; refusing to publish"
            )
        if str(staged_sha256).lower() != expected.lower():
            raise VerificationError(
                f"staged {component.name} {component.version} sha256 "
                f"{staged_sha256} != manifest expected {expected}; refusing to publish"
            )

        # 5. atomically publish the staged tree WITH rollback (still locked).
        #    Retain the previous tree's backup until the state commit succeeds so
        #    a failed commit can roll the publish back (never leave a published
        #    artifact whose high-water mark was not durably recorded).
        result = _publish(stage_dir, target_dir, in_use=in_use, keep_backup=True)
        if not result.published:
            return PublishTxnResult(
                published=False,
                committed=False,
                deferred=result.deferred,
                rolled_back=result.rolled_back,
                reason=result.reason,
                manifest_sequence=current.manifest_sequence,
            )

        # 6. commit the high-water mark AFTER the successful publish, same lock.
        #    If the state write fails, ROLL BACK the publish (restore the prior
        #    working install) and fail closed — never a published-but-uncommitted
        #    install that a later replay could exploit.
        apply_release_commit(
            current, manifest_sequence=seq, component=(component.name, component.version)
        )
        try:
            save_state(current, path)
        except Exception:
            from .publish import rollback_publish

            rollback_publish(result, target_dir)
            raise
        from .publish import finalize_publish

        finalize_publish(result)
        verifier.state = current
        return PublishTxnResult(
            published=True, committed=True, manifest_sequence=current.manifest_sequence
        )

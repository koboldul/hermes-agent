"""A6: the real release-verified Python publication sink + CLI.

``guard_install()`` is PLAN-ONLY — a ``PROCEED`` decision means "the compiled
trust root + freshness are verified and the artifact has an anchor", nothing is
committed. This module is the reachable production caller that turns that plan
into an install through the full A6 transaction:

    plan (guard_install) → stage OUTSIDE the lock → publish_release_verified()
    [ kernel advisory lock → reload state (strict) → re-verify compiled trust
      root → recheck high-water/floor → verify staged digest vs the committed
      manifest → atomically swap WITH rollback → commit the high-water AFTER the
      swap (state-write failure rolls the swap back) ]

It fails closed (raises / non-PROCEED) on any non-release-verified plan or a
verification failure, and preserves the previous working install on every
failure path. Desktop routes Electron/get-windows publication through this
helper (CLI: ``python -m hermes_cli.supply_chain.publish_cli``) so the
release-verified sink is a single shared kernel-locked transaction across
Python and JS, rather than each surface reinventing the lock/commit ordering.
"""

from __future__ import annotations

import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Callable, Optional

from .errors import VerificationError
from .gate import GateAction, GateResult, guard_install
from .identity import current_arch, current_platform
from .publish import compute_sha256, iter_zip_members, validate_archive_members
from .transaction import PublishTxnResult, publish_release_verified


def _safe_extract_zip(archive: Path, dest: Path) -> None:
    """Validate members (reject absolute/traversal/symlink/special/hardlink;
    flat multi-root archives like Electron's ZIP are allowed) BEFORE extracting
    into *dest*. The archive's bytes are digest-checked against the committed
    manifest inside :func:`publish_release_verified`; this member gate is the
    pre-extraction defence so a wrong-digest archive cannot traverse the FS
    during staging."""
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(str(archive)) as zf:
        validate_archive_members(
            iter_zip_members(zf), allow_symlinks=False, require_single_root=False
        )
        zf.extractall(str(dest))


def publish_component(
    component_name: str,
    *,
    target_dir: str | Path,
    archive_path: str | Path | None = None,
    stage_dir: str | Path | None = None,
    staged_sha256: str | None = None,
    platform: str | None = None,
    arch: str | None = None,
    verifier=None,
    state_path: str | Path | None = None,
    operator_probe: Callable[[], Optional[str]] | None = None,
    _extract: Callable[[Path, Path], None] = _safe_extract_zip,
):
    """Publish a release-verified component through the A6 transaction.

    Provide EITHER *archive_path* (the helper validates members, extracts to a
    private stage, and hashes the archive bytes) OR a pre-staged *stage_dir* +
    *staged_sha256* (the caller already extracted + hashed — Desktop's path).

    Returns a :class:`PublishTxnResult` on the PROCEED path, or the
    :class:`GateResult` when the plan is NOT ``PROCEED`` (operator-managed /
    transport-trusted / fail-closed) so the caller can act on it. Raises
    (fails closed) on a staged-digest mismatch, replay/rollback, corrupt state,
    or a trust failure — the previous install is preserved in every case.
    """
    plat = platform or current_platform()
    ar = arch or current_arch()
    sp = Path(state_path) if state_path is not None else None

    if verifier is None:
        from . import get_verifier
        from .state import default_state_path, load_state

        sp = sp or default_state_path()
        verifier = get_verifier(state=load_state(sp, strict=False))

    # 1. PLAN — guard_install commits nothing (A6). A non-PROCEED decision is
    #    returned verbatim so the caller can use an operator binary / fail closed.
    plan = guard_install(
        component_name,
        platform=plat,
        arch=ar,
        verifier=verifier,
        operator_probe=operator_probe,
    )
    if plan.action is not GateAction.PROCEED:
        return plan

    component = verifier.manifest.component(component_name)
    artifact = component.artifact(plat, ar)

    # 2. STAGE outside the transaction lock (slow, uncontended).
    own_stage = False
    if stage_dir is None:
        if archive_path is None:
            raise VerificationError(
                "publish_component requires either archive_path or a pre-staged "
                "stage_dir + staged_sha256"
            )
        archive = Path(archive_path)
        staged_sha256 = compute_sha256(archive)
        stage_parent = Path(target_dir).parent
        stage_parent.mkdir(parents=True, exist_ok=True)
        stage_path = Path(tempfile.mkdtemp(prefix=f"{component_name}-stage-", dir=str(stage_parent)))
        own_stage = True
        _extract(archive, stage_path)
    else:
        stage_path = Path(stage_dir)
        if not staged_sha256:
            raise VerificationError(
                "staged_sha256 is required when publishing a pre-staged stage_dir"
            )

    # 3. TRANSACTION — the kernel-locked publish + commit-after with rollback.
    try:
        return publish_release_verified(
            verifier,
            component,
            artifact,
            staged_sha256=staged_sha256,
            stage_dir=str(stage_path),
            target_dir=str(target_dir),
            state_path=str(sp) if sp is not None else None,
        )
    finally:
        if own_stage:
            shutil.rmtree(stage_path, ignore_errors=True)


def _result_payload(result) -> dict:
    if isinstance(result, GateResult):
        return {
            "ok": result.action is GateAction.USE_OPERATOR,
            "kind": "plan",
            "action": result.action.value,
            "reason": result.reason,
            "operator_path": getattr(result, "operator_path", None),
        }
    assert isinstance(result, PublishTxnResult)
    return {
        "ok": bool(result.published and result.committed),
        "kind": "publish",
        "published": result.published,
        "committed": result.committed,
        "deferred": result.deferred,
        "rolled_back": result.rolled_back,
        "reason": result.reason,
        "manifest_sequence": result.manifest_sequence,
    }


def main(argv: list[str] | None = None) -> int:
    """CLI entry: ``python -m hermes_cli.supply_chain.publish_cli --component ...``.

    Exit 0 only when the component was published+committed (or an
    operator-managed binary is to be used in place); non-zero on any fail-closed
    / verification failure. Emits a single JSON object on stdout for the caller.
    """
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="python -m hermes_cli.supply_chain.publish_cli",
        description="Publish a release-verified component through the A6 kernel-locked transaction.",
    )
    parser.add_argument("--component", required=True, help="manifest component name, e.g. electron")
    parser.add_argument("--target", required=True, help="destination directory to publish into")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--archive", help="archive (.zip) to validate, extract, hash, and publish")
    src.add_argument("--staged-dir", help="a pre-extracted staged tree to publish (needs --staged-sha256)")
    parser.add_argument("--staged-sha256", help="sha256 of the archive bytes (required with --staged-dir)")
    parser.add_argument("--platform", help="canonical platform (default: host)")
    parser.add_argument("--arch", help="canonical arch (default: host)")
    parser.add_argument("--state", help="anti-rollback state path (default: profile state)")
    args = parser.parse_args(argv)

    try:
        result = publish_component(
            args.component,
            target_dir=args.target,
            archive_path=args.archive,
            stage_dir=args.staged_dir,
            staged_sha256=args.staged_sha256,
            platform=args.platform,
            arch=args.arch,
            state_path=args.state,
        )
    except Exception as exc:  # fail closed — emit a machine-readable error
        print(json.dumps({"ok": False, "kind": "error", "error_type": type(exc).__name__, "error": str(exc)}))
        return 1

    payload = _result_payload(result)
    print(json.dumps(payload))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":  # pragma: no cover - CLI entry
    import sys

    sys.exit(main())

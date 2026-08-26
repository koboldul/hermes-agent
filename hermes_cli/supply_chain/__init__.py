"""Supply-chain verification subsystem (Work Package 4).

Public API for consumers that fetch or extract a Hermes-managed artifact. The
canonical committed data lives in the repository ``supply-chain/`` directory;
:func:`default_manifest_path` / :func:`default_ledger_path` resolve it relative
to the source tree.

Typical consumer use::

    from hermes_cli.supply_chain import get_verifier, current_platform, current_arch
    verifier = get_verifier()
    plan = verifier.plan("uv", platform=current_platform(), arch=current_arch())
    if plan.release_verified:
        ...  # download to temp, verifier.verify_staged_artifact(...), atomic_publish
    elif plan.decision is Decision.FAIL_CLOSED:
        plan.raise_if_blocked()   # prints operator guidance, never downloads
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from .errors import (
    FailClosed,
    ManifestError,
    StateCorruptError,
    SupplyChainError,
    TrustRootError,
    VerificationError,
)
from .gate import (
    GateAction,
    GateResult,
    compat_opt_in,
    enforce_enabled,
    guard_install,
)
from .identity import (
    ARCHES,
    PLATFORMS,
    current_arch,
    current_platform,
    normalize_arch,
    normalize_platform,
)
from .ledger import Ledger, LedgerPath, load_ledger
from .manifest import ReleaseManifest, load_manifest
from .publish import (
    ArchiveMember,
    PublishResult,
    atomic_publish,
    compute_sha256,
    iter_tar_members,
    iter_zip_members,
    validate_archive_members,
)
from .state import RollbackState, commit_state, load_state, reset_state, save_state
from .trust_root import TRUSTED_SIGNER, signer_matches_trust_root
from .verifier import Decision, SupplyChainVerifier, VerificationPlan

__all__ = [
    "ARCHES",
    "PLATFORMS",
    "ArchiveMember",
    "Decision",
    "FailClosed",
    "GateAction",
    "GateResult",
    "Ledger",
    "LedgerPath",
    "ManifestError",
    "PublishResult",
    "ReleaseManifest",
    "RollbackState",
    "SupplyChainError",
    "SupplyChainVerifier",
    "StateCorruptError",
    "TRUSTED_SIGNER",
    "TrustRootError",
    "VerificationError",
    "VerificationPlan",
    "atomic_publish",
    "commit_state",
    "compute_sha256",
    "compat_opt_in",
    "current_arch",
    "current_platform",
    "default_ledger_path",
    "default_manifest_path",
    "enforce_enabled",
    "get_verifier",
    "guard_install",
    "iter_tar_members",
    "iter_zip_members",
    "load_ledger",
    "load_manifest",
    "load_state",
    "normalize_arch",
    "normalize_platform",
    "reset_state",
    "save_state",
    "signer_matches_trust_root",
    "supply_chain_root",
    "validate_archive_members",
]


def supply_chain_root() -> Path:
    """Return the repository ``supply-chain/`` directory."""
    return Path(__file__).resolve().parents[2] / "supply-chain"


def default_manifest_path() -> Path:
    return supply_chain_root() / "manifest.json"


def default_ledger_path() -> Path:
    return supply_chain_root() / "ledger.json"


@lru_cache(maxsize=1)
def _cached_manifest(path_str: str) -> ReleaseManifest:
    return load_manifest(path_str)


def get_manifest(path: str | Path | None = None) -> ReleaseManifest:
    resolved = Path(path) if path is not None else default_manifest_path()
    return _cached_manifest(str(resolved))


def get_verifier(
    *,
    manifest_path: str | Path | None = None,
    state: RollbackState | None = None,
    downloaded: bool = False,
) -> SupplyChainVerifier:
    """Build a verifier over the committed (in-tree) manifest by default.

    The in-tree manifest is the only ACTIVE production trust path: it is
    reviewed code, so it is trusted without attestation. The downloaded-manifest
    path (``SupplyChainVerifier(downloaded=True)`` + ``verify_trust_root``) is a
    tested defensive building block for the planned Sigstore-attested remote
    manifest — it has no production caller yet, so no public "load a downloaded
    manifest" entry point is exported (that would claim unimplemented support).
    ``plan()`` still refuses to run on a downloaded manifest before its trust
    root is verified, so the defence is enforced wherever the machinery is used.
    """
    manifest = get_manifest(manifest_path)
    return SupplyChainVerifier(manifest, state=state, downloaded=downloaded)

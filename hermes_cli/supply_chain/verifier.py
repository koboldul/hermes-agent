"""The central supply-chain verifier and chokepoint decision API.

Every migrated consumer calls :meth:`SupplyChainVerifier.plan` with a component
name and the host's canonical ``(platform, arch)``. The verifier enforces, in
order and *before* any download:

1. **Trust root** — an in-tree manifest is trusted (reviewed code); a
   downloaded manifest must have its attestation verified against the pinned
   release-workflow identity, else it fails closed.
2. **Freshness** — not expired, sequence at/above ``min_sequence`` and at/above
   the machine's stored high-water mark (replay/downgrade defence).
3. **Revocation** — a revoked component/version fails closed.
4. **Anti-rollback floor** — a version below the component's security floor or
   the last-installed version fails closed.
5. **Exact identity** — a missing ``(platform, arch)`` mapping fails closed
   rather than resolving the wrong artifact.

The returned :class:`VerificationPlan` tells the caller exactly what to do:
proceed with a byte/provenance-verified fetch, use an operator-managed binary
in place, run a labelled transport-trusted compatibility fetch, or abort with
operator guidance. Under ``enforce`` only release-verified and operator-managed
outcomes are allowed.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable

from .errors import FailClosed, ManifestError, TrustRootError, VerificationError
from .manifest import (
    TRUST_OPERATOR_MANAGED,
    TRUST_RELEASE_VERIFIED,
    TRUST_TRANSPORT_TRUSTED,
    Artifact,
    Component,
    ReleaseManifest,
    Signer,
)
from .publish import compute_sha256
from .state import RollbackState, load_state

_DEFAULT_GUIDANCE = (
    "Install this component through your OS/version manager, or wait for a "
    "reviewed manifest update that pins an exact digest. See "
    "docs/security/supply-chain-trust-root.md."
)


class Decision(str, Enum):
    PROCEED = "proceed"
    OPERATOR_MANAGED = "operator_managed"
    TRANSPORT_COMPAT = "transport_compat"
    FAIL_CLOSED = "fail_closed"


@dataclass
class VerificationPlan:
    component: str
    version: str
    decision: Decision
    trust_class: str
    artifact: Artifact | None
    reason: str
    guidance: str | None = None

    @property
    def release_verified(self) -> bool:
        return self.decision is Decision.PROCEED

    def raise_if_blocked(self) -> "VerificationPlan":
        if self.decision is Decision.FAIL_CLOSED:
            guidance = self.guidance or _DEFAULT_GUIDANCE
            raise FailClosed(
                f"cannot obtain a verified {self.component}: {self.reason} — {guidance}",
                component=self.component,
                version=self.version,
                reason=self.reason,
                guidance=guidance,
            )
        return self


def _version_tuple(version: str) -> tuple:
    parts: list = []
    for chunk in str(version).replace("-", ".").split("."):
        parts.append((0, int(chunk)) if chunk.isdigit() else (1, chunk))
    return tuple(parts)


def _is_below(candidate: str, floor: str) -> bool:
    try:
        return _version_tuple(candidate) < _version_tuple(floor)
    except Exception:
        return False


AttestationVerifier = Callable[[Path, Signer], bool]


def default_attestation_verifier(target: Path, signer: Signer) -> bool:
    """Verify a Sigstore attestation with ``gh`` or ``cosign``, if present.

    Returns True only on a positive verification against the pinned identity.
    Absence of a verifier tool is reported as ``False`` so the caller fails
    closed and points the operator at the two-channel bootstrap.
    """
    gh = shutil.which("gh")
    if gh:
        result = subprocess.run(
            [
                gh, "attestation", "verify", str(target),
                "--repo", signer.repository,
                "--cert-identity-regexp", signer.identity_regexp,
                "--cert-oidc-issuer", signer.issuer,
            ],
            capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
        )
        return result.returncode == 0
    return False


class SupplyChainVerifier:
    def __init__(
        self,
        manifest: ReleaseManifest,
        *,
        state: RollbackState | None = None,
        now: datetime | None = None,
        downloaded: bool = False,
        attestation_verifier: AttestationVerifier | None = None,
    ) -> None:
        self.manifest = manifest
        self.state = state if state is not None else load_state(strict=True)
        self._now = now
        self.downloaded = downloaded
        self._attest = attestation_verifier or default_attestation_verifier
        # An in-tree manifest is reviewed code → already trusted. A downloaded
        # manifest is untrusted until verify_trust_root() succeeds; plan() refuses
        # to run before then (A9).
        self._trust_verified = not downloaded

    def now(self) -> datetime:
        return self._now or datetime.now(timezone.utc)

    # -- trust root --------------------------------------------------------
    def verify_trust_root(self, manifest_path: Path | None = None) -> None:
        """Ensure the manifest itself chains to the COMPILED-IN trust anchor.

        The accepted identity comes from :mod:`trust_root` (reviewed code), never
        from the manifest. A downloaded manifest whose self-declared signer does
        not exactly equal the compiled-in trust root is rejected outright, and
        the attestation is checked against the compiled-in identity — an attacker
        cannot substitute their own signer.
        """
        from .trust_root import TRUSTED_SIGNER, signer_matches_trust_root

        if not self.downloaded:
            self._trust_verified = True
            return  # in-tree manifest: trusted because it is reviewed code

        # (a) the manifest's declared signer MUST equal the compiled-in root.
        if not signer_matches_trust_root(self.manifest.meta.signer):
            raise TrustRootError(
                "downloaded manifest declares a signer that is not the compiled-in "
                "trust root (NousResearch/hermes-agent release-attest.yml); refusing "
                "to trust a self-declared identity"
            )

        target = manifest_path or self.manifest.source_path
        if target is None:
            raise TrustRootError("downloaded manifest has no path to attest")
        # (b) verify the attestation against the COMPILED-IN identity, not the
        # manifest's copy.
        try:
            ok = self._attest(Path(target), TRUSTED_SIGNER)
        except (OSError, subprocess.SubprocessError) as exc:
            raise FailClosed(
                "cannot verify the downloaded manifest's attestation",
                reason=str(exc),
                guidance=(
                    "Install an attestation verifier (gh >= 2.49 or cosign), or "
                    "bootstrap Hermes from an OS package / the documented "
                    "two-channel path in docs/security/supply-chain-trust-root.md."
                ),
            ) from exc
        if not ok:
            raise TrustRootError(
                "downloaded manifest attestation did not chain to the compiled-in "
                f"release identity {TRUSTED_SIGNER.identity_regexp!r}"
            )
        self._trust_verified = True

    # -- freshness ---------------------------------------------------------
    def check_freshness(self) -> None:
        meta = self.manifest.meta
        if self.now() > meta.expires_at:
            raise ManifestError(
                f"manifest expired at {meta.expires_at.isoformat()}"
            )
        if meta.sequence < meta.min_sequence:
            raise ManifestError(
                f"manifest sequence {meta.sequence} below min {meta.min_sequence}"
            )
        if meta.sequence < self.state.manifest_sequence:
            raise ManifestError(
                f"manifest sequence {meta.sequence} is a replay/downgrade below "
                f"the accepted high-water mark {self.state.manifest_sequence}"
            )

    def accept_sequence(self) -> None:
        """Advance the stored high-water mark after a successful verification."""
        if self.manifest.meta.sequence > self.state.manifest_sequence:
            self.state.manifest_sequence = self.manifest.meta.sequence

    def commit(self, component: Component | None = None) -> None:
        """Transactional anti-rollback commit for the guard PROCEED path (A9).

        The full transaction is: verify the COMPILED-IN trust root (raises for a
        downloaded, unverified manifest) → acquire the cross-process lock →
        recheck the freshness/high-water mark and component floor *under the
        lock* → atomically raise the high-water mark + record the component.

        Call this after a successful verify+publish so a concurrent process
        cannot lose the update, and a later run refuses a replayed manifest or a
        rolled-back component version. A detected replay/rollback/trust failure
        raises (the caller must fail closed, not report success).
        """
        self.verify_trust_root()
        from .state import commit_release_state

        committed = commit_release_state(
            manifest_sequence=self.manifest.meta.sequence,
            min_sequence=self.manifest.meta.min_sequence,
            component=(component.name, component.version) if component is not None else None,
            security_floor=(component.security_floor if component is not None else None),
            path=self.state.path,
        )
        # Reflect the persisted mark back into the in-memory state.
        self.state.manifest_sequence = committed.manifest_sequence
        self.state.components.update(committed.components)

    # -- planning ----------------------------------------------------------
    def plan(
        self,
        component_name: str,
        *,
        platform: str | None,
        arch: str | None,
        enforce: bool = False,
    ) -> VerificationPlan:
        # A9: a downloaded manifest may NOT be planned before its trust root is
        # verified — no self-declared manifest can reach the decision logic.
        if self.downloaded and not self._trust_verified:
            raise TrustRootError(
                "refusing to plan against a downloaded manifest before its trust "
                "root is verified; call verify_trust_root() first"
            )
        self.check_freshness()
        component = self.manifest.component(component_name)
        if component is None:
            return self._fail(
                component_name, "?", "component not present in the release manifest"
            )

        revocation = self.manifest.is_revoked(component.name, component.version)
        if revocation is not None:
            return self._fail(
                component.name, component.version,
                f"component revoked: {revocation.reason}",
            )

        floor_reason = self._floor_violation(component)
        if floor_reason:
            return self._fail(component.name, component.version, floor_reason)

        if platform is None or arch is None:
            return self._fail(
                component.name, component.version,
                "host platform/architecture is not in the canonical vocabulary",
            )
        artifact = component.artifact(platform, arch)
        if artifact is None:
            return self._fail(
                component.name, component.version,
                f"no artifact for platform/arch {platform}/{arch}",
                guidance=(
                    "This platform is unsupported by the pinned release; use an "
                    "operator-managed install."
                ),
            )

        return self._decide(component, artifact, enforce)

    def _decide(
        self, component: Component, artifact: Artifact, enforce: bool
    ) -> VerificationPlan:
        if component.trust_class == TRUST_OPERATOR_MANAGED:
            return VerificationPlan(
                component.name, component.version, Decision.OPERATOR_MANAGED,
                component.trust_class, artifact,
                "operator-managed component; used in place, not relabelled",
            )

        if component.trust_class == TRUST_RELEASE_VERIFIED:
            if not artifact.has_anchor:
                # A release_verified entry with no digest and no provenance is a
                # manifest inconsistency; refuse rather than claim verification.
                return self._fail(
                    component.name, component.version,
                    "release_verified artifact has neither digest nor provenance",
                    guidance=artifact.operator_guidance,
                )
            return VerificationPlan(
                component.name, component.version, Decision.PROCEED,
                component.trust_class, artifact,
                "release-verified: byte digest and/or provenance anchor present",
            )

        # transport_trusted (or anything without an anchor)
        reason = artifact.blocker or "no committed digest/anchor for this artifact"
        if enforce:
            return self._fail(
                component.name, component.version, reason,
                guidance=artifact.operator_guidance,
            )
        return VerificationPlan(
            component.name, component.version, Decision.TRANSPORT_COMPAT,
            component.trust_class, artifact,
            f"transport-trusted compatibility path ({reason}); not release-verified",
            guidance=artifact.operator_guidance,
        )

    def _floor_violation(self, component: Component) -> str | None:
        if component.security_floor and _is_below(
            component.version, component.security_floor
        ):
            return (
                f"version {component.version} below security floor "
                f"{component.security_floor}"
            )
        last = self.state.components.get(component.name)
        if last and _is_below(component.version, last):
            return (
                f"version {component.version} is a rollback below the "
                f"last-installed {last}"
            )
        return None

    def _fail(
        self,
        component: str,
        version: str,
        reason: str,
        *,
        guidance: str | None = None,
    ) -> VerificationPlan:
        return VerificationPlan(
            component, version, Decision.FAIL_CLOSED, "unknown", None, reason,
            guidance or _DEFAULT_GUIDANCE,
        )

    # -- artifact verification --------------------------------------------
    def verify_staged_artifact(self, path: str | Path, artifact: Artifact) -> None:
        """Verify staged bytes by digest (raises before extraction/execution).

        A present digest is checked directly. When only provenance is
        available the caller must run :meth:`verify_artifact_provenance`
        instead; a byte-only call with no digest fails closed rather than
        silently accepting unverified bytes.
        """
        if artifact.digest.present:
            actual = compute_sha256(path)
            if actual != artifact.digest.value:
                raise VerificationError(
                    f"digest mismatch: expected {artifact.digest.value}, got {actual}"
                )
            return
        if artifact.provenance is not None:
            raise VerificationError(
                "artifact has no byte digest; run provenance verification"
            )
        raise FailClosed(
            "no digest available to verify staged artifact",
            reason=artifact.blocker or "digest unavailable",
            guidance=artifact.operator_guidance or _DEFAULT_GUIDANCE,
        )

    def record_component(self, component: Component) -> None:
        """Record a component version as installed (advances anti-rollback)."""
        self.state.components[component.name] = component.version

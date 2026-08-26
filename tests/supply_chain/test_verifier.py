"""Behavioral tests for the central verifier: trust root, freshness, replay,
revocation, anti-rollback floor, chokepoint decisions, and digest verification.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from conftest import (
    make_artifact,
    make_component,
    make_digest,
    make_manifest,
    sha256_hex,
    transport_artifact,
)
from hermes_cli.supply_chain.errors import (
    FailClosed,
    ManifestError,
    TrustRootError,
    VerificationError,
)
from hermes_cli.supply_chain.manifest import ReleaseManifest
from hermes_cli.supply_chain.state import RollbackState
from hermes_cli.supply_chain.verifier import Decision, SupplyChainVerifier

_FAR_FUTURE = datetime(2027, 1, 1, tzinfo=timezone.utc)


def _verifier(data: dict, **kwargs) -> SupplyChainVerifier:
    manifest = ReleaseManifest.from_dict(data, source_path=None)
    kwargs.setdefault("state", RollbackState())
    kwargs.setdefault("now", _FAR_FUTURE)
    return SupplyChainVerifier(manifest, **kwargs)


# --- trust root -----------------------------------------------------------

def test_hostile_distribution_fails_unless_attestation_chains(tmp_path):
    """A server that controls installer, artifact, checksum, signature, and key
    still fails: the downloaded manifest's attestation must chain to the pinned
    identity."""
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")
    data = make_manifest()
    manifest = ReleaseManifest.from_dict(data, source_path=manifest_path)
    verifier = SupplyChainVerifier(
        manifest, downloaded=True, now=_FAR_FUTURE,
        attestation_verifier=lambda path, signer: False,  # attacker key: no chain
    )
    with pytest.raises(TrustRootError):
        verifier.verify_trust_root()


def test_downloaded_manifest_with_valid_attestation_passes(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")
    manifest = ReleaseManifest.from_dict(make_manifest(), source_path=manifest_path)
    captured = {}

    def verify(path, signer):
        captured["repo"] = signer.repository
        return True

    verifier = SupplyChainVerifier(
        manifest, downloaded=True, now=_FAR_FUTURE, attestation_verifier=verify
    )
    verifier.verify_trust_root()
    assert captured["repo"] == "NousResearch/hermes-agent"


def test_missing_verifier_tool_fails_closed_with_guidance(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")
    manifest = ReleaseManifest.from_dict(make_manifest(), source_path=manifest_path)

    def raise_missing(path, signer):
        raise OSError("gh not found")

    verifier = SupplyChainVerifier(
        manifest, downloaded=True, now=_FAR_FUTURE, attestation_verifier=raise_missing
    )
    with pytest.raises(FailClosed) as exc:
        verifier.verify_trust_root()
    assert "two-channel" in exc.value.operator_message()


def test_in_tree_manifest_is_trusted_without_attestation():
    verifier = _verifier(make_manifest(), downloaded=False)
    # No attestation callback is invoked; a reviewed in-tree manifest is trusted.
    verifier.verify_trust_root()


# --- freshness / replay / downgrade --------------------------------------

def test_expired_manifest_is_rejected():
    data = make_manifest(expires_at="2026-06-01T00:00:00Z")
    verifier = _verifier(data, now=datetime(2026, 8, 1, tzinfo=timezone.utc))
    with pytest.raises(ManifestError):
        verifier.check_freshness()


def test_replayed_lower_sequence_is_rejected():
    verifier = _verifier(make_manifest(sequence=5), state=RollbackState(manifest_sequence=10))
    with pytest.raises(ManifestError):
        verifier.check_freshness()


def test_accept_sequence_advances_high_water():
    state = RollbackState(manifest_sequence=2)
    verifier = _verifier(make_manifest(sequence=7), state=state)
    verifier.check_freshness()
    verifier.accept_sequence()
    assert state.manifest_sequence == 7


# --- revocation / floor / rollback ---------------------------------------

def test_revoked_component_fails_closed():
    rev = [{"component": "demo", "version": "1.2.3", "reason": "CVE-2026-1"}]
    verifier = _verifier(make_manifest(revocations=rev))
    plan = verifier.plan("demo", platform="linux", arch="x86_64")
    assert plan.decision is Decision.FAIL_CLOSED
    assert "revoked" in plan.reason


def test_security_floor_downgrade_fails_closed():
    comp = make_component(version="1.5.0", security_floor="2.0.0")
    verifier = _verifier(make_manifest(components=[comp]))
    plan = verifier.plan("demo", platform="linux", arch="x86_64")
    assert plan.decision is Decision.FAIL_CLOSED
    assert "floor" in plan.reason


def test_rollback_below_last_installed_fails_closed():
    comp = make_component(version="1.0.0")
    state = RollbackState(components={"demo": "2.0.0"})
    verifier = _verifier(make_manifest(components=[comp]), state=state)
    plan = verifier.plan("demo", platform="linux", arch="x86_64")
    assert plan.decision is Decision.FAIL_CLOSED
    assert "rollback" in plan.reason


# --- chokepoint decisions -------------------------------------------------

def test_release_verified_with_anchor_proceeds():
    verifier = _verifier(make_manifest())
    plan = verifier.plan("demo", platform="linux", arch="x86_64")
    assert plan.decision is Decision.PROCEED
    assert plan.release_verified


def test_transport_trusted_is_compat_by_default_and_fail_closed_under_enforce():
    comp = make_component(trust_class="transport_trusted", artifacts=[transport_artifact()])
    verifier = _verifier(make_manifest(components=[comp]))
    compat = verifier.plan("demo", platform="linux", arch="x86_64")
    assert compat.decision is Decision.TRANSPORT_COMPAT
    assert not compat.release_verified

    enforced = verifier.plan("demo", platform="linux", arch="x86_64", enforce=True)
    assert enforced.decision is Decision.FAIL_CLOSED
    assert enforced.guidance


def test_operator_managed_used_in_place():
    comp = make_component(trust_class="operator_managed", artifacts=[transport_artifact()])
    verifier = _verifier(make_manifest(components=[comp]))
    plan = verifier.plan("demo", platform="linux", arch="x86_64", enforce=True)
    assert plan.decision is Decision.OPERATOR_MANAGED


def test_missing_arch_mapping_fails_closed():
    verifier = _verifier(make_manifest())
    plan = verifier.plan("demo", platform="linux", arch="armv7")
    assert plan.decision is Decision.FAIL_CLOSED
    assert "armv7" in plan.reason


def test_unknown_host_platform_fails_closed():
    verifier = _verifier(make_manifest())
    plan = verifier.plan("demo", platform=None, arch=None)
    assert plan.decision is Decision.FAIL_CLOSED


def test_unknown_component_fails_closed():
    verifier = _verifier(make_manifest())
    plan = verifier.plan("nonexistent", platform="linux", arch="x86_64")
    assert plan.decision is Decision.FAIL_CLOSED


def test_release_verified_without_anchor_refuses():
    comp = make_component(
        trust_class="release_verified",
        artifacts=[make_artifact(digest=make_digest(value=None, status="unavailable"))],
    )
    verifier = _verifier(make_manifest(components=[comp]))
    plan = verifier.plan("demo", platform="linux", arch="x86_64")
    assert plan.decision is Decision.FAIL_CLOSED


def test_raise_if_blocked_raises_failclosed_with_guidance():
    comp = make_component(trust_class="transport_trusted", artifacts=[transport_artifact()])
    verifier = _verifier(make_manifest(components=[comp]))
    plan = verifier.plan("demo", platform="linux", arch="x86_64", enforce=True)
    with pytest.raises(FailClosed):
        plan.raise_if_blocked()


# --- staged artifact digest ----------------------------------------------

def test_digest_match_and_mismatch(tmp_path):
    payload = b"exact-bytes"
    good = make_digest(value=sha256_hex(payload))
    comp = make_component(artifacts=[make_artifact(digest=good)])
    verifier = _verifier(make_manifest(components=[comp]))
    artifact = verifier.manifest.component("demo").artifacts[0]

    staged = tmp_path / "artifact.bin"
    staged.write_bytes(payload)
    verifier.verify_staged_artifact(staged, artifact)  # no raise

    staged.write_bytes(payload + b"x")  # one-byte mutation
    with pytest.raises(VerificationError):
        verifier.verify_staged_artifact(staged, artifact)


def test_verify_without_digest_or_provenance_fails_closed(tmp_path):
    comp = make_component(trust_class="transport_trusted", artifacts=[transport_artifact()])
    verifier = _verifier(make_manifest(components=[comp]))
    artifact = verifier.manifest.component("demo").artifacts[0]
    staged = tmp_path / "artifact.bin"
    staged.write_bytes(b"whatever")
    with pytest.raises(FailClosed):
        verifier.verify_staged_artifact(staged, artifact)

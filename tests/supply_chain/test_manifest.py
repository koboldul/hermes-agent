"""Behavioral tests for the release-manifest schema and loader."""

from __future__ import annotations

import pytest

from conftest import make_artifact, make_component, make_digest, make_manifest
from hermes_cli.supply_chain.errors import ManifestError
from hermes_cli.supply_chain.manifest import ReleaseManifest


def _load(data: dict) -> ReleaseManifest:
    return ReleaseManifest.from_dict(data)


def test_valid_manifest_round_trips():
    manifest = _load(make_manifest())
    assert manifest.meta.sequence == 5
    assert manifest.component("demo") is not None
    comp, art = next(iter(manifest.iter_artifacts()))
    assert art.platform == "linux"
    assert art.has_anchor


def test_expiry_before_issue_is_rejected():
    data = make_manifest(issued_at="2030-01-01T00:00:00Z", expires_at="2029-01-01T00:00:00Z")
    with pytest.raises(ManifestError):
        _load(data)


def test_sequence_below_min_is_rejected():
    with pytest.raises(ManifestError):
        _load(make_manifest(sequence=1, min_sequence=5))


def test_duplicate_platform_arch_is_rejected():
    comp = make_component(
        artifacts=[make_artifact(), make_artifact()]  # same linux/x86_64 twice
    )
    with pytest.raises(ManifestError):
        _load(make_manifest(components=[comp]))


def test_duplicate_component_is_rejected():
    with pytest.raises(ManifestError):
        _load(make_manifest(components=[make_component(), make_component()]))


def test_present_digest_requires_valid_hex():
    bad = make_component(artifacts=[make_artifact(digest=make_digest(value="xyz"))])
    with pytest.raises(ManifestError):
        _load(make_manifest(components=[bad]))


def test_member_digests_parse_and_are_addressable():
    art = make_artifact(members=("node-get-windows.node",))
    art["member_digests"] = {
        "node-get-windows.node": {
            "algorithm": "sha256",
            "value": "5" * 64,
            "status": "present",
        }
    }
    # The artifact-level digest authenticates the ARCHIVE; the member digest the
    # extracted file — two DISTINCT values.
    art["digest"] = {"algorithm": "sha256", "value": "3" * 64, "status": "present"}
    comp = make_component(artifacts=[art])
    manifest = _load(make_manifest(components=[comp]))
    parsed = manifest.component("demo").artifacts[0]
    assert parsed.digest.value == "3" * 64  # archive
    assert parsed.member_digest("node-get-windows.node").value == "5" * 64  # extracted
    assert parsed.member_digest("does-not-exist") is None


def test_member_digest_key_must_be_a_listed_member():
    # A member digest for a path NOT in `members` is a manifest error — it pins
    # bytes nothing extracts (guards archive/member confusion).
    art = make_artifact(members=("main",))
    art["member_digests"] = {
        "not-listed": {"algorithm": "sha256", "value": "5" * 64, "status": "present"}
    }
    comp = make_component(artifacts=[art])
    with pytest.raises(ManifestError):
        _load(make_manifest(components=[comp]))


def test_member_digest_validates_hex():
    art = make_artifact(members=("main",))
    art["member_digests"] = {
        "main": {"algorithm": "sha256", "value": "nothex", "status": "present"}
    }
    comp = make_component(artifacts=[art])
    with pytest.raises(ManifestError):
        _load(make_manifest(components=[comp]))


def test_real_get_windows_archive_digest_matches_lock_integrity():
    # The committed manifest's macOS archive digest (sha512) MUST equal the
    # package-lock integrity for get-windows (base64 → hex): the archive digest
    # authenticates the npm tarball bytes, and a mirror cannot change it. The
    # extracted-member digest is distinct (the archive/member split).
    import base64
    import json
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[2]
    manifest = _load(json.loads((repo_root / "supply-chain" / "manifest.json").read_text()))
    gw = manifest.component("get-windows")
    assert gw is not None
    mac = next(a for a in gw.artifacts if a.platform == "macos")
    assert mac.digest.algorithm == "sha512"

    lock = json.loads((repo_root / "package-lock.json").read_text())
    integrity = None
    for key, value in (lock.get("packages") or {}).items():
        if key.endswith("node_modules/get-windows") and value.get("integrity"):
            integrity = value["integrity"]
    assert integrity and integrity.startswith("sha512-"), "get-windows must be lock-integrity-bound"
    hex_digest = base64.b64decode(integrity[len("sha512-"):]).hex()

    assert mac.digest.value == hex_digest
    # The staged member is the extracted universal helper — a DIFFERENT digest.
    assert mac.member_digest("main") is not None
    assert mac.member_digest("main").value != mac.digest.value

    # Windows: archive is a GitHub .tar.gz (sha256); member is the extracted PE.
    win = next(a for a in gw.artifacts if a.platform == "windows" and a.arch == "x86_64")
    assert win.digest.algorithm == "sha256"
    assert win.member_digest("node-get-windows.node") is not None
    assert win.member_digest("node-get-windows.node").value != win.digest.value


def test_unavailable_digest_allows_absent_value():
    comp = make_component(
        trust_class="transport_trusted",
        artifacts=[make_artifact(digest=make_digest(value=None, status="unavailable"))],
    )
    manifest = _load(make_manifest(components=[comp]))
    art = manifest.component("demo").artifacts[0]
    assert not art.digest.present
    assert not art.has_anchor


def test_unknown_trust_class_is_rejected():
    comp = make_component(trust_class="totally_trusted")
    with pytest.raises(ManifestError):
        _load(make_manifest(components=[comp]))


def test_provenance_counts_as_anchor_without_digest():
    prov = {
        "type": "github-artifact-attestation",
        "issuer": "https://token.actions.githubusercontent.com",
        "identity_regexp": "^https://github\\.com/x/y/.*",
    }
    comp = make_component(
        artifacts=[make_artifact(digest=make_digest(value=None, status="unavailable"), provenance=prov)]
    )
    manifest = _load(make_manifest(components=[comp]))
    art = manifest.component("demo").artifacts[0]
    assert art.provenance is not None
    assert art.has_anchor


def test_revocation_matching():
    rev = [{"component": "demo", "version": "1.2.3", "reason": "cve"}]
    manifest = _load(make_manifest(revocations=rev))
    assert manifest.is_revoked("demo", "1.2.3") is not None
    assert manifest.is_revoked("demo", "9.9.9") is None


def test_missing_top_level_sections_rejected():
    with pytest.raises(ManifestError):
        ReleaseManifest.from_dict({"components": []})
    with pytest.raises(ManifestError):
        ReleaseManifest.from_dict({"manifest": {}})

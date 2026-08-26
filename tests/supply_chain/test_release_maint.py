"""Behavioral tests for the maintainer release-maintenance transforms.

These lock the invariants that matter for trust: a component is promoted to
release_verified only when every artifact has an anchor, the sequence is
monotonic, and the tool refuses (raises) rather than inventing an identity.
"""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_tool():
    path = _REPO_ROOT / "scripts" / "release" / "update_supply_chain_manifest.py"
    spec = importlib.util.spec_from_file_location("update_supply_chain_manifest", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL = _load_tool()


def _manifest() -> dict:
    return copy.deepcopy(TOOL.load())


def test_bump_sequence_is_monotonic():
    manifest = _manifest()
    before = manifest["manifest"]["sequence"]
    after = TOOL.bump_sequence(manifest)
    assert after == before + 1
    assert manifest["manifest"]["sequence"] == after


def test_pin_all_artifacts_promotes_to_release_verified():
    manifest = _manifest()
    uv = next(c for c in manifest["components"] if c["name"] == "uv")
    digests = {(a["platform"], a["arch"]): "a" * 64 for a in uv["artifacts"]}
    updated = TOOL.pin_component(manifest, "uv", "0.5.11", digests=digests, security_floor="0.5.11")
    comp = next(c for c in updated["components"] if c["name"] == "uv")
    assert comp["trust_class"] == "release_verified"
    assert comp["version"] == "0.5.11"
    assert comp["security_floor"] == "0.5.11"
    for art in comp["artifacts"]:
        assert art["digest"]["status"] == "present"
        assert "blocker" not in art


def test_partial_digests_stay_transport_trusted():
    manifest = _manifest()
    uv = next(c for c in manifest["components"] if c["name"] == "uv")
    first = uv["artifacts"][0]
    digests = {(first["platform"], first["arch"]): "b" * 64}
    updated = TOOL.pin_component(manifest, "uv", "0.5.11", digests=digests)
    comp = next(c for c in updated["components"] if c["name"] == "uv")
    assert comp["trust_class"] == "transport_trusted"


def test_provenance_only_component_promotes_without_digest():
    manifest = _manifest()
    # tirith artifacts carry an upstream provenance identity in the committed
    # manifest, so pinning a version with no byte digest still anchors them.
    updated = TOOL.pin_component(manifest, "tirith", "1.4.0")
    comp = next(c for c in updated["components"] if c["name"] == "tirith")
    assert comp["trust_class"] == "release_verified"


def test_unknown_component_refuses():
    with pytest.raises(ValueError):
        TOOL.pin_component(_manifest(), "does-not-exist", "1.0.0")


def test_invalid_sha_refuses():
    manifest = _manifest()
    with pytest.raises(ValueError):
        TOOL.pin_component(manifest, "uv", "0.5.11", digests={("linux", "x86_64"): "nothex"})


def test_pin_is_deterministic():
    import json

    manifest = _manifest()
    digests = {("linux", "x86_64"): "c" * 64}
    a = TOOL.pin_component(manifest, "uv", "0.5.11", digests=digests, review_date="2026-08-25")
    b = TOOL.pin_component(manifest, "uv", "0.5.11", digests=digests, review_date="2026-08-25")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_does_not_mutate_input():
    manifest = _manifest()
    original = copy.deepcopy(manifest)
    TOOL.pin_component(manifest, "uv", "9.9.9", digests={("linux", "x86_64"): "d" * 64})
    assert manifest == original  # pin returns a copy

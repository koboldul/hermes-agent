"""WP4 A9: compiled-in trust root + anti-rollback under lock (behavioral).

Exercises the real verifier/state: an attacker's self-declared signer is
rejected, plan() cannot run before trust verification, corrupt state fails
closed, and the sequence/component floor persists monotonically under a
cross-process lock (replay/downgrade/concurrency).
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from conftest import make_component, make_manifest, make_signer

from hermes_cli.supply_chain.errors import StateCorruptError, TrustRootError
from hermes_cli.supply_chain.manifest import ReleaseManifest, load_manifest
from hermes_cli.supply_chain.state import (
    RollbackState,
    commit_state,
    load_state,
    reset_state,
)
from hermes_cli.supply_chain.verifier import Decision, SupplyChainVerifier

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)


def _write_manifest(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


# --- trust root: compiled-in, never from the manifest ----------------------

def test_attacker_self_declared_signer_is_rejected(tmp_path):
    """A downloaded manifest that declares its OWN signer must be refused before
    any attestation — the trust root is compiled in, not read from the file."""
    data = make_manifest()
    data["manifest"]["signer"]["repository"] = "attacker/hermes-agent"
    data["manifest"]["signer"]["identity_regexp"] = "^https://github\\.com/attacker/.*"
    path = _write_manifest(tmp_path, data)
    manifest = load_manifest(path)
    # Even an attestation verifier that ALWAYS says yes must not save this.
    verifier = SupplyChainVerifier(
        manifest, state=RollbackState(path=tmp_path / "s.json"),
        now=_NOW, downloaded=True, attestation_verifier=lambda p, s: True,
    )
    with pytest.raises(TrustRootError):
        verifier.verify_trust_root()


def test_attestation_checked_against_compiled_in_identity(tmp_path):
    """The signer passed to the attestation verifier is the COMPILED-IN one."""
    from hermes_cli.supply_chain.trust_root import TRUSTED_REPOSITORY

    data = make_manifest()  # legitimate signer
    path = _write_manifest(tmp_path, data)
    manifest = load_manifest(path)
    seen = {}

    def fake_attest(target, signer):
        seen["repo"] = signer.repository
        seen["idre"] = signer.identity_regexp
        return True

    verifier = SupplyChainVerifier(
        manifest, state=RollbackState(path=tmp_path / "s.json"),
        now=_NOW, downloaded=True, attestation_verifier=fake_attest,
    )
    verifier.verify_trust_root()
    assert seen["repo"] == TRUSTED_REPOSITORY


def test_plan_refuses_before_trust_verification_for_downloaded(tmp_path):
    data = make_manifest(components=[make_component(name="demo")])
    path = _write_manifest(tmp_path, data)
    manifest = load_manifest(path)
    verifier = SupplyChainVerifier(
        manifest, state=RollbackState(path=tmp_path / "s.json"),
        now=_NOW, downloaded=True, attestation_verifier=lambda p, s: True,
    )
    with pytest.raises(TrustRootError):
        verifier.plan("demo", platform="linux", arch="x86_64")
    # After verification, plan() is allowed.
    verifier.verify_trust_root()
    plan = verifier.plan("demo", platform="linux", arch="x86_64")
    assert plan.decision is Decision.PROCEED


def test_in_tree_manifest_needs_no_attestation(tmp_path):
    data = make_manifest(components=[make_component(name="demo")])
    manifest = ReleaseManifest.from_dict(data)
    verifier = SupplyChainVerifier(
        manifest, state=RollbackState(path=tmp_path / "s.json"), now=_NOW, downloaded=False,
    )
    plan = verifier.plan("demo", platform="linux", arch="x86_64")
    assert plan.decision is Decision.PROCEED


# --- anti-rollback state: corrupt fails closed, monotonic under lock --------

def test_corrupt_state_fails_closed_strict(tmp_path):
    sp = tmp_path / "state.json"
    sp.write_text("{not json", encoding="utf-8")
    with pytest.raises(StateCorruptError):
        load_state(sp, strict=True)
    # Non-strict callers still degrade gracefully.
    assert load_state(sp, strict=False).manifest_sequence == 0


def test_reset_state_recovers_to_zero(tmp_path):
    sp = tmp_path / "state.json"
    sp.write_text("garbage", encoding="utf-8")
    fresh = reset_state(sp)
    assert fresh.manifest_sequence == 0
    assert load_state(sp, strict=True).manifest_sequence == 0


def test_commit_state_is_monotonic(tmp_path):
    sp = tmp_path / "state.json"
    commit_state(manifest_sequence=5, components={"uv": "1.2.0"}, path=sp)
    # A lower sequence / older version must NOT lower the high-water mark.
    commit_state(manifest_sequence=3, components={"uv": "1.0.0"}, path=sp)
    st = load_state(sp, strict=True)
    assert st.manifest_sequence == 5
    assert st.components["uv"] == "1.2.0"
    # A higher sequence / newer version advances it.
    commit_state(manifest_sequence=9, components={"uv": "1.3.0"}, path=sp)
    st = load_state(sp, strict=True)
    assert st.manifest_sequence == 9
    assert st.components["uv"] == "1.3.0"


def test_replay_below_high_water_fails_closed(tmp_path):
    sp = tmp_path / "state.json"
    commit_state(manifest_sequence=7, path=sp)
    data = make_manifest(sequence=4, components=[make_component(name="demo")])
    manifest = ReleaseManifest.from_dict(data)
    verifier = SupplyChainVerifier(manifest, state=load_state(sp, strict=True), now=_NOW)
    from hermes_cli.supply_chain.errors import ManifestError

    with pytest.raises(ManifestError):
        verifier.plan("demo", platform="linux", arch="x86_64")


def test_concurrent_commits_do_not_lose_updates(tmp_path):
    sp = tmp_path / "state.json"
    reset_state(sp)
    seqs = list(range(1, 21))
    errors = []

    def worker(seq):
        try:
            commit_state(manifest_sequence=seq, components={"c": f"1.0.{seq}"}, path=sp)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(s,)) for s in seqs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    # The lock guarantees the max survived — no update was clobbered.
    assert load_state(sp, strict=True).manifest_sequence == 20

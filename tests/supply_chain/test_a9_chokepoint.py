"""WP4 A6/A9: the guard is PLAN-ONLY; the real sink commits under the lock.

``guard_install`` no longer commits any state (A6): a ``PROCEED`` result is a
plan — the compiled trust root + freshness are verified and the artifact has an
anchor, but the anti-rollback high-water mark is advanced only AFTER a
successful atomic publish, inside ``publish_release_verified`` (reached through
the real Python sink ``publish_component``). These drive the REAL chokepoint and
assert:

  * guard PROCEED writes NO state (plan only);
  * the real sink stages -> verifies -> publishes -> commits (target lands, the
    high-water advances) — the commit happens after the swap, never before;
  * a replayed manifest already reflected in memory fails closed at PLAN;
  * a stale-in-memory manifest that PLAN passed still fails closed at the LOCKED
    recheck when the on-disk mark advanced (the TOCTOU the lock closes), with
    the previous install preserved;
  * a rolled-back component version fails closed;
  * a non-release-verified component never PROCEEDs;
  * a downloaded manifest with a forged signer never reaches PROCEED.

The anti-rollback state helpers are also exercised directly for the
replay/rollback/monotonic/concurrency invariants.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

import pytest

from conftest import make_artifact, make_component, make_digest, make_manifest, sha256_hex
from hermes_cli.supply_chain.errors import ManifestError
from hermes_cli.supply_chain.gate import GateAction, GateResult, guard_install
from hermes_cli.supply_chain.manifest import ReleaseManifest
from hermes_cli.supply_chain.publish_cli import publish_component
from hermes_cli.supply_chain.state import (
    RollbackState,
    commit_release_state,
    load_state,
    save_state,
)
from hermes_cli.supply_chain.transaction import PublishTxnResult
from hermes_cli.supply_chain.verifier import SupplyChainVerifier

_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
_PAYLOAD = b"release-verified-artifact-bytes"
_SHA = sha256_hex(_PAYLOAD)


def _rv_manifest(*, sequence=5, min_sequence=1, version="1.2.3", floor=None):
    art = make_artifact(platform="linux", arch="x86_64", digest=make_digest(value=_SHA))
    comp = make_component(
        name="demo", version=version, trust_class="release_verified",
        artifacts=[art], security_floor=floor,
    )
    return ReleaseManifest.from_dict(
        make_manifest(sequence=sequence, min_sequence=min_sequence, components=[comp]),
        source_path=None,
    )


def _transport_manifest(*, sequence=5):
    art = make_artifact(platform="linux", arch="x86_64")
    comp = make_component(
        name="demo", version="1.2.3", trust_class="transport_trusted", artifacts=[art],
    )
    return ReleaseManifest.from_dict(
        make_manifest(sequence=sequence, components=[comp]), source_path=None
    )


def _verifier(manifest, state_path, *, seq_in_memory=0, components=None):
    state = RollbackState(manifest_sequence=seq_in_memory, components=components or {}, path=state_path)
    return SupplyChainVerifier(manifest, state=state, now=_NOW)


def _stage(tmp_path, name="stage", content=b"payload-tree"):
    d = tmp_path / name
    d.mkdir()
    (d / "file.bin").write_bytes(content)
    return d


# ── guard_install is PLAN-ONLY (A6) ─────────────────────────────────────────

def test_guard_proceed_is_plan_only_and_writes_no_state(tmp_path):
    sp = tmp_path / "state.json"
    verifier = _verifier(_rv_manifest(sequence=5), sp)

    result = guard_install("demo", platform="linux", arch="x86_64", verifier=verifier, enforce=True)

    assert result.action is GateAction.PROCEED, result.reason
    # The plan commits NOTHING — the high-water mark is advanced only by the
    # publish transaction, never by the guard.
    assert not sp.exists(), "guard_install must not write anti-rollback state"


def test_guard_transport_trusted_fails_closed_without_operator(tmp_path):
    sp = tmp_path / "state.json"
    verifier = _verifier(_transport_manifest(), sp)
    result = guard_install("demo", platform="linux", arch="x86_64", verifier=verifier, enforce=True)
    assert result.action is GateAction.FAIL_CLOSED
    assert not sp.exists()


def test_guard_transport_trusted_prefers_operator_binary(tmp_path):
    sp = tmp_path / "state.json"
    verifier = _verifier(_transport_manifest(), sp)
    result = guard_install(
        "demo", platform="linux", arch="x86_64",
        operator_probe=lambda: "/usr/bin/demo", verifier=verifier, enforce=True,
    )
    assert result.action is GateAction.USE_OPERATOR
    assert result.operator_path == "/usr/bin/demo"


# ── the real sink: plan -> stage -> publish -> commit-after ─────────────────

def test_sink_publishes_and_commits_after_swap(tmp_path):
    sp = tmp_path / "state.json"
    verifier = _verifier(_rv_manifest(sequence=5), sp)
    stage = _stage(tmp_path)
    target = tmp_path / "live"

    res = publish_component(
        "demo", target_dir=target, stage_dir=stage, staged_sha256=_SHA,
        platform="linux", arch="x86_64", verifier=verifier, state_path=sp,
    )
    assert isinstance(res, PublishTxnResult)
    assert res.published and res.committed
    assert (target / "file.bin").read_bytes() == b"payload-tree"
    st = load_state(sp, strict=True)
    assert st.manifest_sequence == 5
    assert st.components["demo"] == "1.2.3"


def test_sink_is_monotonic_never_lowers(tmp_path):
    sp = tmp_path / "state.json"
    save_state(RollbackState(manifest_sequence=5, components={"demo": "1.2.3"}), sp)
    verifier = _verifier(_rv_manifest(sequence=9, version="1.3.0"), sp, seq_in_memory=5, components={"demo": "1.2.3"})
    res = publish_component(
        "demo", target_dir=tmp_path / "live", stage_dir=_stage(tmp_path), staged_sha256=_SHA,
        platform="linux", arch="x86_64", verifier=verifier, state_path=sp,
    )
    assert res.published and res.committed
    st = load_state(sp, strict=True)
    assert st.manifest_sequence == 9
    assert st.components["demo"] == "1.3.0"


# ── replay / downgrade / rollback fail closed ───────────────────────────────

def test_replay_reflected_in_memory_fails_closed_at_plan(tmp_path):
    """The in-memory state already reflects the high-water, so PLAN's freshness
    check rejects the replayed manifest — the sink returns the fail-closed plan
    and never stages/publishes."""
    sp = tmp_path / "state.json"
    save_state(RollbackState(manifest_sequence=10), sp)
    verifier = _verifier(_rv_manifest(sequence=5), sp, seq_in_memory=10)
    target = tmp_path / "live"

    res = publish_component(
        "demo", target_dir=target, stage_dir=_stage(tmp_path), staged_sha256=_SHA,
        platform="linux", arch="x86_64", verifier=verifier, state_path=sp,
    )
    assert isinstance(res, GateResult) and res.action is GateAction.FAIL_CLOSED
    assert not target.exists()
    assert load_state(sp, strict=True).manifest_sequence == 10


def test_toctou_advance_caught_under_lock_preserves_old(tmp_path):
    """PLAN saw stale in-memory state (0) and PROCEEDed; the LOCKED recheck
    re-reads disk (12) and refuses the stale manifest — the previous install is
    preserved and the high-water is not lowered."""
    sp = tmp_path / "state.json"
    save_state(RollbackState(manifest_sequence=12), sp)  # a concurrent process advanced
    verifier = _verifier(_rv_manifest(sequence=5), sp, seq_in_memory=0)  # stale in memory
    target = tmp_path / "live"
    target.mkdir()
    (target / "file.bin").write_bytes(b"OLD-WORKING")

    with pytest.raises(ManifestError):
        publish_component(
            "demo", target_dir=target, stage_dir=_stage(tmp_path, content=b"STALE"),
            staged_sha256=_SHA, platform="linux", arch="x86_64",
            verifier=verifier, state_path=sp,
        )
    assert (target / "file.bin").read_bytes() == b"OLD-WORKING", "old install preserved"
    assert load_state(sp, strict=True).manifest_sequence == 12  # not lowered


def test_component_rollback_fails_closed_at_plan(tmp_path):
    """The in-memory state records demo 2.0.0, so PLAN's floor check rejects the
    older 1.2.3 — the sink returns the fail-closed plan without publishing."""
    sp = tmp_path / "state.json"
    save_state(RollbackState(manifest_sequence=0, components={"demo": "2.0.0"}), sp)
    verifier = _verifier(_rv_manifest(sequence=5, version="1.2.3"), sp, seq_in_memory=0, components={"demo": "2.0.0"})
    target = tmp_path / "live"

    res = publish_component(
        "demo", target_dir=target, stage_dir=_stage(tmp_path), staged_sha256=_SHA,
        platform="linux", arch="x86_64", verifier=verifier, state_path=sp,
    )
    assert isinstance(res, GateResult) and res.action is GateAction.FAIL_CLOSED
    assert not target.exists()


def test_component_rollback_toctou_caught_under_lock_preserves_old(tmp_path):
    """PLAN's in-memory state has NO component record (passes), but the on-disk
    state records demo 2.0.0 from a concurrent install; the LOCKED recheck
    refuses the 1.2.3 downgrade and preserves the previous install."""
    sp = tmp_path / "state.json"
    save_state(RollbackState(manifest_sequence=0, components={"demo": "2.0.0"}), sp)
    verifier = _verifier(_rv_manifest(sequence=5, version="1.2.3"), sp, seq_in_memory=0)  # no in-memory component
    target = tmp_path / "live"
    target.mkdir()
    (target / "file.bin").write_bytes(b"OLD-2.0.0")

    with pytest.raises(ManifestError):
        publish_component(
            "demo", target_dir=target, stage_dir=_stage(tmp_path, content=b"DOWNGRADE"),
            staged_sha256=_SHA, platform="linux", arch="x86_64",
            verifier=verifier, state_path=sp,
        )
    assert (target / "file.bin").read_bytes() == b"OLD-2.0.0", "old install preserved"


def test_sink_non_release_verified_returns_plan_without_publishing(tmp_path):
    sp = tmp_path / "state.json"
    verifier = _verifier(_transport_manifest(), sp)
    target = tmp_path / "live"
    res = publish_component(
        "demo", target_dir=target, stage_dir=_stage(tmp_path), staged_sha256=_SHA,
        platform="linux", arch="x86_64", verifier=verifier, state_path=sp,
    )
    assert isinstance(res, GateResult) and res.action is GateAction.FAIL_CLOSED
    assert not target.exists()
    assert not sp.exists()


# ── downloaded manifest with a forged signer never reaches PROCEED ──────────

def test_guard_downloaded_forged_signer_fails_closed(tmp_path):
    sp = tmp_path / "state.json"
    manifest = _rv_manifest(sequence=5)
    state = RollbackState(path=sp)
    verifier = SupplyChainVerifier(
        manifest, state=state, now=_NOW, downloaded=True,
        attestation_verifier=lambda p, s: True,  # even a "passing" attestation...
    )
    # ...cannot help: plan() refuses a downloaded manifest before verify_trust_root,
    # so the chokepoint fails closed rather than PROCEED.
    result = guard_install("demo", platform="linux", arch="x86_64", verifier=verifier, enforce=True)
    assert result.action is GateAction.FAIL_CLOSED, result.reason
    assert not sp.exists() or load_state(sp, strict=True).manifest_sequence == 0


# ── commit_release_state invariants (direct) ────────────────────────────────

def test_commit_release_state_rejects_replay(tmp_path):
    sp = tmp_path / "state.json"
    save_state(RollbackState(manifest_sequence=10), sp)
    with pytest.raises(ManifestError):
        commit_release_state(manifest_sequence=5, path=sp)


def test_commit_release_state_rejects_component_rollback(tmp_path):
    sp = tmp_path / "state.json"
    save_state(RollbackState(manifest_sequence=1, components={"demo": "2.0.0"}), sp)
    with pytest.raises(ManifestError):
        commit_release_state(manifest_sequence=2, component=("demo", "1.0.0"), path=sp)


def test_commit_release_state_enforces_security_floor(tmp_path):
    sp = tmp_path / "state.json"
    with pytest.raises(ManifestError):
        commit_release_state(
            manifest_sequence=2, component=("demo", "1.0.0"),
            security_floor="1.5.0", path=sp,
        )


def test_commit_release_state_is_monotonic_and_serialized(tmp_path):
    sp = tmp_path / "state.json"
    save_state(RollbackState(manifest_sequence=0), sp)

    seqs = [3, 7, 5, 9, 2, 8]
    errors: list = []

    def _worker(seq):
        try:
            commit_release_state(manifest_sequence=seq, path=sp)
        except ManifestError:
            pass  # a lower-than-current seq is a legit replay refusal under the race
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=_worker, args=(s,)) for s in seqs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert load_state(sp, strict=True).manifest_sequence == max(seqs)

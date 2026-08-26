"""WP4 A6: the release-verified publication transaction (behavioral).

Exercises the REAL verifier + state + atomic_publish through
``transaction.publish_release_verified``:

  * a real caller stages -> verifies -> publishes -> commits (target lands, the
    high-water mark advances) — the transaction is the production chokepoint;
  * a staged-digest mismatch refuses to publish and never touches the target;
  * commit happens ONLY after a successful publish — a deferred/failed publish
    never advances the high-water mark;
  * the concurrency invariant: an OLD (lower-sequence) publisher that stages then
    stalls, after a NEW (N+1) publisher commits under the lock, has its
    under-lock recheck FAIL and cannot overwrite the newer install.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from conftest import make_artifact, make_component, make_digest, make_manifest, sha256_hex

from hermes_cli.supply_chain.errors import ManifestError, VerificationError
from hermes_cli.supply_chain.manifest import ReleaseManifest
from hermes_cli.supply_chain.publish import PublishResult, atomic_publish
from hermes_cli.supply_chain.state import (
    commit_state,
    load_state,
    reset_state,
)
from hermes_cli.supply_chain.transaction import publish_release_verified
from hermes_cli.supply_chain.verifier import SupplyChainVerifier

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
_PAYLOAD = b"release-verified-artifact-bytes"
_SHA = sha256_hex(_PAYLOAD)


def _verifier(tmp_path: Path, *, sequence: int, version: str = "1.2.3", state_path=None):
    art = make_artifact(digest=make_digest(value=_SHA))
    comp = make_component(name="demo", version=version, artifacts=[art])
    data = make_manifest(sequence=sequence, components=[comp])
    manifest = ReleaseManifest.from_dict(data)
    sp = state_path or (tmp_path / "state.json")
    state = load_state(sp, strict=False)
    v = SupplyChainVerifier(manifest, state=state, now=_NOW)
    component = manifest.component("demo")
    artifact = component.artifact("linux", "x86_64")
    return v, component, artifact, sp


def _stage(tmp_path: Path, name: str, content: bytes = b"payload-tree") -> Path:
    d = tmp_path / name
    d.mkdir()
    (d / "file.bin").write_bytes(content)
    return d


# ── real caller: stage -> verify -> publish -> commit ───────────────────────


def test_real_caller_publishes_and_commits(tmp_path):
    v, comp, art, sp = _verifier(tmp_path, sequence=7)
    stage = _stage(tmp_path, "stage")
    target = tmp_path / "live"

    res = publish_release_verified(
        v, comp, art, staged_sha256=_SHA, stage_dir=stage, target_dir=target,
        state_path=sp,
    )
    assert res.published and res.committed
    assert (target / "file.bin").read_bytes() == b"payload-tree"
    # high-water advanced + component recorded
    st = load_state(sp, strict=True)
    assert st.manifest_sequence == 7
    assert st.components["demo"] == "1.2.3"


def test_digest_mismatch_refuses_and_leaves_target_untouched(tmp_path):
    v, comp, art, sp = _verifier(tmp_path, sequence=7)
    stage = _stage(tmp_path, "stage")
    target = tmp_path / "live"

    with pytest.raises(VerificationError):
        publish_release_verified(
            v, comp, art, staged_sha256=sha256_hex(b"WRONG"),
            stage_dir=stage, target_dir=target, state_path=sp,
        )
    assert not target.exists(), "target must not be published on a digest mismatch"
    # high-water NOT advanced
    assert load_state(sp, strict=False).manifest_sequence == 0


def test_replay_downgrade_blocked_under_lock(tmp_path):
    sp = tmp_path / "state.json"
    commit_state(manifest_sequence=10, path=sp)  # machine already at 10
    v, comp, art, _sp = _verifier(tmp_path, sequence=5, state_path=sp)  # stale N=5
    stage = _stage(tmp_path, "stage")
    target = tmp_path / "live"

    with pytest.raises(ManifestError):
        publish_release_verified(
            v, comp, art, staged_sha256=_SHA, stage_dir=stage, target_dir=target,
            state_path=sp,
        )
    assert not target.exists()
    assert load_state(sp, strict=True).manifest_sequence == 10  # unchanged


def test_never_commit_before_publish_on_deferred(tmp_path):
    v, comp, art, sp = _verifier(tmp_path, sequence=7)
    stage = _stage(tmp_path, "stage")
    target = tmp_path / "live"

    def _deferred_publish(staged, tgt, *, in_use=False, keep_backup=False):
        return PublishResult(published=False, rolled_back=False, deferred=True, reason="in use")

    res = publish_release_verified(
        v, comp, art, staged_sha256=_SHA, stage_dir=stage, target_dir=target,
        state_path=sp, _publish=_deferred_publish,
    )
    assert res.published is False and res.committed is False and res.deferred is True
    # a failed/deferred publish MUST NOT advance the high-water mark
    assert load_state(sp, strict=False).manifest_sequence == 0


def test_state_write_failure_rolls_back_publish(tmp_path, monkeypatch):
    """If the anti-rollback state commit fails AFTER the atomic swap, the publish
    is rolled back — the PREVIOUS working install is restored and the high-water
    mark is not advanced (never a published-but-uncommitted install)."""
    v, comp, art, sp = _verifier(tmp_path, sequence=7)
    target = tmp_path / "live"
    target.mkdir()
    (target / "file.bin").write_bytes(b"OLD-WORKING")
    stage = _stage(tmp_path, "stage", b"NEW-PAYLOAD")

    import hermes_cli.supply_chain.transaction as txn_mod

    def _boom(state, path):
        raise OSError("disk full during state commit")

    monkeypatch.setattr(txn_mod, "save_state", _boom)

    with pytest.raises(OSError):
        publish_release_verified(
            v, comp, art, staged_sha256=_SHA, stage_dir=stage, target_dir=target,
            state_path=sp,
        )
    # rollback restored the OLD working tree, not the NEW payload
    assert (target / "file.bin").read_bytes() == b"OLD-WORKING"
    # high-water NOT advanced (no committed state)
    assert load_state(sp, strict=False).manifest_sequence == 0


# ── concurrency: old stalls, N+1 publishes, old recheck fails ───────────────


def test_old_publisher_cannot_overwrite_newer_after_commit(tmp_path):
    """OLD (seq 5) stages then stalls; NEW (seq 6) publishes+commits under the
    lock; OLD's under-lock recheck then fails and cannot overwrite."""
    sp = tmp_path / "state.json"
    reset_state(sp)
    target = tmp_path / "live"

    new_v, new_c, new_a, _ = _verifier(tmp_path, sequence=6, version="2.0.0", state_path=sp)
    old_v, old_c, old_a, _ = _verifier(tmp_path, sequence=5, version="1.0.0", state_path=sp)
    new_stage = _stage(tmp_path, "new_stage", b"NEW-2.0.0")
    old_stage = _stage(tmp_path, "old_stage", b"OLD-1.0.0")

    new_done = threading.Event()
    errors: list[Exception] = []
    old_result: dict = {}

    def _old():
        new_done.wait(timeout=10)  # stall until NEW has committed
        try:
            old_result["res"] = publish_release_verified(
                old_v, old_c, old_a, staged_sha256=_SHA, stage_dir=old_stage,
                target_dir=target, state_path=sp,
            )
        except Exception as exc:  # noqa: BLE001
            old_result["exc"] = exc

    t = threading.Thread(target=_old)
    t.start()

    new_res = publish_release_verified(
        new_v, new_c, new_a, staged_sha256=_SHA, stage_dir=new_stage,
        target_dir=target, state_path=sp,
    )
    new_done.set()
    t.join(timeout=15)

    assert new_res.published and new_res.committed
    # OLD must have FAILED its recheck (replay/downgrade) — never published.
    assert isinstance(old_result.get("exc"), ManifestError), old_result
    # The live target still holds the NEWER install; OLD did not overwrite it.
    assert (target / "file.bin").read_bytes() == b"NEW-2.0.0"
    st = load_state(sp, strict=True)
    assert st.manifest_sequence == 6
    assert st.components["demo"] == "2.0.0"


def test_racing_publishers_never_lose_newer(tmp_path):
    """Two publishers race for the lock with a barrier; regardless of order the
    final high-water is the max and the target holds the newer content (the
    stale one, if it runs second, fails its recheck)."""
    sp = tmp_path / "state.json"
    reset_state(sp)
    target = tmp_path / "live"
    barrier = threading.Barrier(2)
    results: dict = {}

    def _run(seq, version, content, key):
        v, c, a, _ = _verifier(tmp_path, sequence=seq, version=version, state_path=sp)
        stage = _stage(tmp_path, f"stage_{key}", content)
        barrier.wait()
        try:
            results[key] = publish_release_verified(
                v, c, a, staged_sha256=_SHA, stage_dir=stage, target_dir=target,
                state_path=sp,
            )
        except Exception as exc:  # noqa: BLE001
            results[key] = exc

    t1 = threading.Thread(target=_run, args=(5, "1.0.0", b"OLD", "old"))
    t2 = threading.Thread(target=_run, args=(6, "2.0.0", b"NEW", "new"))
    t1.start(); t2.start(); t1.join(15); t2.join(15)

    st = load_state(sp, strict=True)
    assert st.manifest_sequence == 6, st.manifest_sequence  # newer always wins
    assert st.components["demo"] == "2.0.0"
    # NEW published successfully; the target holds NEW.
    assert (target / "file.bin").read_bytes() == b"NEW"

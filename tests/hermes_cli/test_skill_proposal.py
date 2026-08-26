"""Behavior tests for the A4 propose -> activate skill-hub flow.

These exercise the real :mod:`hermes_cli.skill_proposal` orchestration against
injected fakes and a REAL on-disk quarantine directory, so drift/replay/mutation
are proven by behavior, never by reading source text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from hermes_cli import skill_proposal as sp


COMMIT = "a" * 40
DIGEST = "b" * 64


@dataclass
class FakeBundle:
    name: str = "weather"
    source: str = "github"
    identifier: str = "acme/weather"
    files: Dict[str, str] = field(default_factory=lambda: {"SKILL.md": "hi"})
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FakeScan:
    skill_name: str = "weather"
    scan_provenance: Dict[str, Any] = field(default_factory=lambda: {"src": "github"})
    verdict: str = "safe"


def _make_quarantine(tmp_path: Path, content: str = "hello") -> Path:
    q = tmp_path / "q" / "weather"
    q.mkdir(parents=True, exist_ok=True)
    (q / "SKILL.md").write_text(content, encoding="utf-8")
    return q


def _propose_deps(
    tmp_path: Path,
    *,
    bundle: Optional[FakeBundle] = None,
    commit: Optional[str] = COMMIT,
    digest: str = DIGEST,
    policy: Tuple[Optional[bool], str] = (True, "allow"),
    resolve: Optional[Any] = None,
) -> Tuple[sp.ProposeDeps, Path, List[str]]:
    b = bundle or FakeBundle()
    q = _make_quarantine(tmp_path)
    ids = iter(["prop-1", "prop-2", "prop-3"])

    def _resolve(identifier: str):
        if resolve is not None:
            return resolve(identifier)
        return (None, b)

    deps = sp.ProposeDeps(
        resolve_bundle=_resolve,
        quarantine=lambda _b: q,
        scan=lambda _p, _s: FakeScan(),
        policy=lambda _r: policy,
        digest_of=lambda _b: digest,
        commit_of=lambda _b: commit,
        id_factory=lambda: next(ids),
        clock=lambda: 1000.0,
    )
    return deps, q, []


@pytest.fixture(autouse=True)
def fresh_store():
    previous = sp._set_store_for_test(sp.ProposalStore(clock=lambda: 1000.0))
    try:
        yield
    finally:
        sp._set_store_for_test(previous)


def _install_recorder() -> Tuple[sp.ActivateDeps, List[sp.Proposal]]:
    installed: List[sp.Proposal] = []

    def _install(record: sp.Proposal) -> Path:
        installed.append(record)
        return Path("/skills") / record.name

    return sp.ActivateDeps(install=_install), installed


# ---------------------------------------------------------------------------
# propose
# ---------------------------------------------------------------------------
def test_propose_returns_nonsecret_identity_and_stores(tmp_path):
    deps, _q, _ = _propose_deps(tmp_path)

    out = sp.propose("acme/weather", deps)

    assert out["proposal_id"] == "prop-1"
    assert out["commit"] == COMMIT
    assert out["digest"] == DIGEST
    assert out["policy"] == "allow"
    assert out["identifier"] == "acme/weather"
    assert out["name"] == "weather"
    # Stored exactly once, ready for a single activate.
    assert len(sp.get_store()) == 1


def test_propose_unknown_identifier_raises_not_found(tmp_path):
    deps, _q, _ = _propose_deps(tmp_path, resolve=lambda _i: None)

    with pytest.raises(sp.ProposalNotFound):
        sp.propose("nope/nope", deps)
    assert len(sp.get_store()) == 0


def test_propose_none_bundle_discards_and_raises(tmp_path):
    deps, _q, _ = _propose_deps(tmp_path, resolve=lambda _i: (None, None))

    with pytest.raises(sp.ProposalNotFound):
        sp.propose("acme/weather", deps)


# ---------------------------------------------------------------------------
# activate — happy path
# ---------------------------------------------------------------------------
def test_activate_success_installs_with_matching_identity(tmp_path):
    deps, _q, _ = _propose_deps(tmp_path)
    out = sp.propose("acme/weather", deps)

    act, installed = _install_recorder()
    result = sp.activate_proposal(out["proposal_id"], COMMIT, DIGEST, act)

    assert result["ok"] is True
    assert len(installed) == 1
    assert installed[0].digest == DIGEST
    assert installed[0].commit == COMMIT
    # Consumed — the store is now empty.
    assert len(sp.get_store()) == 0


def test_activate_case_insensitive_identity(tmp_path):
    deps, _q, _ = _propose_deps(tmp_path)
    out = sp.propose("acme/weather", deps)

    act, installed = _install_recorder()
    sp.activate_proposal(out["proposal_id"], COMMIT.upper(), DIGEST.upper(), act)
    assert len(installed) == 1


# ---------------------------------------------------------------------------
# activate — drift / replay / mutation / policy
# ---------------------------------------------------------------------------
def test_activate_commit_drift_rejected(tmp_path):
    deps, _q, _ = _propose_deps(tmp_path)
    out = sp.propose("acme/weather", deps)

    act, installed = _install_recorder()
    with pytest.raises(sp.CommitDrift):
        sp.activate_proposal(out["proposal_id"], "c" * 40, DIGEST, act)
    assert installed == []
    # Consumed even on failure — no second attempt with the same id.
    assert len(sp.get_store()) == 0


def test_activate_digest_drift_rejected(tmp_path):
    deps, _q, _ = _propose_deps(tmp_path)
    out = sp.propose("acme/weather", deps)

    act, installed = _install_recorder()
    with pytest.raises(sp.DigestDrift):
        sp.activate_proposal(out["proposal_id"], COMMIT, "d" * 64, act)
    assert installed == []


def test_activate_replay_rejected(tmp_path):
    deps, _q, _ = _propose_deps(tmp_path)
    out = sp.propose("acme/weather", deps)

    act, installed = _install_recorder()
    sp.activate_proposal(out["proposal_id"], COMMIT, DIGEST, act)
    # Second activate with the same id is a replay.
    with pytest.raises(sp.ProposalReplay):
        sp.activate_proposal(out["proposal_id"], COMMIT, DIGEST, act)
    assert len(installed) == 1


def test_activate_unknown_id_rejected(tmp_path):
    act, installed = _install_recorder()
    with pytest.raises(sp.ProposalReplay):
        sp.activate_proposal("does-not-exist", COMMIT, DIGEST, act)
    assert installed == []


def test_activate_ondisk_mutation_rejected(tmp_path):
    deps, q, _ = _propose_deps(tmp_path)
    out = sp.propose("acme/weather", deps)

    # Tamper with the quarantined artifact AFTER it was proposed.
    (q / "SKILL.md").write_text("MALICIOUS", encoding="utf-8")

    act, installed = _install_recorder()
    with pytest.raises(sp.BundleMutation):
        sp.activate_proposal(out["proposal_id"], COMMIT, DIGEST, act)
    assert installed == []


def test_activate_policy_block_rejected(tmp_path):
    deps, _q, _ = _propose_deps(tmp_path, policy=(False, "dangerous"))
    out = sp.propose("acme/weather", deps)
    assert out["policy"] == "block"

    act, installed = _install_recorder()
    with pytest.raises(sp.PolicyBlocked):
        sp.activate_proposal(out["proposal_id"], COMMIT, DIGEST, act)
    assert installed == []


def test_activate_policy_block_allowed_with_break_glass(tmp_path):
    deps, _q, _ = _propose_deps(tmp_path, policy=(False, "dangerous"))
    out = sp.propose("acme/weather", deps)

    act, installed = _install_recorder()
    act.allow_blocked = True
    sp.activate_proposal(out["proposal_id"], COMMIT, DIGEST, act)
    assert len(installed) == 1


# ---------------------------------------------------------------------------
# network source (no transport commit): the DIGEST is the identity, so a raw
# "accept" without the exact digest can never activate.
# ---------------------------------------------------------------------------
def test_network_source_requires_exact_digest(tmp_path):
    deps, _q, _ = _propose_deps(tmp_path, commit=None)
    out = sp.propose("acme/weather", deps)
    assert out["commit"] is None

    act, installed = _install_recorder()
    # Wrong digest -> rejected even though "commit" is null on both sides.
    with pytest.raises(sp.DigestDrift):
        sp.activate_proposal(out["proposal_id"], None, "e" * 64, act)
    assert installed == []


def test_network_source_activates_on_exact_digest(tmp_path):
    deps, _q, _ = _propose_deps(tmp_path, commit=None)
    out = sp.propose("acme/weather", deps)

    act, installed = _install_recorder()
    sp.activate_proposal(out["proposal_id"], None, DIGEST, act)
    assert len(installed) == 1


# ---------------------------------------------------------------------------
# store: TTL + single-use + eviction discards quarantine trees
# ---------------------------------------------------------------------------
def test_store_ttl_expiry_discards_and_replays(tmp_path):
    now = {"t": 0.0}
    discarded: List[Path] = []
    store = sp.ProposalStore(
        ttl_seconds=100.0, clock=lambda: now["t"], discard=lambda p: discarded.append(p)
    )
    sp._set_store_for_test(store)

    deps, q, _ = _propose_deps(tmp_path)
    # Give the propose path the same clock so created_at lines up.
    deps.clock = lambda: now["t"]
    out = sp.propose("acme/weather", deps)

    now["t"] = 1000.0  # well past TTL
    act, installed = _install_recorder()
    with pytest.raises(sp.ProposalReplay):
        sp.activate_proposal(out["proposal_id"], COMMIT, DIGEST, act)
    assert q in discarded
    assert installed == []


def test_store_eviction_discards_oldest(tmp_path):
    discarded: List[Path] = []
    store = sp.ProposalStore(
        max_entries=1, clock=lambda: 5.0, discard=lambda p: discarded.append(p)
    )
    sp._set_store_for_test(store)

    q1 = tmp_path / "a"
    q1.mkdir()
    q2 = tmp_path / "b"
    q2.mkdir()
    rec1 = _record("id1", q1)
    rec2 = _record("id2", q2)
    store.put(rec1)
    store.put(rec2)  # evicts id1

    assert q1 in discarded
    assert store.consume("id1") is None
    assert store.consume("id2") is not None


def _record(pid: str, q: Path) -> sp.Proposal:
    return sp.Proposal(
        proposal_id=pid,
        identifier="acme/x",
        name="x",
        source="github",
        commit=COMMIT,
        digest=DIGEST,
        tree_digest=DIGEST,
        quarantine_path=q,
        bundle=FakeBundle(),
        scan_result=FakeScan(),
        scan_provenance={},
        category="",
        policy="allow",
        policy_reason="allow",
        created_at=5.0,
    )

"""Integration tests for the A4 propose -> activate hub endpoints.

Drives the real FastAPI handlers, the real quarantine, and the real WP4
activation gate (:func:`tools.skills_hub.install_from_quarantine`) against an
isolated ``HERMES_HOME``. Proves the endpoints mint ``activation_accepted``
server-side only after the confirmed identity matches the quarantined artifact,
and that commit drift / digest drift / replay fail closed with a stable reason.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _fresh_proposal_store():
    """Give every test a clean, single-use proposal store.

    ``hermes_cli.skill_proposal._STORE`` is a process-global; without this the
    propose/activate endpoints share one store across the whole file, so a
    proposal minted (or left dangling) by one test leaks into the next and the
    endpoint outcomes become order-dependent. Mirrors the ``fresh_store``
    isolation in tests/hermes_cli/test_skill_proposal.py.
    """
    from hermes_cli import skill_proposal as sp

    previous = sp._set_store_for_test(sp.ProposalStore())
    try:
        yield
    finally:
        sp._set_store_for_test(previous)


@pytest.fixture
def client(monkeypatch, _isolate_hermes_home, _fresh_proposal_store):
    try:
        from starlette.testclient import TestClient
    except ImportError:
        pytest.skip("fastapi/starlette not installed")

    import hermes_state
    from hermes_constants import get_hermes_home
    from hermes_cli import web_server
    from hermes_cli.web_server import app, _SESSION_HEADER_NAME

    # Re-seed a known session token and drive both the server global and the
    # request header from the SAME local value. This makes auth independent of
    # any leaked/blank _SESSION_TOKEN an earlier test may have installed via
    # _apply_ssh_session_token(...); monkeypatch restores the original on
    # teardown so this file never leaks its token outward either.
    token = web_server._resolve_session_token()
    monkeypatch.setattr(web_server, "_SESSION_TOKEN", token)

    home = get_hermes_home()
    (home / "skills").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(hermes_state, "DEFAULT_DB_PATH", home / "state.db")
    c = TestClient(app)
    c.headers[_SESSION_HEADER_NAME] = token
    return c


def _make_bundle(commit: str = "a" * 40):
    from tools.skills_hub import SkillBundle

    return SkillBundle(
        name="weathertest",
        files={
            "SKILL.md": (
                "---\nname: weathertest\ndescription: A tiny test skill.\n---\n\n"
                "# Weathertest\n\nJust a benign test skill.\n"
            )
        },
        source="github",
        identifier="acme/weathertest",
        trust_level="community",
        metadata={"resolved_commit": commit},
    )


def _patch_resolver(monkeypatch, bundle):
    import hermes_cli.skills_hub as cli_hub
    import tools.skills_hub as hub

    monkeypatch.setattr(hub, "create_source_router", lambda: [])
    monkeypatch.setattr(
        cli_hub,
        "_resolve_source_meta_and_bundle",
        lambda identifier, sources: (None, bundle, None),
    )


def test_propose_returns_identity_then_activate_installs(client, monkeypatch):
    _patch_resolver(monkeypatch, _make_bundle())

    r = client.post("/api/skills/hub/propose", json={"identifier": "acme/weathertest"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["commit"] == "a" * 40
    assert len(body["digest"]) == 64
    assert body["policy"] in ("allow", "ask")
    pid = body["proposal_id"]

    r2 = client.post(
        "/api/skills/hub/activate",
        json={"proposal_id": pid, "commit": "a" * 40, "digest": body["digest"]},
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["ok"] is True

    # Replay: the proposal was atomically consumed.
    r3 = client.post(
        "/api/skills/hub/activate",
        json={"proposal_id": pid, "commit": "a" * 40, "digest": body["digest"]},
    )
    assert r3.status_code == 409
    assert r3.json()["detail"]["reason"] == "replay"


def test_activate_commit_drift_rejected(client, monkeypatch):
    _patch_resolver(monkeypatch, _make_bundle())
    body = client.post(
        "/api/skills/hub/propose", json={"identifier": "acme/weathertest"}
    ).json()

    r = client.post(
        "/api/skills/hub/activate",
        json={"proposal_id": body["proposal_id"], "commit": "c" * 40, "digest": body["digest"]},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["reason"] == "commit-drift"


def test_activate_digest_drift_rejected(client, monkeypatch):
    _patch_resolver(monkeypatch, _make_bundle())
    body = client.post(
        "/api/skills/hub/propose", json={"identifier": "acme/weathertest"}
    ).json()

    r = client.post(
        "/api/skills/hub/activate",
        json={"proposal_id": body["proposal_id"], "commit": "a" * 40, "digest": "d" * 64},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["reason"] == "digest-drift"


def test_activate_unknown_proposal_rejected(client):
    r = client.post(
        "/api/skills/hub/activate",
        json={"proposal_id": "nope", "commit": "a" * 40, "digest": "b" * 64},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["reason"] == "replay"


def test_propose_unknown_identifier_404(client, monkeypatch):
    import hermes_cli.skills_hub as cli_hub
    import tools.skills_hub as hub

    monkeypatch.setattr(hub, "create_source_router", lambda: [])
    monkeypatch.setattr(
        cli_hub, "_resolve_source_meta_and_bundle", lambda i, s: (None, None, None)
    )
    r = client.post("/api/skills/hub/propose", json={"identifier": "acme/missing"})
    assert r.status_code == 404

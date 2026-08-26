"""Shared builders for supply-chain behavioral tests.

These construct in-memory manifest/ledger dicts so each test exercises the real
loaders and verifier against controlled data — never the committed production
manifest (whose values are expected to change) and never source text.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

_HEX64 = "a" * 64


@pytest.fixture
def sc_config(monkeypatch):
    """Control the supply-chain gate posture without env vars or real config.

    Returns a mutable ``security.supply_chain`` dict the gate reads live. Mutate
    it to opt a component in/out. Default is secure: ``enforce=True`` with an
    empty allow-list, so every mutable installer fails closed.

    This replaces the removed ``HERMES_ALLOW_UNVERIFIED_BOOTSTRAP`` /
    ``HERMES_SUPPLY_CHAIN_ENFORCE`` env vars — the Python gate is config-only.
    """
    from hermes_cli.supply_chain import gate as _gate

    cfg: dict = {"enforce": True, "allow_unverified_components": []}
    monkeypatch.setattr(_gate, "_sc_config", lambda: cfg)
    return cfg


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_digest(value: str | None = _HEX64, status: str = "present") -> dict:
    return {"algorithm": "sha256", "value": value, "status": status}


def make_artifact(
    platform: str = "linux",
    arch: str = "x86_64",
    url: str = "https://github.com/astral-sh/uv/releases",
    digest: dict | None = None,
    members: tuple[str, ...] = (),
    provenance: dict | None = None,
    blocker: str | None = None,
    operator_guidance: str | None = None,
) -> dict:
    art: dict[str, Any] = {
        "platform": platform,
        "arch": arch,
        "url": url,
        "digest": digest if digest is not None else make_digest(),
        "members": list(members),
    }
    if provenance is not None:
        art["provenance"] = provenance
    if blocker is not None:
        art["blocker"] = blocker
    if operator_guidance is not None:
        art["operator_guidance"] = operator_guidance
    return art


def make_component(
    name: str = "demo",
    version: str = "1.2.3",
    trust_class: str = "release_verified",
    artifacts: list[dict] | None = None,
    security_floor: str | None = None,
) -> dict:
    return {
        "name": name,
        "version": version,
        "trust_class": trust_class,
        "security_floor": security_floor,
        "review_date": "2026-08-25",
        "eol": None,
        "artifacts": artifacts if artifacts is not None else [make_artifact()],
    }


def make_signer() -> dict:
    return {
        "type": "github-artifact-attestation",
        "issuer": "https://token.actions.githubusercontent.com",
        "identity_regexp": "^https://github\\.com/NousResearch/hermes-agent/\\.github/workflows/release-attest\\.yml@refs/tags/v",
        "repository": "NousResearch/hermes-agent",
        "workflow": ".github/workflows/release-attest.yml",
        "fingerprint_publication": "docs/security/supply-chain-trust-root.md",
    }


def make_manifest(
    *,
    sequence: int = 5,
    min_sequence: int = 1,
    issued_at: str = "2026-01-01T00:00:00Z",
    expires_at: str = "2099-01-01T00:00:00Z",
    components: list[dict] | None = None,
    revocations: list[dict] | None = None,
) -> dict:
    return {
        "manifest": {
            "schema_version": 1,
            "sequence": sequence,
            "min_sequence": min_sequence,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "signer": make_signer(),
            "revocations": revocations or [],
        },
        "components": components if components is not None else [make_component()],
    }


def transport_artifact(**kwargs) -> dict:
    kwargs.setdefault("digest", make_digest(value=None, status="unavailable"))
    kwargs.setdefault("blocker", "no committed digest")
    kwargs.setdefault("operator_guidance", "install via OS package")
    return make_artifact(**kwargs)

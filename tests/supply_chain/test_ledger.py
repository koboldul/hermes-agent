"""Behavioral tests over the committed ledger + manifest, and the invariant
that no ledgered production path is (yet) release-verified without an anchor."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from hermes_cli.supply_chain import (
    default_ledger_path,
    default_manifest_path,
    get_verifier,
    load_ledger,
    load_manifest,
)
from hermes_cli.supply_chain.ledger import Ledger
from hermes_cli.supply_chain.verifier import Decision

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)


def test_committed_manifest_and_ledger_load():
    manifest = load_manifest(default_manifest_path())
    ledger = load_ledger(default_ledger_path())
    assert manifest.components
    assert ledger.paths


def test_every_ledger_component_exists_in_manifest():
    manifest = load_manifest(default_manifest_path())
    ledger = load_ledger(default_ledger_path())
    names = {c.name for c in manifest.components}
    for entry in ledger.paths:
        if entry.component is not None:
            assert entry.component in names, entry.id


def test_transport_trusted_component_paths_fail_closed_release_verified_proceed():
    """A ledgered path whose component is transport_trusted fails closed under
    enforce (never silently proceeds); a release_verified component (electron,
    with committed per-target digests) is allowed to PROCEED — download, verify
    against the committed digest, publish."""
    manifest = load_manifest(default_manifest_path())
    verifier = get_verifier()
    verifier._now = _NOW  # keep the freshness check deterministic
    ledger = load_ledger(default_ledger_path())
    for entry in ledger.paths:
        if entry.component is None:
            continue
        component = manifest.component(entry.component)
        platform = entry.platforms[0] if entry.platforms else "linux"
        arch = "x86_64"
        if component.artifact(platform, arch) is None:
            continue
        plan = verifier.plan(entry.component, platform=platform, arch=arch, enforce=True)
        if component.trust_class == "release_verified":
            assert plan.decision is Decision.PROCEED, entry.id
        else:
            assert plan.decision is not Decision.PROCEED, entry.id


def test_no_ledger_entry_is_pending():
    """The secure-default migration is complete: nothing remains pending."""
    ledger = load_ledger(default_ledger_path())
    pending = [p.id for p in ledger.paths if p.migration_state == "pending"]
    assert pending == [], f"pending ledger entries remain: {pending}"


def test_metadata_and_component_paths_are_not_transport_trusted_release():
    """A release_verified path must be digest-pinned. The Docker bases pin
    @sha256; the nix fixed-output derivations pin an in-derivation sha256."""
    digest_pinned = {
        "docker-base-images", "nix-desktop-electron-headers", "nix-npm-tarball",
        "electron-builder-fetch",
        # The Electron byte-verifier enforces the COMMITTED manifest digest for
        # the target archive before extraction — it is anchored to that digest.
        "electron-dist-verifier",
    }
    ledger = load_ledger(default_ledger_path())
    for entry in ledger.paths:
        if entry.trust_owner == "release_verified":
            assert entry.id in digest_pinned, entry.id


def test_ledger_covers_matches_source_and_prefix():
    ledger = Ledger.from_dict(
        {
            "schema_version": 1,
            "paths": [
                {
                    "id": "x",
                    "description": "d",
                    "source": "hermes_cli/managed_uv.py",
                    "trust_owner": "transport_trusted",
                    "activation_point": "a",
                    "negative_test": "tests/supply_chain/test_ledger.py",
                    "platforms": ["linux"],
                    "migration_state": "pending",
                    "blocker": "b",
                },
                {
                    "id": "y",
                    "description": "d",
                    "source": "scripts/",
                    "trust_owner": "transport_trusted",
                    "activation_point": "a",
                    "negative_test": "tests/supply_chain/test_ledger.py",
                    "platforms": ["linux"],
                    "migration_state": "pending",
                    "blocker": "b",
                },
            ],
        }
    )
    assert ledger.covers("hermes_cli/managed_uv.py")
    assert ledger.covers("scripts/install.sh")  # directory prefix
    assert not ledger.covers("hermes_cli/other.py")


def test_pending_entry_requires_blocker():
    from hermes_cli.supply_chain.errors import ManifestError

    with pytest.raises(ManifestError):
        Ledger.from_dict(
            {
                "schema_version": 1,
                "paths": [
                    {
                        "id": "x",
                        "description": "d",
                        "source": "hermes_cli/managed_uv.py",
                        "trust_owner": "transport_trusted",
                        "activation_point": "a",
                        "negative_test": "tests/supply_chain/test_ledger.py",
                        "platforms": ["linux"],
                        "migration_state": "pending",
                    }
                ],
            }
        )

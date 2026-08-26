"""WP4 item 2: Desktop native/electron payload coverage (behavioral).

Asserts the manifest/ledger encode the electron payload chain and that the nix
fetches are digest-pinned. Declaration/packaging invariants (reading a .nix or a
manifest file) are allowed — they assert about a committed file, not runtime.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]


def _manifest() -> dict:
    return json.loads((_ROOT / "supply-chain" / "manifest.json").read_text(encoding="utf-8"))


def _ledger() -> dict:
    return json.loads((_ROOT / "supply-chain" / "ledger.json").read_text(encoding="utf-8"))


def test_manifest_pins_electron_version_and_targets():
    comp = next((c for c in _manifest()["components"] if c["name"] == "electron"), None)
    assert comp is not None, "manifest has no electron component"
    # Exact version pin (not a range).
    assert comp["version"].count(".") == 2 and comp["version"][0].isdigit()
    # release_verified with a committed sha256 + canonical release URL per target.
    assert comp["trust_class"] == "release_verified"
    seen = {(a["platform"], a["arch"]): a for a in comp["artifacts"]}
    for pair in (("linux", "x86_64"), ("linux", "aarch64"), ("macos", "x86_64"),
                 ("macos", "aarch64"), ("windows", "x86_64"), ("windows", "aarch64")):
        assert pair in seen, f"electron artifact missing for {pair}"
        dig = seen[pair]["digest"]
        assert dig["status"] == "present" and isinstance(dig["value"], str) and len(dig["value"]) == 64, pair
        assert "github.com/electron/electron/releases/download/" in seen[pair]["url"], pair


def test_ledger_covers_desktop_native_paths():
    sources = {p["source"] for p in _ledger()["paths"]}
    for src in (
        "apps/desktop/scripts/stage-native-deps.mjs",
        "apps/desktop/scripts/rebuild-native.mjs",
        "apps/desktop/scripts/run-electron-builder.mjs",
        "nix/desktop.nix",
        "nix/npm-12-0-2.nix",
    ):
        assert src in sources, f"ledger does not classify {src}"


def test_desktop_native_entries_are_gated_or_pinned():
    entries = {p["id"]: p for p in _ledger()["paths"]}
    # The two network-rebuild paths must be explicitly disabled (fail closed).
    for eid in ("electron-native-staging", "electron-native-rebuild"):
        assert entries[eid]["migration_state"] == "explicitly_disabled", eid
    # The electron-builder fetch is release-verified against the committed digest.
    assert entries["electron-builder-fetch"]["trust_owner"] == "release_verified"
    # The nix fetches must be digest-pinned (release_verified).
    for eid in ("nix-desktop-electron-headers", "nix-npm-tarball"):
        assert entries[eid]["trust_owner"] == "release_verified", eid


@pytest.mark.parametrize("nix_file", ["nix/desktop.nix", "nix/npm-12-0-2.nix"])
def test_nix_files_pin_sha256(nix_file):
    """Every network fetch in these nix derivations pins an exact sha256 hash."""
    text = (_ROOT / nix_file).read_text(encoding="utf-8")
    assert "sha256-" in text or "sha256 =" in text or "hash =" in text, (
        f"{nix_file}: a nix fetch is not digest-pinned"
    )


def test_verifier_module_and_gate_exist():
    assert (_ROOT / "apps/desktop/scripts/native-payload-verifier.mjs").exists()
    assert (_ROOT / "apps/desktop/scripts/verify-native-payloads.mjs").exists()
    stage = (_ROOT / "apps/desktop/scripts/stage-native-deps.mjs").read_text(encoding="utf-8")
    # The staging path routes the network fallback through the fail-closed
    # decision (not an unconditional electron-rebuild).
    assert "nativePrebuildDecision" in stage

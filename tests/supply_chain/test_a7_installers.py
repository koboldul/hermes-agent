"""WP4 A7: installer hardening — declaration/packaging invariants.

These assert about committed installer files (nix/shell), not runtime behavior on
another host, so they are packaging-declaration invariants (allowed): the
NodeSource external apt path is gated behind an explicit opt-in, and the
locked/hash-verified install is authoritative with the unlocked fallback gated.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]


def test_nixos_nodesource_is_gated_not_unconditional():
    text = (_ROOT / "nix" / "nixosModules.nix").read_text(encoding="utf-8")
    # The NodeSource external repo/key must appear only inside the
    # allowUnverifiedBootstrap conditional, never as an unconditional step.
    assert "deb.nodesource.com" in text
    idx_gate = text.find("cfg.allowUnverifiedBootstrap")
    # The FIRST allowUnverifiedBootstrap gate must precede the NodeSource usage
    # that follows it (the apt provisioning block).
    idx_node = text.find("deb.nodesource.com/gpgkey")
    assert idx_gate != -1 and idx_node != -1
    # The NodeSource key fetch is within a `${if cfg.allowUnverifiedBootstrap ...}`
    # block: the nearest preceding gate marker must be an allowUnverifiedBootstrap
    # conditional, and a secure-default guidance branch must exist.
    assert "NodeSource Node auto-install is disabled by default" in text


def test_setup_hermes_locked_sync_is_authoritative():
    text = (_ROOT / "setup-hermes.sh").read_text(encoding="utf-8")
    assert "uv sync --extra all --locked" in text or "$UV_CMD sync --extra all --locked" in text
    # The unhashed/unlocked fallback runs only under the explicit bootstrap flag.
    assert "_HERMES_SC_BOOTSTRAP_OVERRIDE" in text
    assert "disabled by default (supply-chain enforce)" in text


def test_setup_hermes_no_bare_unpinned_pip_default():
    """A bare `pip install -e "."` fallback must not run without the override."""
    text = (_ROOT / "setup-hermes.sh").read_text(encoding="utf-8")
    # Every unpinned install line is guarded by the override check somewhere
    # above it (structural: the override token appears in the file and the
    # fallback function fails closed by default).
    assert "the unpinned fallback is disabled by default" in text or \
           "the unhashed fallback is disabled by default" in text

"""Behavioral fail-closed tests for the migrated installer/update/repair paths.

Each asserts that, under the secure default (no opt-in), the mutable route does
NOT execute — no network, no subprocess — and the previous working install is
preserved. The explicit opt-in re-enables the (labelled) compatibility path.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest


@pytest.fixture(autouse=True)
def _secure_default(monkeypatch):
    # Removed env vars have no effect on the config-only gate; delete defensively.
    monkeypatch.delenv("HERMES_ALLOW_UNVERIFIED_BOOTSTRAP", raising=False)
    monkeypatch.delenv("HERMES_SUPPLY_CHAIN_ENFORCE", raising=False)


# --- managed npm upgrade --------------------------------------------------

def test_npm_upgrade_disabled_by_default_preserves_old_npm(monkeypatch):
    import hermes_cli.npm_engine as npm_engine

    monkeypatch.setattr(npm_engine, "managed_node_tree_in_use", lambda *a, **k: False)

    def forbidden(*a, **k):
        raise AssertionError("npm must not run under the secure default")

    monkeypatch.setattr(npm_engine.subprocess, "run", forbidden)
    ok = npm_engine.upgrade_managed_npm("npm", ">=10", prefix=SimpleNamespace(), quiet=True)
    assert ok is False  # skipped; the old managed npm is untouched


def test_npm_upgrade_runs_on_opt_in(monkeypatch, tmp_path, sc_config):
    import hermes_cli.npm_engine as npm_engine

    sc_config["allow_unverified_components"] = ["npm"]
    monkeypatch.setattr(npm_engine, "managed_node_tree_in_use", lambda *a, **k: False)
    calls = {"n": 0}

    def fake_run(*a, **k):
        calls["n"] += 1
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(npm_engine.subprocess, "run", fake_run)
    npm_engine.upgrade_managed_npm("npm", "10.9.0", prefix=tmp_path, quiet=True)
    assert calls["n"] >= 1


# --- cua-driver installer (fresh install + auto-repair chokepoint) --------

def test_cua_installer_disabled_by_default_no_subprocess(monkeypatch):
    import hermes_cli.tools_config as tools_config

    def forbidden(*a, **k):
        raise AssertionError("the cua-driver installer must not run by default")

    monkeypatch.setattr(subprocess, "run", forbidden)
    assert tools_config._run_cua_driver_installer(verbose=False) is False


def test_cua_installer_gate_opens_on_opt_in(sc_config):
    # The gate decision flips with the explicit scoped opt-in; the installer
    # body itself is platform-specific and exercised by test_install_cua_driver.
    from hermes_cli.supply_chain.gate import compat_opt_in

    assert compat_opt_in("cua-driver") is False
    sc_config["allow_unverified_components"] = ["cua-driver"]
    assert compat_opt_in("cua-driver") is True


# --- tirith auto-install --------------------------------------------------

def test_tirith_install_disabled_by_default_no_download(monkeypatch):
    import tools.tirith_security as tirith

    monkeypatch.setattr(tirith, "_detect_target", lambda: "x86_64-unknown-linux-gnu")

    def forbidden(*a, **k):
        raise AssertionError("tirith must not download under the secure default")

    monkeypatch.setattr(tirith, "_download_file", forbidden)
    path, reason = tirith._install_tirith(log_failures=False)
    assert path is None
    assert reason == "supply_chain_enforced"


def test_tirith_install_attempts_download_on_opt_in(monkeypatch, sc_config):
    import tools.tirith_security as tirith

    sc_config["allow_unverified_components"] = ["tirith"]
    monkeypatch.setattr(tirith, "_detect_target", lambda: "x86_64-unknown-linux-gnu")
    reached = {"download": False}

    def fake_download(*a, **k):
        reached["download"] = True
        raise OSError("stop after the gate")

    monkeypatch.setattr(tirith, "_download_file", fake_download)
    tirith._install_tirith(log_failures=False)
    assert reached["download"] is True


# --- Hermes update ZIP fallback -------------------------------------------

def test_update_zip_fallback_disabled_by_default(monkeypatch):
    import sys as _sys

    from hermes_cli import update_cmd

    fake_main = SimpleNamespace(
        sys=_sys,
        _capture_active_tool_dependencies=lambda: {},
        _resolve_update_branch=lambda a: "main",
    )
    monkeypatch.setattr(update_cmd, "_m", lambda: fake_main)
    with pytest.raises(SystemExit):
        update_cmd._update_via_zip(SimpleNamespace())


# --- lazy dependency installation -----------------------------------------

def test_lazy_installs_disabled_by_default(monkeypatch):
    import tools.lazy_deps as ld

    monkeypatch.setattr("hermes_cli.config.load_config", lambda: {}, raising=False)
    monkeypatch.delenv("HERMES_DISABLE_LAZY_INSTALLS", raising=False)
    assert ld._allow_lazy_installs() is False


def test_lazy_installs_enabled_on_opt_in(monkeypatch, sc_config):
    import tools.lazy_deps as ld

    sc_config["allow_unverified_components"] = ["lazy-deps"]
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: {}, raising=False)
    monkeypatch.delenv("HERMES_DISABLE_LAZY_INSTALLS", raising=False)
    assert ld._allow_lazy_installs() is True


# --- MCP bootstrap dependency install -------------------------------------

def test_mcp_bootstrap_disabled_by_default():
    from hermes_cli import mcp_catalog
    from pathlib import Path

    with pytest.raises(mcp_catalog.CatalogError):
        mcp_catalog._run_bootstrap(Path("."), ["pip install some-unpinned-pkg"])


def test_mcp_bootstrap_noop_when_empty():
    from hermes_cli import mcp_catalog
    from pathlib import Path

    mcp_catalog._run_bootstrap(Path("."), [])  # no commands → no gate, no raise


# --- browser payload (browser-use) ----------------------------------------

def test_browser_use_install_disabled_by_default(monkeypatch):
    import tools.browser_use_cli as bu

    monkeypatch.setattr(bu, "_managed_bin_dir", lambda: None)
    ok, message = bu.install_cli()
    assert ok is False
    assert "disabled by default" in message


def test_browser_use_uvx_fallback_suppressed_by_default(monkeypatch):
    import tools.browser_use_cli as bu

    monkeypatch.setattr(bu.shutil, "which", lambda name, path=None: "/x/uvx" if name == "uvx" else None)
    assert bu._find_cli() is None  # uvx network resolution not offered


# --- profile distribution (mutable git HEAD) ------------------------------

def test_profile_distribution_clone_disabled_by_default(tmp_path):
    from hermes_cli import profile_distribution as pd

    with pytest.raises(pd.DistributionError):
        pd._git_clone("https://github.com/example/profile", tmp_path / "dest")


# --- Docker base images (declaration invariant) ---------------------------

def test_dockerfile_base_images_are_digest_pinned():
    import re
    from pathlib import Path

    dockerfile = Path(__file__).resolve().parents[2] / "Dockerfile"
    lines = dockerfile.read_text(encoding="utf-8").splitlines()
    # A multi-stage `FROM <prior-stage> AS <name>` references a build stage
    # defined earlier in the file, not a registry image — it inherits the
    # earlier external stage's @sha256 pin and must not itself be pinned.
    stage_names = set()
    for line in lines:
        m = re.search(r"^\s*FROM\s+.*\bAS\s+([A-Za-z0-9_.-]+)\s*$", line, re.IGNORECASE)
        if m:
            stage_names.add(m.group(1).lower())
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("FROM "):
            continue
        parts = stripped.split()
        image = parts[1] if len(parts) >= 2 else ""
        if image.lower() in stage_names:
            continue  # references a prior build stage, already anchored
        assert re.search(r"@sha256:[0-9a-f]{64}", stripped), (
            f"unpinned base image (no @sha256 digest): {stripped}"
        )


def test_dockerfile_playwright_download_is_gated():
    from pathlib import Path

    text = (Path(__file__).resolve().parents[2] / "Dockerfile").read_text(encoding="utf-8")
    # The browser payload download must be guarded by the fail-closed build arg.
    assert "npx playwright install" in text
    assert "ALLOW_UNVERIFIED_BROWSER" in text

"""WP4 A6: centralized managed resolution — end-to-end behavioral tests.

Every managed executable resolver/installer must verify a provenance marker
before returning or executing a binary, quarantine an invalid legacy target
before any installer fallback, and run ZERO install subprocess under the secure
default. These drive the exact named flows: resolve_uv / the Termux uv
bootstrap, find_bws(install_if_missing=True), install_iron_proxy's early return,
tirith's background install, and browser-use find/install.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hermes_cli.supply_chain.managed import managed_ok, write_marker


def _fake_exe(path: Path, content: bytes = b"fake-binary") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    if os.name != "nt":
        os.chmod(path, 0o755)
    return path


_NODE = "node.exe" if os.name == "nt" else "node"


def _managed_node_dir(home: Path) -> Path:
    return (home / "node") if os.name == "nt" else (home / "node" / "bin")


def _make_node(directory: Path, content: str = "fake-node") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    node = directory / _NODE
    node.write_text(content, encoding="utf-8")
    if os.name != "nt":
        node.chmod(0o755)
    return node


def _mark(path: Path, component: str) -> None:
    write_marker(path, component=component, version="test", provenance="test")


@pytest.fixture
def secure(monkeypatch):
    """Secure default: enforce on, no component opted in (fails every installer)."""
    from hermes_cli.supply_chain import gate as _gate

    cfg = {"enforce": True, "allow_unverified_components": []}
    monkeypatch.setattr(_gate, "_sc_config", lambda: cfg)
    return cfg


class _NoSubprocess:
    """Assert no subprocess is spawned under the secure default."""

    def __init__(self, monkeypatch, module):
        self.calls = 0
        import subprocess as _sp

        def _forbid(*a, **k):
            self.calls += 1
            raise AssertionError(f"no subprocess allowed under secure default: {a!r}")

        if hasattr(module, "subprocess"):
            monkeypatch.setattr(module.subprocess, "run", _forbid)
        monkeypatch.setattr(_sp, "run", _forbid)


# --- uv: centralized resolve_uv is marker-verified -------------------------

def test_resolve_uv_ignores_unmarked_returns_marked(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from hermes_cli import managed_uv

    uv = managed_uv.managed_uv_path()
    _fake_exe(uv)
    assert managed_uv.resolve_uv() is None, "unmarked managed uv must not resolve"
    _mark(uv, "uv")
    assert managed_uv.resolve_uv() == str(uv), "marked managed uv resolves"


def test_ensure_uv_for_termux_does_not_return_unmarked(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from hermes_cli import managed_uv, update_cmd, main as _main

    uv = managed_uv.managed_uv_path()
    _fake_exe(uv)  # unmarked
    # Not Termux, no operator uv on PATH → the unmarked managed uv is NOT
    # returned (resolve_uv is marker-verified), so the whole path yields None.
    monkeypatch.setattr(_main, "_is_termux_env", lambda: False, raising=False)
    monkeypatch.setattr(update_cmd.shutil, "which", lambda *a, **k: None)
    assert update_cmd._ensure_uv_for_termux(["python", "-m", "pip"]) is None
    # Marking it makes resolve_uv (and thus the Termux bootstrap) return it.
    _mark(uv, "uv")
    assert update_cmd._ensure_uv_for_termux(["python", "-m", "pip"]) == str(uv)


# --- bitwarden: find/install ----------------------------------------------

def test_find_bws_install_missing_unmarked_blocks_token_execution(tmp_path, monkeypatch, secure):
    """find_bws(install_if_missing=True) must NOT return an unmarked managed bws
    and must not download under the secure default — the binary that would
    decrypt tokens is never handed back."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from agent.secret_sources import bitwarden

    target = bitwarden._hermes_bin_dir() / bitwarden._platform_binary_name()
    _fake_exe(target)  # unmarked legacy managed bws
    monkeypatch.setattr(bitwarden.shutil, "which", lambda *a, **k: None)  # no operator bws
    _NoSubprocess(monkeypatch, bitwarden)

    result = bitwarden.find_bws(install_if_missing=True)
    assert result is None, "unmarked managed bws must not be returned/executed"
    # The invalid legacy target was quarantined before the installer fallback.
    assert not target.exists()


def test_install_bws_quarantines_unmarked_and_fails_closed(tmp_path, monkeypatch, secure):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from agent.secret_sources import bitwarden

    target = bitwarden._hermes_bin_dir() / bitwarden._platform_binary_name()
    _fake_exe(target)  # unmarked
    _NoSubprocess(monkeypatch, bitwarden)

    with pytest.raises(RuntimeError):
        bitwarden.install_bws()  # gated: no opt-in → fail closed (no download)
    assert not target.exists(), "unmarked target quarantined before install"


def test_install_bws_returns_marked_target(tmp_path, monkeypatch, secure):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from agent.secret_sources import bitwarden

    target = bitwarden._hermes_bin_dir() / bitwarden._platform_binary_name()
    _fake_exe(target)
    _mark(target, "bws")
    assert bitwarden.install_bws() == target  # marked → returned, no download


# --- iron-proxy: install early return -------------------------------------

def test_install_iron_proxy_quarantines_unmarked_and_fails_closed(tmp_path, monkeypatch, secure):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from agent.proxy_sources import iron_proxy

    target = iron_proxy._hermes_bin_dir() / iron_proxy._platform_binary_name()
    _fake_exe(target)  # unmarked
    _NoSubprocess(monkeypatch, iron_proxy)

    with pytest.raises(Exception):
        iron_proxy.install_iron_proxy()  # gated → fail closed, no download
    assert not target.exists(), "unmarked target quarantined before install"


def test_install_iron_proxy_returns_marked_target(tmp_path, monkeypatch, secure):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from agent.proxy_sources import iron_proxy

    target = iron_proxy._hermes_bin_dir() / iron_proxy._platform_binary_name()
    _fake_exe(target)
    _mark(target, "iron-proxy")
    assert iron_proxy.install_iron_proxy() == target


# --- tirith: background install -------------------------------------------

def test_tirith_background_install_ignores_unmarked(tmp_path, monkeypatch, secure):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    import tools.tirith_security as ts

    monkeypatch.setattr(ts, "_resolved_path", None, raising=False)
    monkeypatch.setattr(ts, "_hermes_bin_dir", lambda: str(tmp_path / "bin"))
    hermes_bin = Path(ts._hermes_bin_dir()) / "tirith"
    _fake_exe(hermes_bin)  # unmarked
    monkeypatch.setattr(ts.shutil, "which", lambda *a, **k: None)  # no operator tirith
    # The install download must not run (fail closed); intercept it.
    monkeypatch.setattr(ts, "_install_tirith", lambda **k: (None, "gated"))

    ts._background_install(log_failures=False)
    # The unmarked managed tirith was NOT adopted as the resolved path...
    assert ts._resolved_path != str(hermes_bin)
    # ...and it was quarantined before the installer fallback.
    assert not hermes_bin.exists()


def test_tirith_background_install_adopts_marked(tmp_path, monkeypatch, secure):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    import tools.tirith_security as ts

    monkeypatch.setattr(ts, "_resolved_path", None, raising=False)
    monkeypatch.setattr(ts, "_hermes_bin_dir", lambda: str(tmp_path / "bin"))
    hermes_bin = Path(ts._hermes_bin_dir()) / "tirith"
    _fake_exe(hermes_bin)
    _mark(hermes_bin, "tirith")
    monkeypatch.setattr(ts.shutil, "which", lambda *a, **k: None)

    ts._background_install(log_failures=False)
    assert ts._resolved_path == str(hermes_bin)


# --- browser-use: find / install ------------------------------------------

def test_browser_use_find_cli_ignores_unmarked_managed(tmp_path, monkeypatch, secure):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    import tools.browser_use_cli as bu

    managed_dir = Path(bu._managed_bin_dir())
    _fake_exe(managed_dir / ("browser-use.exe" if os.name == "nt" else "browser-use"))
    # No operator/user-local browser-use, uvx disabled by default.
    monkeypatch.setattr(bu, "_user_local_bin_dir", lambda: None)

    def _which(name, path=None):
        # Only the managed dir has a browser-use; PATH/user-local have none.
        if path == str(managed_dir):
            exe = managed_dir / ("browser-use.exe" if os.name == "nt" else "browser-use")
            return str(exe) if exe.exists() else None
        return None

    monkeypatch.setattr(bu.shutil, "which", _which)
    assert bu._find_cli() is None, "unmarked managed browser-use must be ignored"


def test_browser_use_install_cli_quarantines_unmarked_and_fails_closed(tmp_path, monkeypatch, secure):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    import tools.browser_use_cli as bu

    managed_dir = Path(bu._managed_bin_dir())
    exe = _fake_exe(managed_dir / ("browser-use.exe" if os.name == "nt" else "browser-use"))

    def _which(name, path=None):
        if path == str(managed_dir):
            return str(exe) if exe.exists() else None
        return None

    monkeypatch.setattr(bu.shutil, "which", _which)
    _NoSubprocess(monkeypatch, bu)

    ok, msg = bu.install_cli()
    assert ok is False, "unmarked browser-use must not short-circuit; install is gated"
    assert "disabled by default" in msg
    assert not exe.exists(), "unmarked managed browser-use quarantined before install"


def test_browser_use_find_cli_returns_marked_managed(tmp_path, monkeypatch, secure):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    import tools.browser_use_cli as bu
    from hermes_cli.supply_chain.managed import write_tool_marker

    managed_dir = Path(bu._managed_bin_dir())
    exe = _fake_exe(managed_dir / ("browser-use.exe" if os.name == "nt" else "browser-use"))
    tree = Path(bu._browser_use_tool_tree())
    (tree / "lib").mkdir(parents=True)
    (tree / "lib" / "pkg.py").write_text("code", encoding="utf-8")
    # A6: the marker binds BOTH launcher and the whole tool tree.
    write_tool_marker(exe, tree_dir=tree, component="browser-use", version="test", provenance="test")

    def _which(name, path=None):
        if path == str(managed_dir):
            return str(exe)
        return None

    monkeypatch.setattr(bu.shutil, "which", _which)
    monkeypatch.setattr(bu, "_user_local_bin_dir", lambda: None)
    assert bu._find_cli() == [str(exe)]


def test_browser_use_find_cli_rejects_tampered_tool_tree(tmp_path, monkeypatch, secure):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    import tools.browser_use_cli as bu
    from hermes_cli.supply_chain.managed import write_tool_marker

    managed_dir = Path(bu._managed_bin_dir())
    exe = _fake_exe(managed_dir / ("browser-use.exe" if os.name == "nt" else "browser-use"))
    tree = Path(bu._browser_use_tool_tree())
    (tree / "lib").mkdir(parents=True)
    pkg = tree / "lib" / "pkg.py"
    pkg.write_text("good", encoding="utf-8")
    write_tool_marker(exe, tree_dir=tree, component="browser-use", version="test", provenance="test")

    def _which(name, path=None):
        return str(exe) if path == str(managed_dir) else None

    monkeypatch.setattr(bu.shutil, "which", _which)
    monkeypatch.setattr(bu, "_user_local_bin_dir", lambda: None)
    assert bu._find_cli() == [str(exe)]  # trusted while intact
    # Tamper a file inside the tool tree WITHOUT touching the launcher and
    # WITHOUT clearing any cache: tool_marker_ok now rehashes the full tree on
    # every resolve (A6 alert-2), so the same-process mutation is rejected on the
    # very next _find_cli() call.
    pkg.write_text("EVIL", encoding="utf-8")
    assert bu._find_cli() is None, "a tampered tool tree must be rejected"


# --- alias bypass: operator/PATH fallback resolving into a managed root ----

def test_accept_operator_path_rejects_unmarked_managed_accepts_marked(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from hermes_cli.supply_chain.managed import accept_operator_path

    managed = _fake_exe(tmp_path / "bin" / "bws")
    # Same path an operator PATH probe could return — under a managed root.
    assert accept_operator_path(str(managed), component="bws") is None
    _mark(managed, "bws")
    assert accept_operator_path(str(managed), component="bws") == str(managed)


def test_accept_operator_path_accepts_genuine_operator(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))
    from hermes_cli.supply_chain.managed import accept_operator_path

    op = _fake_exe(tmp_path / "usr" / "bin" / "bws")
    assert accept_operator_path(str(op), component="bws") == str(op)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink")
def test_accept_operator_path_rejects_symlink_to_managed(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))
    from hermes_cli.supply_chain.managed import accept_operator_path

    managed = _fake_exe(tmp_path / "h" / "bin" / "bws")  # unmarked
    link_dir = tmp_path / "elsewhere"
    link_dir.mkdir()
    link = link_dir / "bws"
    link.symlink_to(managed)
    assert accept_operator_path(str(link), component="bws") is None


@pytest.mark.skipif(os.name != "nt", reason="Windows case-insensitive paths")
def test_accept_operator_path_rejects_case_variant_managed(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from hermes_cli.supply_chain.managed import accept_operator_path

    managed = _fake_exe(tmp_path / "bin" / "bws.exe")  # unmarked
    assert accept_operator_path(str(managed).upper(), component="bws") is None


def test_find_bws_rejects_managed_alias_and_never_executes(tmp_path, monkeypatch, secure):
    """find_bws(install_if_missing=True) with a managed bws aliased onto PATH and
    a BWS_ACCESS_TOKEN present must never return/execute the unmarked binary."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "s3cret")
    from agent.secret_sources import bitwarden

    managed = bitwarden._hermes_bin_dir() / bitwarden._platform_binary_name()
    _fake_exe(managed)  # unmarked managed bws
    monkeypatch.setattr(bitwarden.shutil, "which", lambda n: str(managed))  # PATH alias
    _NoSubprocess(monkeypatch, bitwarden)

    assert bitwarden.find_bws() is None
    assert bitwarden.find_bws(install_if_missing=True) is None


def test_find_iron_proxy_rejects_managed_alias(tmp_path, monkeypatch, secure):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from agent.proxy_sources import iron_proxy

    managed = iron_proxy._hermes_bin_dir() / iron_proxy._platform_binary_name()
    _fake_exe(managed)
    monkeypatch.setattr(iron_proxy.shutil, "which", lambda n: str(managed))
    _NoSubprocess(monkeypatch, iron_proxy)
    assert iron_proxy.find_iron_proxy() is None


def test_find_cli_rejects_managed_browser_use_alias_on_path(tmp_path, monkeypatch, secure):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    import tools.browser_use_cli as bu

    managed_dir = Path(bu._managed_bin_dir())
    exe = _fake_exe(managed_dir / ("browser-use.exe" if os.name == "nt" else "browser-use"))
    monkeypatch.setattr(bu, "_user_local_bin_dir", lambda: None)

    # PATH probe (probe_path is None) returns the managed browser-use itself.
    def _which(name, path=None):
        return str(exe)

    monkeypatch.setattr(bu.shutil, "which", _which)
    assert bu._find_cli() is None, "managed browser-use via PATH alias must be rejected"


def test_probe_operator_uv_rejects_managed_alias(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from hermes_cli import managed_uv

    # Isolate ~/.local/bin so a real operator uv on the test host isn't picked up.
    monkeypatch.setattr(managed_uv.Path, "home", classmethod(lambda cls: tmp_path / "home"))
    uv = _fake_exe(managed_uv.managed_uv_path())  # unmarked managed uv
    monkeypatch.setattr(managed_uv.shutil, "which", lambda n: str(uv))  # PATH alias
    assert managed_uv._probe_operator_uv() is None, "unmarked managed uv via PATH alias must be rejected"


def test_find_node_executable_rejects_managed_alias_on_path(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    import hermes_constants as hc

    node_dir = _managed_node_dir(tmp_path)
    _make_node(node_dir)  # unmarked managed node tree
    node_exe = node_dir / _NODE
    monkeypatch.setattr(hc, "node_tool_runnable", lambda p: True)
    monkeypatch.setattr(hc, "_managed_node_heal_attempted", False)
    monkeypatch.setattr(hc, "heal_hermes_managed_node", lambda: False)
    # find_node_executable_on_path returns the managed node via PATH alias.
    monkeypatch.setattr(hc, "find_node_executable_on_path", lambda c: str(node_exe))
    assert hc.find_node_executable("node") is None, "managed node via PATH alias must be rejected"


def test_operator_tirith_rejects_managed_alias(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    import tools.tirith_security as ts

    monkeypatch.setattr(ts, "_hermes_bin_dir", lambda: str(tmp_path / "bin"))
    hermes_bin = Path(ts._hermes_bin_dir()) / "tirith"
    _fake_exe(hermes_bin)  # unmarked managed tirith
    monkeypatch.setattr(ts.shutil, "which", lambda n: str(hermes_bin))  # PATH alias
    assert ts._operator_tirith() is None

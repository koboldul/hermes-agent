"""SEC-AUDIT-002 Alert 2: effective ``auto`` must never trust arbitrary PATH.

These tests drive the REAL server builders (`ServerDef.build_spawn`) and the
centralized strategy-aware resolver, proving that under effective ``auto`` an
attacker-controlled PATH entry is ignored and only a verified managed marker, a
re-approved exact-digest binary, a digest-re-approved config command override,
or a committed locked install can be launched — across every builder family.
Manual mode still honours operator PATH.  No source text is read.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from agent.lsp import install as inst
from agent.lsp import manifest, provenance
from agent.lsp import servers as _servers
from agent.lsp.servers import ServerContext, find_server_for_file


@pytest.fixture(autouse=True)
def _fresh_home(monkeypatch, tmp_path):
    home = tmp_path / "hh"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    inst._install_results.clear()
    inst._install_locks.clear()
    yield home
    inst._install_results.clear()
    inst._install_locks.clear()


def _exe(path: Path, content: str = "#!/bin/sh\necho stub\n") -> str:
    path.write_text(content, encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o755)
    return str(path)


def _ctx(strategy: str, tmp_path: Path, **overrides) -> ServerContext:
    return ServerContext(workspace_root=str(tmp_path), install_strategy=strategy, **overrides)


def _build(server_id_file: str, tmp_path: Path, ctx: ServerContext):
    srv = find_server_for_file(str(tmp_path / server_id_file))
    assert srv is not None, server_id_file
    return srv.build_spawn(str(tmp_path), ctx)


# A minimal fake npm that records nothing but materialises the server bin
# declared in the committed package-lock.json.  Used to create a real managed
# provenance marker without network.
_FAKE_NPM = r"""
import json, os, sys
cwd = os.getcwd()
binroot = os.path.join(cwd, "node_modules", ".bin")
os.makedirs(binroot, exist_ok=True)
with open(os.path.join(cwd, "package-lock.json"), encoding="utf-8") as lf:
    lock = json.load(lf)
for pkg in (lock.get("packages") or {}).values():
    for bname in (pkg.get("bin") or {}):
        p = os.path.join(binroot, bname)
        with open(p, "w", encoding="utf-8") as bf:
            bf.write("#!/bin/sh\necho fake-server\n")
        os.chmod(p, 0o755)
sys.exit(0)
"""


def _fake_npm(tmp_path: Path):
    s = tmp_path / "fake_npm.py"
    s.write_text(_FAKE_NPM, encoding="utf-8")
    return [sys.executable, str(s)]


# ---------------------------------------------------------------------------
# Auto ignores attacker PATH and launches the managed/locked-install path
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "ext,pkg", [(".py", "pyright"), (".go", "gopls")]
)
def test_auto_ignores_attacker_path_and_launches_managed(monkeypatch, tmp_path, ext, pkg):
    attacker = _exe(tmp_path / f"attacker{ext}.bin")
    managed = _exe(tmp_path / "managed-server")
    monkeypatch.setattr(inst, "_path_binary", lambda *names: attacker)
    monkeypatch.setattr(inst, "_install_and_verify", lambda recipe: managed)

    spec = _build(f"proj{ext}", tmp_path, _ctx("auto", tmp_path))
    assert spec is not None
    assert spec.command[0] == managed
    assert spec.command[0] != attacker


def test_auto_launches_valid_marker_without_reinstall(monkeypatch, tmp_path):
    # First: a genuine locked install produces a verified managed marker.
    monkeypatch.setattr(inst, "_npm_argv", lambda: _fake_npm(tmp_path))
    monkeypatch.setattr(inst, "_path_binary", lambda *names: None)
    managed = inst.resolve_binary("pyright", "auto")
    assert managed is not None
    recipe = manifest.get_recipe("pyright")
    assert provenance.verify_managed(recipe) == managed

    # Now an attacker plants a PATH binary; auto must launch the marker, not
    # the attacker, and must NOT reinstall.
    inst._install_results.clear()
    attacker = _exe(tmp_path / "attacker-pyright-langserver")
    monkeypatch.setattr(inst, "_path_binary", lambda *names: attacker)

    def _boom(recipe):
        raise AssertionError("must not reinstall when a valid marker exists")

    monkeypatch.setattr(inst, "_install_and_verify", _boom)
    spec = _build("proj.py", tmp_path, _ctx("auto", tmp_path))
    assert spec is not None
    assert spec.command[0] == managed
    assert spec.command[0] != attacker


def test_auto_rejects_mutated_marker_and_never_uses_path(monkeypatch, tmp_path):
    monkeypatch.setattr(inst, "_npm_argv", lambda: _fake_npm(tmp_path))
    monkeypatch.setattr(inst, "_path_binary", lambda *names: None)
    managed = inst.resolve_binary("pyright", "auto")
    assert managed is not None

    # Tamper the installed binary → marker no longer verifies.
    with open(managed, "a", encoding="utf-8") as fh:
        fh.write("; tampered\n")

    inst._install_results.clear()
    attacker = _exe(tmp_path / "attacker-pyright-langserver")
    sentinel = _exe(tmp_path / "reinstalled-server")
    monkeypatch.setattr(inst, "_path_binary", lambda *names: attacker)
    monkeypatch.setattr(inst, "_install_and_verify", lambda recipe: sentinel)

    spec = _build("proj.py", tmp_path, _ctx("auto", tmp_path))
    # Mutated marker is ignored; auto reinstalls (sentinel), never the attacker.
    assert spec is not None
    assert spec.command[0] == sentinel
    assert spec.command[0] != attacker


def test_auto_locked_install_runs_and_ignores_path(monkeypatch, tmp_path):
    monkeypatch.setattr(inst, "_npm_argv", lambda: _fake_npm(tmp_path))
    attacker = _exe(tmp_path / "attacker-pyright-langserver")
    monkeypatch.setattr(inst, "_path_binary", lambda *names: attacker)

    resolved = inst.resolve_binary("pyright", "auto")
    assert resolved is not None
    assert resolved != attacker
    marker = provenance.read_marker("pyright")
    assert marker is not None and marker["source"] == "managed"
    assert provenance.verify_managed(manifest.get_recipe("pyright")) == resolved


# ---------------------------------------------------------------------------
# Manual mode honours operator PATH
# ---------------------------------------------------------------------------
def test_manual_uses_operator_path(monkeypatch, tmp_path):
    attacker = _exe(tmp_path / "operator-pyright")
    monkeypatch.setattr(inst, "_path_binary", lambda *names: attacker)
    spec = _build("proj.py", tmp_path, _ctx("manual", tmp_path))
    assert spec is not None
    assert spec.command[0] == attacker


# ---------------------------------------------------------------------------
# Explicit config command override: digest-reapproval required in auto
# ---------------------------------------------------------------------------
def test_config_command_override_requires_digest_reapproval_in_auto(monkeypatch, tmp_path):
    override = _exe(tmp_path / "operator-pyright.cmd")
    # No arbitrary PATH — isolate the override decision.
    monkeypatch.setattr(inst, "_path_binary", lambda *names: None)
    ov = {"pyright": [override]}

    # auto, not re-approved → refused.
    spec = _build("proj.py", tmp_path, _ctx("auto", tmp_path, binary_overrides=ov))
    assert spec is None

    # manual → operator owns it, honoured directly.
    spec = _build("proj.py", tmp_path, _ctx("manual", tmp_path, binary_overrides=ov))
    assert spec is not None and spec.command[0] == os.path.abspath(override)

    # Re-approve the exact path → auto honours it.
    provenance.record_reapproval("pyright", override)
    spec = _build("proj.py", tmp_path, _ctx("auto", tmp_path, binary_overrides=ov))
    assert spec is not None and spec.command[0] == os.path.abspath(override)

    # Mutate the approved binary → digest mismatch → refused again in auto.
    with open(override, "a", encoding="utf-8") as fh:
        fh.write("tampered\n")
    spec = _build("proj.py", tmp_path, _ctx("auto", tmp_path, binary_overrides=ov))
    assert spec is None


# ---------------------------------------------------------------------------
# Explicit operator re-approval of a PATH binary (no config command)
# ---------------------------------------------------------------------------
def test_reapproved_path_binary_launches_in_auto(monkeypatch, tmp_path):
    operator_bin = _exe(tmp_path / "operator-gopls")
    monkeypatch.setattr(inst, "_path_binary", lambda *names: operator_bin)
    monkeypatch.setattr(
        inst, "_install_and_verify",
        lambda recipe: (_ for _ in ()).throw(AssertionError("should not install")),
    )
    provenance.record_reapproval("gopls", operator_bin)

    spec = _build("proj.go", tmp_path, _ctx("auto", tmp_path))
    assert spec is not None
    assert os.path.abspath(spec.command[0]) == os.path.abspath(operator_bin)


# ---------------------------------------------------------------------------
# Every builder family funnels through the resolver
# ---------------------------------------------------------------------------
# (ext, whether the family is auto-installable via a locked recipe)
_FAMILY_FILES = [
    "proj.py",     # pyright        — npm, auto-installable
    "proj.go",     # gopls          — go, auto-installable
    "proj.ts",     # tsls           — npm, non-locked
    "proj.sh",     # bash-ls        — npm, non-locked
    "proj.vue",    # vue            — npm, non-locked, pkg != server_id
    "proj.rs",     # rust-analyzer  — manual ecosystem
    "proj.c",      # clangd         — manual ecosystem
    "proj.tf",     # terraform-ls   — no manifest recipe, plain PATH
    "proj.dart",   # dart           — no manifest recipe, plain PATH
    "proj.hs",     # haskell-ls     — no manifest recipe, multi-name probe
    "proj.jl",     # julia          — no manifest recipe
    "proj.zig",    # zls            — no manifest recipe
]


def _make_pses_bundle(home: Path, host_content: str = "host-v1", script_content: str = "script-v1"):
    """Create a fake pwsh host + PSES bundle under the HERMES_HOME staging dir.

    Returns ``(host_path, script_path)``.
    """
    host = home / "pwsh.exe"
    _exe(host, host_content)
    bdir = home / "lsp" / "PowerShellEditorServices" / "PowerShellEditorServices"
    bdir.mkdir(parents=True, exist_ok=True)
    script = bdir / "Start-EditorServices.ps1"
    script.write_text(script_content, encoding="utf-8")
    return str(host), str(script)


def _build_powershell(tmp_path: Path, strategy: str, host: str, ctx_kwargs=None):
    srv = find_server_for_file(str(tmp_path / "proj.ps1"))
    assert srv is not None and srv.server_id == "powershell"
    ctx = ServerContext(workspace_root=str(tmp_path), install_strategy=strategy, **(ctx_kwargs or {}))
    # The host is resolved via servers._which; the bundle via _find_pses_bundle.
    with patch.object(_servers, "_which", lambda *names: host):
        return srv.build_spawn(str(tmp_path), ctx)


@pytest.mark.parametrize("fname", _FAMILY_FILES + ["proj.ps1"])
def test_every_builder_family_auto_ignores_path_manual_allows_it(monkeypatch, tmp_path, fname, _fresh_home):
    # PowerShell is a COMPOUND builder (host + PSES script) — its host is not
    # exempt; auto must refuse an attacker host + unmarked bundle, manual works.
    if fname == "proj.ps1":
        home = _fresh_home
        host, _script = _make_pses_bundle(home)  # attacker host on PATH + bundle
        assert _build_powershell(tmp_path, "auto", host) is None
        spec_manual = _build_powershell(tmp_path, "manual", host)
        assert spec_manual is not None and spec_manual.command[0] == host
        return

    attacker = _exe(tmp_path / f"attacker-{fname}.bin")
    monkeypatch.setattr(inst, "_path_binary", lambda *names: attacker)
    # Disable installs so an auto-installable family also proves the PATH
    # entry is never the fallback.
    monkeypatch.setattr(inst, "_install_and_verify", lambda recipe: None)

    # Effective auto: the attacker PATH binary is never launched.  With no
    # marker, no override, and installs disabled, resolution yields nothing.
    spec_auto = _build(fname, tmp_path, _ctx("auto", tmp_path))
    assert spec_auto is None

    # Manual: the operator PATH binary IS launched (operator owns PATH).
    spec_manual = _build(fname, tmp_path, _ctx("manual", tmp_path))
    assert spec_manual is not None
    assert spec_manual.command[0] == attacker


# ---------------------------------------------------------------------------
# PowerShell (compound: host interpreter + PSES bootstrap script)
# SEC-AUDIT-002 Alert 1 — neither component is exempt from the auto gate.
# ---------------------------------------------------------------------------
def test_powershell_auto_refuses_attacker_host_and_unmarked_bundle(tmp_path, _fresh_home):
    host, _script = _make_pses_bundle(_fresh_home)  # attacker pwsh on PATH
    assert _build_powershell(tmp_path, "auto", host) is None


def test_powershell_auto_refuses_unmarked_legacy_bundle(tmp_path, _fresh_home):
    # An unmarked HERMES_HOME/lsp/PowerShellEditorServices bundle is manual-only.
    host, _script = _make_pses_bundle(_fresh_home)
    assert _build_powershell(tmp_path, "auto", host) is None
    # ... but manual resolves it.
    assert _build_powershell(tmp_path, "manual", host) is not None


def test_powershell_manual_success(tmp_path, _fresh_home):
    host, _script = _make_pses_bundle(_fresh_home)
    spec = _build_powershell(tmp_path, "manual", host)
    assert spec is not None
    assert spec.command[0] == host
    assert "Start-EditorServices.ps1" in spec.command[-1]


def test_powershell_auto_success_when_both_components_approved(tmp_path, _fresh_home):
    host, script = _make_pses_bundle(_fresh_home)
    provenance.record_compound_reapproval("powershell", {"host": host, "script": script})
    spec = _build_powershell(tmp_path, "auto", host)
    assert spec is not None
    assert spec.command[0] == host
    assert script in spec.command[-1]
    assert provenance.integrity_state_for("powershell") == "reapproved"


def test_powershell_auto_rejects_host_mutation(tmp_path, _fresh_home):
    host, script = _make_pses_bundle(_fresh_home)
    provenance.record_compound_reapproval("powershell", {"host": host, "script": script})
    assert _build_powershell(tmp_path, "auto", host) is not None
    # Mutate the host executable → whole compound approval is revoked.
    Path(host).write_text("host-TAMPERED", encoding="utf-8")
    assert _build_powershell(tmp_path, "auto", host) is None
    assert provenance.integrity_state_for("powershell") == "mutated"


def test_powershell_auto_rejects_script_mutation(tmp_path, _fresh_home):
    host, script = _make_pses_bundle(_fresh_home)
    provenance.record_compound_reapproval("powershell", {"host": host, "script": script})
    assert _build_powershell(tmp_path, "auto", host) is not None
    # Mutate the PSES bootstrap script → whole compound approval is revoked.
    Path(script).write_text("script-TAMPERED", encoding="utf-8")
    assert _build_powershell(tmp_path, "auto", host) is None
    assert provenance.integrity_state_for("powershell") == "mutated"


def test_powershell_auto_ignores_config_command_and_env_bundle(monkeypatch, tmp_path, _fresh_home):
    # A config command bundle path AND PSES_BUNDLE_PATH are operator inputs that
    # auto must NOT trust without compound digest re-approval.
    home = _fresh_home
    host, script = _make_pses_bundle(home)
    other_bundle = tmp_path / "evil-bundle"
    (other_bundle / "PowerShellEditorServices").mkdir(parents=True)
    (other_bundle / "PowerShellEditorServices" / "Start-EditorServices.ps1").write_text("x", encoding="utf-8")
    monkeypatch.setenv("PSES_BUNDLE_PATH", str(other_bundle))
    ctx_kwargs = {"binary_overrides": {"powershell": [str(other_bundle)]}}

    # auto: refused despite config command + env bundle present.
    srv = find_server_for_file(str(tmp_path / "proj.ps1"))
    ctx_auto = ServerContext(workspace_root=str(tmp_path), install_strategy="auto", **ctx_kwargs)
    with patch.object(_servers, "_which", lambda *names: host):
        assert srv.build_spawn(str(tmp_path), ctx_auto) is None

    # manual: the config/env bundle IS honoured (operator owns it).
    ctx_manual = ServerContext(workspace_root=str(tmp_path), install_strategy="manual", **ctx_kwargs)
    with patch.object(_servers, "_which", lambda *names: host):
        spec = srv.build_spawn(str(tmp_path), ctx_manual)
    assert spec is not None
    assert spec.command[0] == host


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])

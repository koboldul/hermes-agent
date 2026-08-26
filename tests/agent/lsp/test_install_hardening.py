"""Behavior tests for SEC-AUDIT-002 LSP install/process hardening.

These exercise real functions and subprocess boundaries — a fake ``npm``/``go``
executable records the environment it received, the mock LSP server dumps its
environment, and the immutable-install / provenance / consent machinery is
driven end to end.  No test reads Hermes source text or regexes installer
commands.
"""
from __future__ import annotations

import errno
import json
import os
import sys
import threading
from pathlib import Path

import pytest

from agent.lsp import consent, manifest, provenance
from agent.lsp import install as inst
from agent.lsp.manifest import ManifestError
from agent.lsp.restricted_env import (
    _CERT_VARS,
    _HOME_HINT_VARS,
    _LOCALE_VARS,
    _TEMP_VARS,
    _WINDOWS_LAUNCH_VARS,
    LSPEnvPolicy,
    build_lsp_process_env,
)

CANARIES = {
    "OPENAI_API_KEY": "sk-canary-openai",
    "ANTHROPIC_API_KEY": "sk-canary-anthropic",
    "GH_TOKEN": "ghp_canary",
    "GITHUB_TOKEN": "ghp_canary2",
    "TELEGRAM_BOT_TOKEN": "tg-canary",
    "HERMES_DASHBOARD_SESSION_TOKEN": "dash-canary",
    "GATEWAY_RELAY_SECRET": "relay-canary",
    "GATEWAY_RELAY_ID": "relay-id",
    "AWS_ACCESS_KEY_ID": "AKIACANARY",
    "AWS_SECRET_ACCESS_KEY": "aws-secret-canary",
    "AWS_SESSION_TOKEN": "aws-session-canary",
    "MODAL_TOKEN_SECRET": "modal-canary",
    "DAYTONA_API_KEY": "daytona-canary",
    "CI_JOB_TOKEN": "ci-canary",
    "DATABASE_PASSWORD": "db-canary",
    "NPM_TOKEN": "npm-canary",
    "SSH_AUTH_SOCK": "/tmp/agent.sock",
    "GPG_AGENT_INFO": "/tmp/gpg.sock",
    "HTTP_PROXY": "http://user:pass@proxy.internal:8080",
    "AUXILIARY_VISION_API_KEY": "aux-canary",
    "MY_CUSTOM_SECRET": "custom-canary",
}

# Ambient package-manager config that must never influence the install.
AMBIENT_MANAGER_CONFIG = {
    "NPM_CONFIG_REGISTRY": "http://evil.example/registry",
    "NPM_CONFIG_IGNORE_SCRIPTS": "false",
    "NODE_OPTIONS": "--require /tmp/evil.js",
    "GOFLAGS": "-mod=mod",
    "GOPROXY": "http://evil.example/goproxy",
    "GONOSUMCHECK": "1",
    "PIP_INDEX_URL": "http://evil.example/pip",
}


@pytest.fixture(autouse=True)
def _fresh_lsp_home(monkeypatch, tmp_path):
    home = tmp_path / "hh"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    inst._install_results.clear()
    inst._install_locks.clear()
    yield home
    inst._install_results.clear()
    inst._install_locks.clear()


def _seed_canaries(monkeypatch):
    for k, v in {**CANARIES, **AMBIENT_MANAGER_CONFIG}.items():
        monkeypatch.setenv(k, v)


# ---------------------------------------------------------------------------
# fake toolchain executables (real subprocess boundary)
# ---------------------------------------------------------------------------
_FAKE_NPM = r'''
import json, os, sys, stat
cwd = os.getcwd()
with open(os.path.join(cwd, "__npm_env.json"), "w", encoding="utf-8") as f:
    json.dump(dict(os.environ), f)
with open(os.path.join(cwd, "__npm_argv.json"), "w", encoding="utf-8") as f:
    json.dump(sys.argv, f)
if FAIL:
    sys.stderr.write("fake npm forced failure\n")
    sys.exit(1)
binroot = os.path.join(cwd, "node_modules", ".bin")
os.makedirs(binroot, exist_ok=True)
try:
    with open(os.path.join(cwd, "package-lock.json"), encoding="utf-8") as lf:
        lock = json.load(lf)
    for pkg in (lock.get("packages") or {}).values():
        for bname in (pkg.get("bin") or {}):
            p = os.path.join(binroot, bname)
            with open(p, "w", encoding="utf-8") as bf:
                bf.write("#!/bin/sh\necho fake-server\n")
            os.chmod(p, 0o755)
except Exception as e:  # pragma: no cover
    sys.stderr.write("lock parse err: %s\n" % e)
    sys.exit(2)
sys.exit(0)
'''

_FAKE_GO = r'''
import json, os, sys
cwd = os.getcwd()
with open(os.path.join(cwd, "__go_env.json"), "w", encoding="utf-8") as f:
    json.dump(dict(os.environ), f)
with open(os.path.join(cwd, "__go_argv.json"), "w", encoding="utf-8") as f:
    json.dump(sys.argv, f)
if FAIL:
    sys.stderr.write("fake go forced failure\n")
    sys.exit(1)
gobin = os.environ.get("GOBIN")
if gobin:
    os.makedirs(gobin, exist_ok=True)
    name = "gopls.exe" if os.name == "nt" else "gopls"
    p = os.path.join(gobin, name)
    with open(p, "w", encoding="utf-8") as bf:
        bf.write("fake-gopls\n")
    if os.name != "nt":
        os.chmod(p, 0o755)
sys.exit(0)
'''


def _make_fake(tmp_path: Path, name: str, body: str, fail: bool = False) -> list:
    script = tmp_path / name
    script.write_text(f"FAIL = {bool(fail)}\n" + body, encoding="utf-8")
    return [sys.executable, str(script)]


def _install_npm_env_dump(home: Path) -> dict:
    p = home / "lsp" / "servers" / "pyright" / "__npm_env.json"
    return json.loads(p.read_text(encoding="utf-8"))


def _install_npm_argv(home: Path) -> list:
    p = home / "lsp" / "servers" / "pyright" / "__npm_argv.json"
    return json.loads(p.read_text(encoding="utf-8"))


def _install_go_dump(home: Path, which: str) -> object:
    p = home / "lsp" / "go-build" / "gopls" / f"__go_{which}.json"
    return json.loads(p.read_text(encoding="utf-8"))


# ===========================================================================
# 1. Exact environment allowlist for the installer subprocess
# ===========================================================================
def test_npm_installer_env_equals_declared_allowlist(monkeypatch, tmp_path, _fresh_lsp_home):
    home = _fresh_lsp_home
    _seed_canaries(monkeypatch)
    monkeypatch.setattr(inst, "_npm_argv", lambda: _make_fake(tmp_path, "fake_npm.py", _FAKE_NPM))

    resolved = inst.resolve_binary("pyright", "auto")
    assert resolved is not None

    env = _install_npm_env_dump(home)

    # No canary or ambient manager-config value survives, regardless of name.
    for name in {**CANARIES, **AMBIENT_MANAGER_CONFIG}:
        if name in inst._npm_env_policy().additions:
            continue  # our own hermetic override, checked below
        assert name not in env or env[name] != {**CANARIES, **AMBIENT_MANAGER_CONFIG}[name], name

    for canary in CANARIES:
        assert canary not in env, f"leaked credential {canary}"

    # The complete key set is within the declared allowlist.
    allowed = set()
    allowed.add("PATH")
    allowed.update(_WINDOWS_LAUNCH_VARS)
    allowed.update(_LOCALE_VARS)
    allowed.update(_TEMP_VARS)
    allowed.update(_CERT_VARS)
    allowed.update(_HOME_HINT_VARS)
    allowed.update({"HERMES_HOME", "HOME", "HERMES_REAL_HOME"})
    allowed.update(inst._npm_env_policy().additions.keys())
    unexpected = set(env) - allowed
    assert not unexpected, f"env keys outside the declared allowlist: {unexpected}"

    # Hermetic npm config is present with our values (not the ambient evil ones).
    assert env["NPM_CONFIG_REGISTRY"] == "https://registry.npmjs.org/"
    assert env["NPM_CONFIG_IGNORE_SCRIPTS"] == "true"
    # Distinct, empty, Hermes-owned user/global npmrc files neutralise ambient
    # npmrc without npm's double-load error.
    assert env["NPM_CONFIG_USERCONFIG"] != env["NPM_CONFIG_GLOBALCONFIG"]
    assert str(home) in env["NPM_CONFIG_USERCONFIG"]
    assert str(home) in env["NPM_CONFIG_GLOBALCONFIG"]
    assert env["HERMES_HOME"] == str(home)

    # The install command uses `npm ci --ignore-scripts`, never `npm install`.
    argv = _install_npm_argv(home)
    assert "ci" in argv
    assert "--ignore-scripts" in argv
    assert "install" not in argv


def test_recipe_declared_var_survives_but_ordinary_passthrough_absent(monkeypatch):
    monkeypatch.setenv("MY_TOOLCHAIN_HINT", "present")
    monkeypatch.setenv("SOME_TERMINAL_PASSTHROUGH", "should-not-appear")
    policy = LSPEnvPolicy(copy_ambient=("MY_TOOLCHAIN_HINT",))
    env = build_lsp_process_env(policy)
    assert env.get("MY_TOOLCHAIN_HINT") == "present"
    assert "SOME_TERMINAL_PASSTHROUGH" not in env


def test_installer_override_cannot_readd_internal_secret():
    policy = LSPEnvPolicy(additions={"OPENAI_API_KEY": "x", "GH_TOKEN": "y", "SAFE": "ok"})
    env = build_lsp_process_env(policy)
    assert "OPENAI_API_KEY" not in env
    assert "GH_TOKEN" not in env
    assert env.get("SAFE") == "ok"


# ===========================================================================
# 2. Consent + migration
# ===========================================================================
def test_default_config_is_effective_manual():
    from hermes_cli.config_defaults import DEFAULT_CONFIG

    lsp = DEFAULT_CONFIG["lsp"]
    assert lsp["install_strategy"] == "manual"
    assert lsp["auto_install_consent_version"] is None
    assert consent.effective_install_strategy(lsp) == "manual"


def test_effective_strategy_requires_matching_consent():
    assert consent.effective_install_strategy({"install_strategy": "auto"}) == "manual"
    assert (
        consent.effective_install_strategy(
            {"install_strategy": "auto", "auto_install_consent_version": 0}
        )
        == "manual"
    )
    assert (
        consent.effective_install_strategy(
            {
                "install_strategy": "auto",
                "auto_install_consent_version": consent.CONSENT_POLICY_VERSION,
            }
        )
        == "auto"
    )
    # off / unknown collapse to manual
    assert consent.effective_install_strategy({"install_strategy": "off"}) == "manual"


def test_migration_downgrades_unconsented_auto(monkeypatch, _fresh_lsp_home):
    import yaml
    from hermes_cli import config as cfg
    from hermes_cli.config_migrations import _migrate_to_39

    home = _fresh_lsp_home
    (home / "config.yaml").write_text(
        yaml.safe_dump({"_config_version": 38, "lsp": {"install_strategy": "auto"}}),
        encoding="utf-8",
    )
    results = {"config_added": [], "warnings": [], "env_added": []}
    _migrate_to_39(results, quiet=True)

    raw = cfg.read_raw_config()
    lsp = raw.get("lsp") or {}
    assert consent.effective_install_strategy(lsp) == "manual"
    assert str(lsp.get("install_strategy", "manual")).lower() != "auto"
    assert lsp.get(consent.CONSENT_KEY) is None
    assert any("manual" in w for w in results["warnings"])


def test_migration_preserves_consented_auto(monkeypatch, _fresh_lsp_home):
    import yaml
    from hermes_cli import config as cfg
    from hermes_cli.config_migrations import _migrate_to_39

    home = _fresh_lsp_home
    (home / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "_config_version": 38,
                "lsp": {
                    "install_strategy": "auto",
                    "auto_install_consent_version": consent.CONSENT_POLICY_VERSION,
                },
            }
        ),
        encoding="utf-8",
    )
    results = {"config_added": [], "warnings": [], "env_added": []}
    _migrate_to_39(results, quiet=True)

    raw = cfg.read_raw_config()
    lsp = raw.get("lsp") or {}
    assert consent.effective_install_strategy(lsp) == "auto"


def test_record_and_revoke_consent_roundtrip(monkeypatch, _fresh_lsp_home):
    from hermes_cli import config as cfg

    consent.record_consent()
    lsp = (cfg.read_raw_config() or {}).get("lsp") or {}
    assert consent.effective_install_strategy(lsp) == "auto"

    consent.revoke_consent()
    lsp = (cfg.read_raw_config() or {}).get("lsp") or {}
    assert consent.effective_install_strategy(lsp) == "manual"
    assert lsp.get(consent.CONSENT_KEY) is None


# ===========================================================================
# 3. Manual mode performs no network / package-manager call
# ===========================================================================
def test_manual_mode_never_invokes_package_manager(monkeypatch):
    def _boom():
        raise AssertionError("package manager must not be resolved in manual mode")

    monkeypatch.setattr(inst, "_npm_argv", _boom)
    monkeypatch.setattr(inst, "_go_argv", _boom)
    # No operator PATH binary for pyright in the scrubbed test environment.
    monkeypatch.setattr(inst, "_path_binary", lambda *names: None)

    assert inst.resolve_binary("pyright", "manual") is None
    assert inst.try_install("gopls", "manual") is None


# ===========================================================================
# 4. Immutable install + provenance
# ===========================================================================
def test_pyright_offline_fixture_installs_and_marks(monkeypatch, tmp_path, _fresh_lsp_home):
    monkeypatch.setattr(inst, "_npm_argv", lambda: _make_fake(tmp_path, "fake_npm.py", _FAKE_NPM))
    monkeypatch.setattr(inst, "_path_binary", lambda *names: None)

    resolved = inst.resolve_binary("pyright", "auto")
    assert resolved is not None
    assert os.path.exists(resolved)

    recipe = manifest.get_recipe("pyright")
    marker = provenance.read_marker("pyright")
    assert marker is not None
    assert marker["source"] == "managed"
    assert marker["version"] == recipe.version
    assert marker["manifest_identity"] == manifest.manifest_identity(recipe)
    assert provenance.verify_managed(recipe) == marker["bin_path"]
    assert provenance.integrity_state(recipe) == "verified"


def test_failed_install_leaves_no_verified_binary(monkeypatch, tmp_path, _fresh_lsp_home):
    monkeypatch.setattr(
        inst, "_npm_argv", lambda: _make_fake(tmp_path, "fake_npm_fail.py", _FAKE_NPM, fail=True)
    )
    monkeypatch.setattr(inst, "_path_binary", lambda *names: None)

    assert inst.resolve_binary("pyright", "auto") is None
    assert provenance.read_marker("pyright") is None
    assert provenance.verify_managed(manifest.get_recipe("pyright")) is None
    # No stray verified server tree.
    assert inst.detect_status("pyright") in {"missing", "unverified"}


def test_concurrent_first_use_installs_once(monkeypatch, tmp_path, _fresh_lsp_home):
    counter = tmp_path / "invocations"
    counter.write_text("", encoding="utf-8")
    body = _FAKE_NPM.replace(
        'cwd = os.getcwd()\n',
        'cwd = os.getcwd()\n'
        f'open(r"{counter.as_posix()}", "a").write("x")\n'
        'import time as _t; _t.sleep(0.3)\n',
        1,
    )
    monkeypatch.setattr(inst, "_npm_argv", lambda: _make_fake(tmp_path, "fake_npm_c.py", body))
    monkeypatch.setattr(inst, "_path_binary", lambda *names: None)

    results = []

    def worker():
        results.append(inst.resolve_binary("pyright", "auto"))

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(r is not None for r in results)
    assert len(counter.read_text()) == 1  # exactly one installer invocation


def _run_concurrent_first_use(tmp_path: Path, monkeypatch, threads: int = 6) -> None:
    counter = tmp_path / "invocations"
    counter.write_text("", encoding="utf-8")
    # Fast fake npm (no artificial sleep): maximises the chance the publish
    # rename fires while the just-created files are still being scanned — the
    # exact WinError 5 window this test guards.
    body = _FAKE_NPM.replace(
        'cwd = os.getcwd()\n',
        'cwd = os.getcwd()\n' f'open(r"{counter.as_posix()}", "a").write("x")\n',
        1,
    )
    monkeypatch.setattr(inst, "_npm_argv", lambda: _make_fake(tmp_path, "fake_npm_s.py", body))
    monkeypatch.setattr(inst, "_path_binary", lambda *names: None)

    results: list = []
    lock = threading.Lock()

    def worker():
        r = inst.resolve_binary("pyright", "auto")
        with lock:
            results.append(r)

    ts = [threading.Thread(target=worker) for _ in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    # Exactly one install; every caller received the SAME verified path.
    assert len(counter.read_text()) == 1, f"installed {len(counter.read_text())} times"
    assert all(r is not None for r in results), results
    assert len(set(results)) == 1, results
    recipe = manifest.get_recipe("pyright")
    assert provenance.verify_managed(recipe) == results[0]


@pytest.mark.parametrize("iteration", range(20))
def test_concurrent_first_use_installs_once_stress(monkeypatch, tmp_path, _fresh_lsp_home, iteration):
    """Repeat the same-process concurrent first use to smoke out the transient
    Windows publish-rename flake (WinError 5) and prove one-install/one-path."""
    _run_concurrent_first_use(tmp_path, monkeypatch)


def test_os_replace_retry_recovers_from_transient_access_denied(monkeypatch, tmp_path):
    """Deterministic proof: a transient access-denied on the publish rename is
    retried (not surfaced), independent of antivirus timing."""
    src = tmp_path / "src"
    src.write_text("x", encoding="utf-8")
    dst = tmp_path / "dst"
    real = os.replace
    calls = {"n": 0}

    def flaky(s, d, *a, **k):
        calls["n"] += 1
        if calls["n"] < 3:
            raise PermissionError(13, "Access is denied")  # EACCES / WinError 5 class
        return real(s, d)

    monkeypatch.setattr(inst.os, "replace", flaky)
    inst._os_replace_retry(str(src), str(dst), attempts=10, base_delay=0.001)
    assert calls["n"] == 3
    assert dst.exists()


def test_os_replace_retry_reraises_non_transient_error(monkeypatch, tmp_path):
    """A genuine (non-sharing) error is never retried away — it propagates."""
    def boom(s, d, *a, **k):
        raise OSError(errno.ENOENT, "No such file")

    monkeypatch.setattr(inst.os, "replace", boom)
    with pytest.raises(OSError):
        inst._os_replace_retry("x", "y", attempts=5, base_delay=0.001)


def test_auto_refuses_non_locked_recipe(monkeypatch):
    # bash-language-server has no committed lock graph → not auto-installable.
    def _boom():
        raise AssertionError("must not attempt install for a non-locked recipe")

    monkeypatch.setattr(inst, "_npm_argv", _boom)
    monkeypatch.setattr(inst, "_path_binary", lambda *names: None)
    assert inst.resolve_binary("bash-language-server", "auto") is None


def test_auto_refuses_unknown_package(monkeypatch):
    monkeypatch.setattr(inst, "_path_binary", lambda *names: None)
    assert inst.resolve_binary("no-such-language-server", "auto") is None


def test_npm_lock_integrity_mismatch_is_rejected():
    recipe = manifest.get_recipe("pyright")
    files = manifest.read_lock_files(recipe)
    tampered = dict(files)
    tampered["package-lock.json"] = files["package-lock.json"].replace(
        recipe.top_level_integrity.encode(), b"sha512-TAMPERED"
    )
    with pytest.raises(ManifestError):
        manifest.verify_npm_lock(recipe, tampered)


def test_npm_lock_version_drift_is_rejected():
    recipe = manifest.get_recipe("pyright")
    files = manifest.read_lock_files(recipe)
    tampered = dict(files)
    tampered["package.json"] = files["package.json"].replace(
        recipe.version.encode(), b"9.9.9"
    )
    with pytest.raises(ManifestError):
        manifest.verify_npm_lock(recipe, tampered)


def test_npm_unexpected_lifecycle_script_is_rejected():
    import copy as _copy

    recipe = manifest.get_recipe("pyright")
    files = manifest.read_lock_files(recipe)
    lock = json.loads(files["package-lock.json"])
    lock["packages"][f"node_modules/{recipe.server_id}"]["hasInstallScript"] = True
    tampered = dict(files)
    tampered["package-lock.json"] = json.dumps(lock).encode()
    with pytest.raises(ManifestError):
        manifest.verify_npm_lock(recipe, tampered)


# ===========================================================================
# 5. Managed-binary resolution: unmarked legacy + re-approval + mutation
# ===========================================================================
def test_manual_default_does_not_execute_unmarked_legacy_binary(monkeypatch, _fresh_lsp_home):
    home = _fresh_lsp_home
    bindir = home / "lsp" / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    legacy = bindir / ("pyright-langserver.cmd" if os.name == "nt" else "pyright-langserver")
    legacy.write_text("legacy\n", encoding="utf-8")
    if os.name != "nt":
        legacy.chmod(0o755)
    monkeypatch.setattr(inst, "_path_binary", lambda *names: None)

    # Manual mode does not return the unmarked legacy binary either.
    assert inst.resolve_binary("pyright", "manual") is None
    # Status flags it as unverified rather than installed.
    assert inst.detect_status("pyright") == "unverified"


def test_reapproved_binary_bound_to_digest_and_rejected_after_mutation(tmp_path):
    binfile = tmp_path / "operator-gopls"
    binfile.write_text("v1\n", encoding="utf-8")
    binfile.chmod(0o755)

    provenance.record_reapproval("gopls", str(binfile))
    assert provenance.verify_reapproved("gopls") == str(binfile.resolve()) or \
        provenance.verify_reapproved("gopls") == os.path.abspath(str(binfile))
    assert provenance.integrity_state(manifest.get_recipe("gopls")) == "reapproved"

    # Mutate the binary → digest changes → rejected.
    binfile.write_text("v2-tampered\n", encoding="utf-8")
    assert provenance.verify_reapproved("gopls") is None
    assert provenance.integrity_state(manifest.get_recipe("gopls")) == "mutated"


def test_managed_marker_rejected_after_binary_mutation(monkeypatch, tmp_path, _fresh_lsp_home):
    monkeypatch.setattr(inst, "_npm_argv", lambda: _make_fake(tmp_path, "fake_npm.py", _FAKE_NPM))
    monkeypatch.setattr(inst, "_path_binary", lambda *names: None)

    resolved = inst.resolve_binary("pyright", "auto")
    assert resolved is not None
    recipe = manifest.get_recipe("pyright")
    assert provenance.verify_managed(recipe) is not None

    # Tamper the installed executable → verification fails.
    with open(resolved, "a", encoding="utf-8") as fh:
        fh.write("; tampered\n")
    assert provenance.verify_managed(recipe) is None
    assert provenance.integrity_state(recipe) == "mutated"


# ===========================================================================
# 6. Go specifics: flags/env + committed-graph drift
# ===========================================================================
def test_gopls_install_uses_readonly_gowork_off_and_scrubbed_env(
    monkeypatch, tmp_path, _fresh_lsp_home
):
    home = _fresh_lsp_home
    _seed_canaries(monkeypatch)
    monkeypatch.setattr(inst, "_go_argv", lambda: _make_fake(tmp_path, "fake_go.py", _FAKE_GO))
    monkeypatch.setattr(inst, "_path_binary", lambda *names: None)

    resolved = inst.resolve_binary("gopls", "auto")
    assert resolved is not None

    argv = _install_go_dump(home, "argv")
    assert "install" in argv
    assert "-mod=readonly" in argv
    assert "golang.org/x/tools/gopls" in argv
    assert not any("@" in a for a in argv), "no @version suffix may bypass the graph"

    env = _install_go_dump(home, "env")
    assert env["GOWORK"] == "off"
    assert env["GOFLAGS"] == "-mod=readonly"
    assert env["GOTOOLCHAIN"] == "local"
    for canary in CANARIES:
        assert canary not in env
    # Ambient go config does not leak through.
    assert env["GOPROXY"] != "http://evil.example/goproxy"


def test_gopls_go_sum_drift_is_rejected():
    recipe = manifest.get_recipe("gopls")
    files = manifest.read_lock_files(recipe)
    tampered = dict(files)
    tampered["go.sum"] = files["go.sum"].replace(
        recipe.top_level_integrity.encode(), b"h1:TAMPEREDsum="
    )
    with pytest.raises(ManifestError):
        manifest.verify_go_lock(recipe, tampered)


def test_gopls_go_mod_version_drift_is_rejected():
    recipe = manifest.get_recipe("gopls")
    files = manifest.read_lock_files(recipe)
    tampered = dict(files)
    tampered["go.mod"] = files["go.mod"].replace(recipe.version.encode(), b"v9.9.9")
    with pytest.raises(ManifestError):
        manifest.verify_go_lock(recipe, tampered)


# ===========================================================================
# 7. Mock LSP server spawns with a scrubbed environment
# ===========================================================================
@pytest.mark.asyncio
async def test_mock_lsp_server_environment_is_scrubbed(monkeypatch, tmp_path, _fresh_lsp_home):
    from agent.lsp.client import LSPClient

    home = _fresh_lsp_home
    _seed_canaries(monkeypatch)
    dump = tmp_path / "server_env.json"
    mock_server = str(Path(__file__).parent / "_mock_lsp_server.py")

    client = LSPClient(
        server_id="mock-env",
        workspace_root=str(tmp_path),
        command=[sys.executable, mock_server],
        env={
            "MOCK_LSP_SCRIPT": "clean",
            "MOCK_LSP_ENV_DUMP": str(dump),
            # An override attempting to smuggle a credential must be dropped.
            "OPENAI_API_KEY": "override-canary",
        },
        cwd=str(tmp_path),
    )
    await client.start()
    try:
        assert client.is_running
    finally:
        await client.shutdown()

    env = json.loads(dump.read_text(encoding="utf-8"))
    for canary in CANARIES:
        assert canary not in env, f"language server saw credential {canary}"
    assert "OPENAI_API_KEY" not in env  # override could not re-add it
    assert env.get("HERMES_HOME") == str(home)
    assert env.get("MOCK_LSP_SCRIPT") == "clean"


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])

"""Final-confirmation regression tests for WP4 Alerts 1-3.

Alert 1 - cross-profile managed aliases: hermes_managed_roots() enumerates the
default root AND every profile's managed roots independent of the active
HERMES_HOME, so a secondary profile can never execute the default (or a sibling)
profile's managed binary via a PATH/symlink/junction/case alias.

Alert 2 - browser-use integrity: tool_marker_ok() rehashes the FULL tool tree on
every call (no launcher-keyed cache), so a same-process in-place mutation is
rejected on the next invocation.

Alert 3 - npm coverage: root package.json install:* scripts and workflow /
global npm bootstraps are gated (--ignore-scripts, exact global pin), and the
supply-chain scanner covers package.json scripts + workflow run/command blocks.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "scripts" / "ci"))

import check_supply_chain as C  # noqa: E402
from hermes_cli.supply_chain import managed  # noqa: E402
from hermes_cli.supply_chain.managed import (  # noqa: E402
    accept_operator_path,
    compute_tree_digest,
    hermes_managed_roots,
    is_under_managed_root,
    tool_marker_ok,
    write_marker,
    write_tool_marker,
)

_NPM = shutil.which("npm")
_COMPONENTS = ["bws", "uv", "node", "browser-use", "iron-proxy", "tirith"]


# ── Alert 1: cross-profile managed-root enumeration ─────────────────────────


@pytest.fixture
def profile_tree(tmp_path, monkeypatch):
    """A default Hermes root with two profiles; the ACTIVE profile is the
    *secondary* one (coder). Returns (default_root, active_profile)."""
    home = tmp_path
    default_root = home / ".hermes"
    (default_root / "bin").mkdir(parents=True)
    (default_root / "node" / "bin").mkdir(parents=True)
    coder = default_root / "profiles" / "coder"
    alt = default_root / "profiles" / "alt"
    for p in (coder, alt):
        (p / "bin").mkdir(parents=True)
        (p / "uv-tools").mkdir(parents=True)
        (p / "cache").mkdir(parents=True)

    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("HERMES_HOME", str(coder))  # ACTIVE = secondary profile
    import hermes_constants as hc

    monkeypatch.setattr(hc, "_get_platform_default_hermes_home", lambda: default_root)
    monkeypatch.setattr(hc, "_default_hermes_root_memo", None, raising=False)
    return default_root, coder


def _canon_set(paths):
    return {managed._canon(p) for p in paths}


def test_managed_roots_include_default_and_all_profiles(profile_tree):
    default_root, active = profile_tree
    roots = _canon_set(hermes_managed_roots())
    # default root's bin/node AND both profiles' bin/uv-tools/cache are covered,
    # even though the ACTIVE home is only the coder profile.
    assert managed._canon(default_root / "bin") in roots
    assert managed._canon(default_root / "node" / "bin") in roots
    for prof in ("coder", "alt"):
        base = default_root / "profiles" / prof
        assert managed._canon(base / "bin") in roots
        assert managed._canon(base / "uv-tools") in roots
        assert managed._canon(base / "cache") in roots


@pytest.mark.parametrize("component", _COMPONENTS)
def test_secondary_profile_rejects_default_profile_binary(profile_tree, component):
    """From the secondary profile, an UNMARKED managed binary in the DEFAULT
    profile's bin (resolved as an 'operator' path via alias) is rejected for
    every component — never executed on the strength of the alias."""
    default_root, _active = profile_tree
    binpath = default_root / "bin" / component
    binpath.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
    # It IS under a managed root (the default profile's bin) as seen from the
    # secondary profile...
    assert is_under_managed_root(binpath)
    # ...so the classifier refuses it (unmarked) even though it exists+resolves.
    assert accept_operator_path(str(binpath), component=component) is None


def test_secondary_profile_bws_with_token_blocked(profile_tree, monkeypatch):
    """The exact 'default-profile bws w/ BWS token' scenario: a token being set
    must not cause the unmarked cross-profile bws to be handed back/executed."""
    default_root, _active = profile_tree
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok-secret")
    bws = default_root / "bin" / "bws"
    bws.write_text("#!/bin/sh\necho token-would-run\n", encoding="utf-8")
    assert accept_operator_path(str(bws), component="bws") is None
    # A marker on the DEFAULT-profile bws makes it acceptable (tamper-bound),
    # proving the gate is marker-based, not a blanket cross-profile ban.
    write_marker(bws, component="bws", version="1", provenance="test")
    assert accept_operator_path(str(bws), component="bws") == str(bws)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_symlink_alias_into_managed_root_rejected(profile_tree, tmp_path):
    default_root, _active = profile_tree
    real = default_root / "bin" / "uv"
    real.write_text("#!/bin/sh\necho x\n", encoding="utf-8")
    link = tmp_path / "operator_uv"  # looks like an operator path...
    link.symlink_to(real)            # ...but realpath lands in the managed root
    assert is_under_managed_root(link)
    assert accept_operator_path(str(link), component="uv") is None


@pytest.mark.skipif(os.name != "nt", reason="Windows case-insensitive paths")
def test_case_variant_alias_into_managed_root_rejected(profile_tree):
    default_root, _active = profile_tree
    real = default_root / "bin" / "uv"
    real.write_text("x", encoding="utf-8")
    variant = str(real).upper()  # UV, BIN, ... case variant of the same file
    assert is_under_managed_root(variant)
    assert accept_operator_path(variant, component="uv") is None


# ── Alert 2: browser-use tree rehash on same-process mutation ───────────────


def test_tool_marker_rejects_same_process_tree_mutation(tmp_path):
    """A file mutated in place inside the tool venv is rejected on the very next
    tool_marker_ok() call in the SAME process — the digest is rehashed, not
    served from a launcher-keyed cache."""
    launcher = tmp_path / "bin" / "browser-use"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/bin/sh\nexec browser_use\n", encoding="utf-8")
    tree = tmp_path / "uv-tools" / "browser-use"
    (tree / "pkg").mkdir(parents=True)
    victim = tree / "pkg" / "cli.py"
    victim.write_text("print('legit')\n", encoding="utf-8")

    write_tool_marker(
        launcher, tree_dir=tree, component="browser-use", version="1", provenance="test"
    )
    assert tool_marker_ok(launcher, tree_dir=tree, component="browser-use")

    # Mutate a package file in place; do NOT clear any cache or touch launcher.
    victim.write_text("import os; os.system('evil')\n", encoding="utf-8")
    assert not tool_marker_ok(
        launcher, tree_dir=tree, component="browser-use"
    ), "in-place tree mutation must be rejected on the next resolve"

    # There is no launcher-keyed cache to fool.
    assert not hasattr(managed, "_tool_tree_cache")


def test_tree_digest_changes_on_any_mutation(tmp_path):
    tree = tmp_path / "t"
    (tree / "a").mkdir(parents=True)
    (tree / "a" / "f.py").write_text("1", encoding="utf-8")
    d0 = compute_tree_digest(tree)
    (tree / "a" / "f.py").write_text("2", encoding="utf-8")  # edit
    assert compute_tree_digest(tree) != d0
    (tree / "a" / "g.py").write_text("x", encoding="utf-8")  # add
    d2 = compute_tree_digest(tree)
    (tree / "a" / "g.py").unlink()  # remove
    assert compute_tree_digest(tree) != d2


# ── Alert 3: npm coverage (package.json + workflows) ────────────────────────


def test_root_install_scripts_gated_and_orchestrated():
    scripts = json.loads((_REPO / "package.json").read_text(encoding="utf-8"))["scripts"]
    for name in ("install:root", "install:web", "install:tui", "install:desktop"):
        cmd = scripts[name]
        assert "--ignore-scripts" in cmd, f"{name} lacks --ignore-scripts: {cmd}"
        assert "run-allowed-lifecycle.mjs" in cmd, f"{name} lacks the orchestrator: {cmd}"
        assert C._npm_command_offenses(cmd) == [], f"{name} still flagged: {cmd}"


def test_workflow_npm_is_clean_no_direct_global_registry_install():
    # The exact-pin/trusted-installer contract lives in test_npm_bootstrap.py.
    # Here we only assert the workflow surface is clean and free of a direct
    # global `npm@` registry install (superseded by the digest-pinned installer).
    import yaml

    wf_dir = _REPO / ".github" / "workflows"
    findings = C.Findings()
    C.scan_workflow_npm(_REPO, findings)
    assert findings.ok(), "workflow npm findings:\n" + "\n".join(findings.errors)
    for wf in wf_dir.glob("*.yml"):
        for cmd in C._iter_yaml_command_strings(yaml.safe_load(wf.read_text(encoding="utf-8"))):
            assert not re.search(r"\bnpm@\d", cmd), f"{wf.name} installs npm@ directly: {cmd}"


def test_scanner_flags_ungated_package_json_script(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"setup": "npm install --workspace web"}}), encoding="utf-8"
    )
    findings = C.Findings()
    C.scan_package_json_scripts(tmp_path, findings)
    assert not findings.ok()
    assert any("setup" in e and "--ignore-scripts" in e for e in findings.errors)


def test_scanner_flags_direct_global_and_missing_ignore_scripts(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "x.yml").write_text(
        "on: push\njobs:\n  a:\n    steps:\n"
        "      - run: npm i -g npm@12\n"
        "      - run: npm ci\n",
        encoding="utf-8",
    )
    findings = C.Findings()
    C.scan_workflow_npm(tmp_path, findings)
    msgs = "\n".join(findings.errors).lower()
    assert "direct global npm registry install" in msgs  # npm@12 -> use installer
    assert "install-npm-pinned.mjs" in msgs
    assert "--ignore-scripts" in msgs  # both npm i -g and npm ci lack it


def test_scanner_accepts_gated_workflow(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ok.yml").write_text(
        "on: push\njobs:\n  a:\n    steps:\n"
        "      - run: node scripts/ci/install-npm-pinned.mjs\n"
        "      - uses: ./.github/actions/retry\n"
        "        with:\n          command: npm ci --ignore-scripts\n",
        encoding="utf-8",
    )
    findings = C.Findings()
    C.scan_workflow_npm(tmp_path, findings)
    assert findings.ok(), findings.errors


@pytest.mark.skipif(not _NPM, reason="npm not on PATH")
def test_install_desktop_npm_command_ignores_scripts_on_npm10(tmp_path):
    """Behavioral: the npm-install segment of the real `install:desktop` script,
    run by the host npm against a workspace whose dependency has a postinstall
    hook, does NOT run that hook (--ignore-scripts holds on npm 10)."""
    install_desktop = json.loads(
        (_REPO / "package.json").read_text(encoding="utf-8")
    )["scripts"]["install:desktop"]
    npm_seg = install_desktop.split("&&")[0].strip()  # the npm install part
    assert "--ignore-scripts" in npm_seg

    # Build a minimal root workspace mirroring `--workspace apps/desktop`.
    root = tmp_path / "proj"
    (root / "apps" / "desktop").mkdir(parents=True)
    sentinel = root / "HOOK_RAN"
    (root / "package.json").write_text(
        json.dumps({"name": "r", "private": True, "workspaces": ["apps/desktop"]}),
        encoding="utf-8",
    )
    (root / "apps" / "desktop" / "package.json").write_text(
        json.dumps(
            {
                "name": "d",
                "version": "1.0.0",
                "dependencies": {"evilhook": "file:../../evilhook"},
            }
        ),
        encoding="utf-8",
    )
    evil = root / "evilhook"
    evil.mkdir()
    (evil / "package.json").write_text(
        json.dumps(
            {
                "name": "evilhook",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "node -e \"require('fs').writeFileSync(process.env.HOOK_SENTINEL,'x')\""
                },
            }
        ),
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "HOOK_SENTINEL": str(sentinel),
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_cache": str(tmp_path / "npmcache"),
    }
    # control: without the flag the hook DOES run (proves the test is real)
    ctl = tmp_path / "ctl"
    shutil.copytree(root, ctl)
    try:
        subprocess.run(
            [_NPM, "install", "--workspace", "apps/desktop", "--no-audit", "--no-fund"],
            cwd=str(ctl), env={**env, "HOOK_SENTINEL": str(ctl / "HOOK_RAN")},
            capture_output=True, text=True, timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:  # pragma: no cover
        pytest.skip(f"npm unavailable: {exc}")
    if not (ctl / "HOOK_RAN").exists():
        pytest.skip("npm did not run a workspace file: postinstall here; cannot prove contract")

    # gated: the real install:desktop npm segment must NOT run the hook
    args = [_NPM] + npm_seg.split()[1:] + ["--no-audit", "--no-fund"]
    subprocess.run(args, cwd=str(root), env=env, capture_output=True, text=True, timeout=180)
    assert not sentinel.exists(), "install:desktop npm segment ran a dependency postinstall"

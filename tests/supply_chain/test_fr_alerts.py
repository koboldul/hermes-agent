"""Final-review regression tests for alerts A1 (shell/PS fast paths), A3
(js-tests cache), A4 (guidance recipes), A5 (fail-closed YAML scanner).

A6 (publication transaction) is covered by test_a6_transaction.py; A1 Python
node ordering by test_a6_node.py-adjacent behavior exercised here for the shell
side.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "scripts" / "ci"))
import check_supply_chain as C  # noqa: E402

_INSTALL_SH = _REPO / "scripts" / "install.sh"


# ── A5: PyYAML-parsed, FAIL-CLOSED workflow npm audit ───────────────────────


def test_iter_commands_handles_all_yaml_forms():
    import yaml

    def cmds(y):
        return list(C._iter_yaml_command_strings(yaml.safe_load(y)))

    # block `|`
    assert any("npm ci" in c for c in cmds("jobs:\n  a:\n    steps:\n      - run: |\n          npm ci\n          echo ok\n"))
    # folded `>`
    assert any("npm install" in c for c in cmds("steps:\n  - run: >\n      npm install --workspace web\n"))
    # explicit-indent + strip block `|2-`
    assert any("npm ci" in c for c in cmds("step:\n  run: |2-\n    npm ci\n"))
    # with: command:
    assert any("npm ci" in c for c in cmds("steps:\n  - with:\n      command: npm ci\n"))
    # composite action
    assert any("npm ci" in c for c in cmds("runs:\n  using: composite\n  steps:\n    - run: npm ci\n"))
    # flow mapping
    assert any("npm ci" in c for c in cmds('steps: [{run: "npm ci"}]\n'))
    # quoted key
    assert any("npm ci" in c for c in cmds('steps:\n  - "run": npm ci\n'))
    # multiline plain scalar (folded continuation)
    assert any("npm install" in c and "web" in c for c in cmds("steps:\n  - run: npm install\n      --workspace web\n"))
    # anchors / aliases
    assert any("npm ci" in c for c in cmds("x: &a\n  run: npm ci\njobs:\n  a:\n    steps:\n      - *a\n"))


def test_scan_workflow_npm_flags_block_scalar_ungated(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "x.yml").write_text(
        "jobs:\n  a:\n    steps:\n      - run: |\n          npm ci\n", encoding="utf-8"
    )
    findings = C.Findings()
    C.scan_workflow_npm(tmp_path, findings)
    assert any("--ignore-scripts" in e for e in findings.errors)


def test_scan_workflow_npm_no_pyyaml_fails_closed(tmp_path, monkeypatch):
    """PyYAML is a HARD prerequisite: blocking its import must FAIL CLOSED with a
    finding, never fall open to a weak regex fallback."""
    real_import = __import__

    def _blocked(name, *a, **k):
        if name == "yaml" or name.startswith("yaml."):
            raise ImportError("blocked")
        return real_import(name, *a, **k)

    monkeypatch.setattr("builtins.__import__", _blocked)
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "x.yml").write_text("steps:\n  - run: |\n      npm ci\n", encoding="utf-8")
    findings = C.Findings()
    C.scan_workflow_npm(tmp_path, findings)
    assert not findings.ok()
    assert any("PyYAML" in e and "failing closed" in e for e in findings.errors)


def test_scan_workflow_npm_malformed_fails_closed(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "x.yml").write_text("steps:\n  - run: '[unbalanced\n", encoding="utf-8")
    findings = C.Findings()
    C.scan_workflow_npm(tmp_path, findings)
    assert any("unparseable YAML" in e and "fail closed" in e for e in findings.errors)


def test_scan_workflow_npm_unreadable_fails_closed(tmp_path, monkeypatch):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    bad = wf / "x.yml"
    bad.write_text("steps: []\n", encoding="utf-8")
    orig = Path.read_text

    def _boom(self, *a, **k):
        if self == bad:
            raise OSError("unreadable")
        return orig(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", _boom)
    findings = C.Findings()
    C.scan_workflow_npm(tmp_path, findings)
    assert any("fail closed" in e for e in findings.errors)


def test_real_workflows_scan_clean():
    findings = C.Findings()
    C.scan_workflow_npm(_REPO, findings)
    assert findings.ok(), "\n".join(findings.errors)


# ── A4: unsafe operator-guidance recipes ────────────────────────────────────


def test_recipe_hint_flags_unsafe_and_accepts_safe():
    assert C._npm_recipe_hint_unsafe('log_info "cd X && npm ci && npm run pack"')
    assert C._npm_recipe_hint_unsafe('print("Run: cd d && npm install")')
    # safe recipe (has --ignore-scripts + orchestrator) is accepted
    assert not C._npm_recipe_hint_unsafe(
        'log_info "cd X && npm ci --ignore-scripts && node apps/desktop/scripts/run-allowed-lifecycle.mjs"'
    )
    # a bare failure mention is NOT a recipe
    assert not C._npm_recipe_hint_unsafe('log_error "npm install failed or timed out"')


def test_recipe_hint_flags_global_npm_registry_recommendation():
    # UNCHAINED global npm@ registry install recommendation is unsafe (it trusts
    # registry metadata) — even with --ignore-scripts, and even without `&&`.
    assert C._npm_recipe_hint_unsafe('Fix manually: npm install -g --prefix "$X" npm@"$range"')
    assert C._npm_recipe_hint_unsafe("run manually: npm i -g npm@12.0.2")
    assert C._npm_recipe_hint_unsafe('npm install -g npm@"$range" --ignore-scripts')
    # the digest-pinned bootstrap is the safe recommendation
    assert not C._npm_recipe_hint_unsafe(
        "Fix manually: run 'node scripts/ci/install-npm-pinned.mjs' (digest-pinned npm bootstrap)"
    )


def test_recipe_hint_flags_workspace_recipe_with_args_before_and():
    """A4 (final): a workspace-build recipe with ARGUMENTS before `&&` — the
    exact `hermes_cli/main.py` recovery form — is flagged; the safe sequence
    (`npm ci --ignore-scripts && run-allowed-lifecycle.mjs && npm run build`) is
    accepted."""
    assert C._npm_recipe_hint_unsafe("npm install --workspace web && npm run build -w web")
    assert C._npm_recipe_hint_unsafe("Run manually:  npm install --workspace web && npm run build -w web")
    assert not C._npm_recipe_hint_unsafe(
        "npm ci --workspace web --ignore-scripts && node apps/desktop/scripts/run-allowed-lifecycle.mjs && npm run build -w web"
    )
    # prose with punctuation (`;`, a distant `&&` in a template) is NOT a recipe
    assert not C._npm_recipe_hint_unsafe("npm install failed or timed out; deps were not installed")
    assert not C._npm_recipe_hint_unsafe("npm install failed. Run `cd d && x install` manually")
    assert not C._npm_recipe_hint_unsafe("npm install of the verified tarball failed (status ${res && res.status})")
    # a global install of an EXTERNAL tool is an operator choice, not this gate's recipe
    assert not C._npm_recipe_hint_unsafe("npm install -g agent-browser && agent-browser install")


def test_full_tree_has_no_unsafe_recipe_or_ungated_npm():
    findings = C.Findings()
    C.scan_npm_lifecycle(_REPO, findings)
    assert findings.ok(), "\n".join(findings.errors[:20])


# ── A3: js-tests node_modules cache REMOVED (fresh install every run) ───────


def test_js_tests_has_no_node_modules_cache():
    """A3 (final): the node_modules cache was REMOVED entirely — a restore/save
    cache would let a poisoned tree carry a matching-but-forged provenance marker
    stored INSIDE the cache. Every run must install fresh from the trusted,
    committed lockfile with `npm ci --ignore-scripts`, then the audited lifecycle,
    then the pre-test native-payload verification. No cache restore/save, no cache
    key, no cache-hit path."""
    import yaml

    doc = yaml.safe_load((_REPO / ".github" / "workflows" / "js-tests.yml").read_text(encoding="utf-8"))
    steps = [s for j in doc["jobs"].values() for s in j.get("steps", [])]

    for s in steps:
        uses = str(s.get("uses", ""))
        assert "actions/cache" not in uses, f"node_modules cache must be removed: {uses}"
        assert "cache-hit" not in str(s.get("if", "")), "no cache-hit conditional may remain"
        assert "cache-provenance" not in str(s.get("run", "")), "cache-provenance marker path removed"
        assert not (isinstance(s.get("with"), dict) and "key" in s["with"]), "no cache key may remain"

    # `npm ci --ignore-scripts` runs UNCONDITIONALLY (no cache-hit gate).
    install_steps = [
        s for s in steps
        if "npm ci --ignore-scripts" in str((s.get("with") or {}).get("command", ""))
        or "npm ci --ignore-scripts" in str(s.get("run", ""))
    ]
    assert install_steps, "no `npm ci --ignore-scripts` install step"
    for s in install_steps:
        assert not s.get("if"), "install must run unconditionally (no cache-hit gate)"

    # audited lifecycle + native-payload verify precede the workspace checks.
    runs = [str(s.get("run", "")) for s in steps]
    lifecycle_idx = next((i for i, r in enumerate(runs) if "run-allowed-lifecycle" in r), None)
    verify_idx = next((i for i, r in enumerate(runs) if "verify-native-payloads" in r), None)
    checks_idx = next((i for i, r in enumerate(runs) if "run-workspace-checks" in r), None)
    assert lifecycle_idx is not None, "no audited-lifecycle step"
    assert verify_idx is not None, "no native-payload verify step"
    assert checks_idx is not None
    assert lifecycle_idx < checks_idx and verify_idx < checks_idx, (
        "audited lifecycle + native-payload verify must precede the tests"
    )


# ── A1: shell fast-path managed-alias rejection ─────────────────────────────


def _find_bash():
    cands = []
    if sys.platform == "win32":
        cands += [r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"]
    w = shutil.which("bash")
    if w:
        cands.append(w)
    return next((c for c in cands if c and Path(c).exists()), None)


_BASH = _find_bash()


def _extract_and_run(script_body: str, tmp_path: Path) -> subprocess.CompletedProcess:
    sh_posix = str(_INSTALL_SH).replace("\\", "/")
    helpers = (tmp_path / "h.sh").as_posix()
    drv = tmp_path / "drv.sh"
    drv.write_text(
        "#!/usr/bin/env bash\n"
        "set -u\n"
        f'INSTALL_SH="{sh_posix}"\n'
        f'HELPERS="{helpers}"\n'
        'start=$(grep -n "^_sc_sha256() {" "$INSTALL_SH" | head -1 | cut -d: -f1)\n'
        'tail -n +"$start" "$INSTALL_SH" | '
        "awk '{print} /_sc_accept_operator\\(\\) \\{/{ina=1} ina && /^}$/{exit}' > \"$HELPERS\"\n"
        '. "$HELPERS"\n'
        + script_body,
        encoding="utf-8",
    )
    home = (tmp_path / "home")
    env = {
        **os.environ,
        "HOME": str(home),
        "HERMES_HOME": str(home / ".hermes"),
    }
    return subprocess.run([_BASH, str(drv)], capture_output=True, text=True, env=env, timeout=60)


@pytest.mark.skipif(_BASH is None, reason="bash unavailable")
@pytest.mark.live_system_guard_bypass
def test_shell_rejects_unmarked_managed_accepts_operator(tmp_path):
    body = (
        'mkdir -p "$HERMES_HOME/bin"\n'
        'mgd="$HERMES_HOME/bin/uv"; printf "#!/bin/sh\\necho x\\n" > "$mgd"; chmod +x "$mgd"\n'
        'gen="$HOME/realuv"; printf "#!/bin/sh\\necho y\\n" > "$gen"; chmod +x "$gen"\n'
        # direct managed unmarked -> rejected
        'r=$(_sc_accept_operator "$mgd"); [ -z "$r" ] && echo MGD_REJECTED || echo MGD_ACCEPTED\n'
        # genuine operator -> accepted
        'r=$(_sc_accept_operator "$gen"); [ -n "$r" ] && echo GEN_ACCEPTED || echo GEN_REJECTED\n'
        # mark it -> accepted
        '_sc_write_managed_marker "$mgd" uv 1 test\n'
        'r=$(_sc_accept_operator "$mgd"); [ -n "$r" ] && echo MGD_MARKED_ACCEPTED || echo MGD_MARKED_REJECTED\n'
    )
    r = _extract_and_run(body, tmp_path)
    assert "MGD_REJECTED" in r.stdout, (r.stdout, r.stderr)
    assert "GEN_ACCEPTED" in r.stdout
    assert "MGD_MARKED_ACCEPTED" in r.stdout


@pytest.mark.skipif(_BASH is None or os.name == "nt", reason="POSIX symlink aliasing")
@pytest.mark.live_system_guard_bypass
def test_shell_rejects_symlink_alias_into_managed_root(tmp_path):
    body = (
        'mkdir -p "$HERMES_HOME/bin"\n'
        'mgd="$HERMES_HOME/bin/uv"; printf "#!/bin/sh\\necho x\\n" > "$mgd"; chmod +x "$mgd"\n'
        'ln -s "$mgd" "$HOME/operator_uv"\n'  # alias into managed root
        'r=$(_sc_accept_operator "$HOME/operator_uv"); [ -z "$r" ] && echo ALIAS_REJECTED || echo ALIAS_ACCEPTED\n'
    )
    r = _extract_and_run(body, tmp_path)
    assert "ALIAS_REJECTED" in r.stdout, (r.stdout, r.stderr)


# ── A1: Python node resolver verifies marker BEFORE executing ───────────────


@pytest.mark.live_system_guard_bypass
def test_find_hermes_node_never_executes_unmarked_tree(tmp_path, monkeypatch):
    """find_hermes_node_executable must verify the provenance marker BEFORE
    node_tool_runnable runs `node --version`, so an unmarked managed node is
    never executed (the sentinel stays absent) and is not returned."""
    home = tmp_path / ".hermes"
    nodedir = home / "node" / "bin"
    nodedir.mkdir(parents=True)
    sentinel = tmp_path / "EXECUTED"
    node = nodedir / ("node.exe" if os.name == "nt" else "node")
    node.write_text(
        f'#!/bin/sh\necho ran > "{sentinel.as_posix()}"\necho v99.0.0\n', encoding="utf-8"
    )
    if os.name != "nt":
        node.chmod(0o755)
    monkeypatch.setenv("HERMES_HOME", str(home))
    import hermes_constants as hc

    monkeypatch.setattr(hc, "heal_hermes_managed_node", lambda: False)

    assert hc.find_hermes_node_executable("node") is None, "unmarked node returned"
    assert not sentinel.exists(), "unmarked managed node was EXECUTED before the marker check"


def test_managed_node_marker_binds_whole_tree(tmp_path):
    """The node marker binds the WHOLE tree (node exe + npm/npx wrappers + npm
    CLI JS). A swap of ANY of them — including a same-size, mtime-restored
    in-place edit of one npm library file — fails the marker check (no cache)."""
    import hermes_constants as hc
    from hermes_cli.supply_chain.managed import write_tool_marker

    root = tmp_path / ".hermes" / "node"
    bind = root / "bin"
    npmlib = root / "lib" / "node_modules" / "npm" / "lib"
    bind.mkdir(parents=True)
    npmlib.mkdir(parents=True)
    node = bind / ("node.exe" if os.name == "nt" else "node")
    node.write_text("NODE-BINARY-BYTES-AAAA\n", encoding="utf-8")
    (bind / "npm").write_text("NPM-WRAPPER-AAAA\n", encoding="utf-8")
    (bind / "npx").write_text("NPX-WRAPPER-AAAA\n", encoding="utf-8")
    cli = npmlib / "cli.js"
    cli.write_text("console.log('npm cli AAAA')\n", encoding="utf-8")

    anchor = hc._managed_node_anchor(bind)
    assert anchor is not None
    tree_root = hc._managed_node_tree_root(anchor)
    assert tree_root == root
    write_tool_marker(anchor, tree_dir=tree_root, component="node", version="v99", provenance="test")
    assert hc._managed_node_marked(anchor) is True

    # (1) same-size, mtime-restored in-place edit of an npm library file
    st = cli.stat()
    cli.write_text("console.log('npm cli BBBB')\n", encoding="utf-8")  # identical length
    os.utime(cli, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert cli.stat().st_size == st.st_size and cli.stat().st_mtime_ns == st.st_mtime_ns
    assert hc._managed_node_marked(anchor) is False, "same-size mtime-restored npm CLI tamper not caught"

    # restore -> valid again
    cli.write_text("console.log('npm cli AAAA')\n", encoding="utf-8")
    os.utime(cli, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert hc._managed_node_marked(anchor) is True

    # (2) npm wrapper tamper
    (bind / "npm").write_text("NPM-WRAPPER-XXXX\n", encoding="utf-8")
    assert hc._managed_node_marked(anchor) is False, "npm wrapper tamper not caught"
    (bind / "npm").write_text("NPM-WRAPPER-AAAA\n", encoding="utf-8")
    assert hc._managed_node_marked(anchor) is True

    # (3) npx wrapper tamper
    (bind / "npx").write_text("NPX-WRAPPER-XXXX\n", encoding="utf-8")
    assert hc._managed_node_marked(anchor) is False, "npx wrapper tamper not caught"
    (bind / "npx").write_text("NPX-WRAPPER-AAAA\n", encoding="utf-8")
    assert hc._managed_node_marked(anchor) is True

    # (4) node executable tamper
    node.write_text("NODE-BINARY-BYTES-XXXX\n", encoding="utf-8")
    assert hc._managed_node_marked(anchor) is False, "node exe tamper not caught"

    # (5) an added rogue file anywhere in the tree
    node.write_text("NODE-BINARY-BYTES-AAAA\n", encoding="utf-8")
    assert hc._managed_node_marked(anchor) is True
    (npmlib / "rogue.js").write_text("evil()\n", encoding="utf-8")
    assert hc._managed_node_marked(anchor) is False, "added rogue tree file not caught"

"""Behavioral tests for the A4 npm audited-lifecycle policy.

Every production ``npm install`` / ``npm ci`` must run with ``--ignore-scripts``
so no dependency runs arbitrary install-time code on any supported npm major
(npm 10 IGNORES the package.json ``allowScripts`` allowlist). The reviewed,
allowlisted lifecycle (node-pty/esbuild/electron rebuild; ``get-windows`` NEVER)
then runs via the audited orchestrator
(``apps/desktop/scripts/run-allowed-lifecycle.mjs``) for the root workspace, or
an explicit first-party step for a standalone sidecar.

These tests are behavioral: they run the real scanner over the real tree, run
the real npm/node where available (skip otherwise), drive the real orchestrator
decision function under node, and parse the real Dockerfile as a build-path
proxy (``docker build`` is not available in unit CI).
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

_NPM = shutil.which("npm")
_NODE = shutil.which("node")
_ORCH = _REPO / "apps" / "desktop" / "scripts" / "run-allowed-lifecycle.mjs"


# ── Scanner: the real tree is clean ─────────────────────────────────────────


def test_scanner_passes_current_repo():
    """Every production npm install/ci in the tree is gated (0 findings)."""
    findings = C.Findings()
    C.scan_npm_lifecycle(_REPO, findings)
    assert findings.ok(), "ungated npm install/ci found:\n" + "\n".join(findings.errors)


# ── Scanner: ungated invocations ARE flagged (negative fixtures) ────────────


def test_scanner_flags_ungated_shell(tmp_path):
    (tmp_path / "install.sh").write_text("#!/bin/bash\nnpm ci\n", encoding="utf-8")
    findings = C.Findings()
    hits = C.scan_npm_lifecycle(tmp_path, findings)
    assert "install.sh" in hits
    assert not findings.ok()


def test_scanner_flags_ungated_dockerfile(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM x\nRUN npm install --prefer-offline\n", encoding="utf-8"
    )
    findings = C.Findings()
    hits = C.scan_npm_lifecycle(tmp_path, findings)
    assert "Dockerfile" in hits


def test_scanner_flags_ungated_python_argv(tmp_path):
    (tmp_path / "mod.py").write_text(
        'import subprocess\nsubprocess.run([npm, "ci"], cwd=d)\n', encoding="utf-8"
    )
    findings = C.Findings()
    hits = C.scan_npm_lifecycle(tmp_path, findings)
    assert "mod.py" in hits


def test_scanner_flags_ungated_powershell(tmp_path):
    (tmp_path / "x.ps1").write_text("& $npmExe ci 2>&1 | Out-Null\n", encoding="utf-8")
    findings = C.Findings()
    hits = C.scan_npm_lifecycle(tmp_path, findings)
    assert "x.ps1" in hits


# ── Scanner: gated / exempt invocations are NOT flagged ─────────────────────


def test_scanner_accepts_ignore_scripts(tmp_path):
    (tmp_path / "install.sh").write_text("npm ci --ignore-scripts\n", encoding="utf-8")
    (tmp_path / "y.py").write_text(
        'subprocess.run([npm, "ci", "--ignore-scripts"])\n', encoding="utf-8"
    )
    (tmp_path / "p.ps1").write_text("& $npmExe ci --ignore-scripts\n", encoding="utf-8")
    findings = C.Findings()
    hits = C.scan_npm_lifecycle(tmp_path, findings)
    assert hits == []
    assert findings.ok()


def test_scanner_accepts_package_lock_only(tmp_path):
    # --package-lock-only updates the lockfile WITHOUT installing or running any
    # lifecycle script, so it needs no --ignore-scripts.
    (tmp_path / "z.sh").write_text(
        "npm i --package-lock-only --silent --no-audit\n", encoding="utf-8"
    )
    findings = C.Findings()
    assert C.scan_npm_lifecycle(tmp_path, findings) == []


def test_scanner_ignores_message_strings(tmp_path):
    # A shell log line, a PS throw, a Python argparse help, and a JS console
    # message all MENTION npm ci/install as prose but are neither an invocation
    # nor a copy-paste recipe (no `cd X && npm ci` chaining), so they are ignored.
    (tmp_path / "a.sh").write_text(
        'log_info "npm ci failed or timed out; retry later"\n', encoding="utf-8"
    )
    (tmp_path / "b.ps1").write_text('throw "npm install failed"\n', encoding="utf-8")
    (tmp_path / "c.py").write_text(
        'help="Skip npm install/package and launch"\n'
        'msg = f"npm ci reported an error for {d}"\n',
        encoding="utf-8",
    )
    (tmp_path / "d.mjs").write_text(
        "console.error(`npm ci did not finish`)\n", encoding="utf-8"
    )
    findings = C.Findings()
    assert C.scan_npm_lifecycle(tmp_path, findings) == []
    assert findings.ok()


def test_scanner_credits_flag_on_continuation_line(tmp_path):
    # --ignore-scripts on a `\` continuation line is credited (lines joined);
    # its absence across the continued command is still flagged.
    (tmp_path / "gated.sh").write_text(
        "npm ci \\\n  --no-audit \\\n  --ignore-scripts\n", encoding="utf-8"
    )
    (tmp_path / "bare.sh").write_text(
        "npm ci \\\n  --no-audit \\\n  --no-fund\n", encoding="utf-8"
    )
    findings = C.Findings()
    hits = C.scan_npm_lifecycle(tmp_path, findings)
    assert "bare.sh" in hits
    assert "gated.sh" not in hits


def test_scanner_credits_flag_on_powershell_backtick_continuation(tmp_path):
    (tmp_path / "gated.ps1").write_text(
        '& $npmCmd install --global "npm@$range" `\n  --ignore-scripts\n',
        encoding="utf-8",
    )
    (tmp_path / "bare.ps1").write_text(
        '& $npmCmd install --global "npm@$range" `\n  --no-fund\n', encoding="utf-8"
    )
    findings = C.Findings()
    hits = C.scan_npm_lifecycle(tmp_path, findings)
    assert "bare.ps1" in hits
    assert "gated.ps1" not in hits


# ── Install scripts: every real npm install/ci is gated ─────────────────────


@pytest.mark.parametrize(
    "rel",
    [
        "scripts/install.sh",
        "scripts/install.ps1",
        "scripts/lib/node-bootstrap.sh",
        "Dockerfile",
        "nix/lib.nix",
        "plugins/platforms/photon/adapter.py",
        "plugins/platforms/photon/cli.py",
        "plugins/platforms/whatsapp/adapter.py",
        "hermes_cli/main.py",
        "hermes_cli/web_server.py",
        "hermes_cli/tools_config.py",
    ],
)
def test_named_production_file_has_no_ungated_npm(rel):
    text = (_REPO / rel).read_text(encoding="utf-8")
    offenders = [
        line.strip()[:100]
        for line in C._npm_logical_lines(text, rel)
        if C._npm_line_needs_ignore_scripts(line, rel)
    ]
    assert not offenders, f"ungated npm install/ci in {rel}: {offenders}"


# ── Dockerfile build-path: flags + orchestrator/patch order ─────────────────


def _dockerfile_run_blocks(text: str) -> list[str]:
    """Return each ``RUN`` instruction as one logical line (continuations joined)."""
    blocks: list[str] = []
    buf = ""
    in_run = False
    for raw in text.splitlines():
        s = raw.rstrip()
        if not in_run:
            m = re.match(r"\s*RUN\s+(.*)", s)
            if not m:
                continue
            in_run = True
            body = m.group(1)
        else:
            body = s.strip()
        if body.endswith("\\"):
            buf += body[:-1] + " "
            continue
        buf += body
        blocks.append(buf)
        buf = ""
        in_run = False
    if buf:
        blocks.append(buf)
    return blocks


def test_dockerfile_every_npm_install_ci_ignores_scripts_then_runs_lifecycle():
    text = (_REPO / "Dockerfile").read_text(encoding="utf-8")
    npm_runs = [
        r for r in _dockerfile_run_blocks(text) if re.search(r"\bnpm\s+(install|ci)\b", r)
    ]
    assert npm_runs, "expected at least one npm install/ci RUN in the Dockerfile"
    for r in npm_runs:
        assert "--ignore-scripts" in r, f"npm install/ci without --ignore-scripts: {r}"
        # the audited lifecycle (root orchestrator OR the sidecar's first-party
        # patch) must follow the install in the SAME RUN, AFTER --ignore-scripts.
        tail = r[r.index("--ignore-scripts"):]
        assert ("run-allowed-lifecycle.mjs" in tail) or ("patch-spectrum" in tail), (
            f"npm install/ci not followed by the audited lifecycle: {r}"
        )
        # get-windows is never rebuilt by hand in the Dockerfile.
        assert "get-windows" not in r


def test_dockerfile_copies_orchestrator_before_root_install():
    text = (_REPO / "Dockerfile").read_text(encoding="utf-8")
    copy_idx = text.find("run-allowed-lifecycle.mjs apps/desktop/scripts/")
    m = re.search(r"RUN npm install --ignore-scripts", text)
    assert copy_idx != -1, "Dockerfile must COPY the orchestrator"
    assert m is not None, "Dockerfile must run the gated root npm install"
    assert copy_idx < m.start(), "orchestrator must be COPYed before the root npm install"


# ── Real npm 10 behavior: --ignore-scripts blocks dependency postinstall ────


@pytest.mark.live_system_guard_bypass
@pytest.mark.skipif(not _NPM, reason="npm not on PATH")
def test_ignore_scripts_blocks_dependency_postinstall(tmp_path):
    """On the host npm, ``--ignore-scripts`` prevents a dependency's postinstall
    from running; the same hook DOES run without the flag (control proves the
    test is real). Uses only a local ``file:`` dependency -- no network."""

    def _make_project(root: Path, sentinel: Path) -> None:
        root.mkdir()
        (root / "package.json").write_text(
            json.dumps(
                {
                    "name": "proj",
                    "version": "1.0.0",
                    "private": True,
                    "dependencies": {"evilhook": "file:./evilhook"},
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
                        "postinstall": (
                            "node -e \"require('fs').writeFileSync("
                            "process.env.HOOK_SENTINEL,'ran')\""
                        )
                    },
                }
            ),
            encoding="utf-8",
        )

    base_env = {
        **os.environ,
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_update_notifier": "false",
        "npm_config_cache": str(tmp_path / "npmcache"),
    }

    def _install(root: Path, sentinel: Path, *, ignore_scripts: bool) -> int:
        args = [_NPM, "install", "--no-audit", "--no-fund", "--prefer-offline"]
        if ignore_scripts:
            args.append("--ignore-scripts")
        try:
            proc = subprocess.run(
                args,
                cwd=str(root),
                env={**base_env, "HOOK_SENTINEL": str(sentinel)},
                capture_output=True,
                text=True,
                timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:  # pragma: no cover
            pytest.skip(f"npm could not run in this environment: {exc}")
        return proc.returncode

    # Control: WITHOUT --ignore-scripts the postinstall must run.
    control = tmp_path / "control"
    control_sentinel = control / "HOOK_RAN"
    _make_project(control, control_sentinel)
    _install(control, control_sentinel, ignore_scripts=False)
    if not control_sentinel.exists():
        pytest.skip(
            "npm did not run a file: dependency postinstall in this environment; "
            "cannot prove the --ignore-scripts contract here"
        )

    # Gated: WITH --ignore-scripts the same postinstall must NOT run.
    gated = tmp_path / "gated"
    gated_sentinel = gated / "HOOK_RAN"
    _make_project(gated, gated_sentinel)
    _install(gated, gated_sentinel, ignore_scripts=True)
    assert not gated_sentinel.exists(), (
        "dependency postinstall ran despite --ignore-scripts"
    )


# ── Real orchestrator decision: get-windows / denied never rebuilt ──────────


@pytest.mark.live_system_guard_bypass
@pytest.mark.skipif(not _NODE or not _ORCH.exists(), reason="node/orchestrator unavailable")
def test_orchestrator_never_rebuilds_get_windows_or_denied(tmp_path):
    """Drive the real orchestrator's exported ``rebuildDecision`` under node.

    Even if an ``allowScripts`` entry is flipped ``true`` for get-windows, it is
    never rebuilt (it is on ``NEVER_RUN``); an ``allowScripts:false`` package is
    never rebuilt; a lock-version mismatch is skipped; only lock-matched
    allowlisted packages are rebuilt.
    """
    harness = tmp_path / "harness.mjs"
    harness.write_text(
        "import { rebuildDecision } from "
        + json.dumps(_ORCH.as_uri())
        + "\n"
        "const allowScripts = {\n"
        '  "node-pty@1.1.0": true,\n'
        '  "esbuild@0.28.1": true,\n'
        '  "get-windows@9.3.0": true,\n'          # deny-list wins even if true
        '  "unicode-animations@1.0.0": false,\n'  # allowScripts:false
        '  "electron@41.10.3": true,\n'           # lock mismatch below -> skipped
        "}\n"
        "const lock = {\n"
        '  "node-pty": "1.1.0", "esbuild": "0.28.1", "get-windows": "9.3.0",\n'
        '  "electron": "40.0.0",\n'
        "}\n"
        "const d = rebuildDecision({ allowScripts, lockVersionOf: (n) => lock[n] || null })\n"
        "console.log(JSON.stringify(d))\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [_NODE, str(harness)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    decision = json.loads(proc.stdout.strip().splitlines()[-1])

    assert "get-windows" in decision["neverRun"]
    assert "get-windows" not in decision["rebuild"]
    assert "unicode-animations" not in decision["rebuild"]  # allowScripts:false
    assert "electron" not in decision["rebuild"]  # lock version mismatch
    assert "node-pty" in decision["rebuild"]
    assert "esbuild" in decision["rebuild"]

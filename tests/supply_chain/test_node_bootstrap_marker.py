"""A1 (pre-marker execution) behavioral tests for scripts/lib/node-bootstrap.sh.

node-bootstrap.sh symlinks ``$HERMES_HOME/node/bin`` onto PATH, so a bare
``node`` can resolve — and the script would otherwise execute, even for a
``--version`` probe — a Hermes-managed Node on a later run. These tests source
the real script and drive its real functions, asserting that an unmarked or
tampered managed Node is NEVER executed (no sentinel written) and that the heal
path fails closed instead of running it. Behavior, not source text.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_NODE_BOOTSTRAP = _REPO / "scripts" / "lib" / "node-bootstrap.sh"


def _find_bash():
    cands = []
    if sys.platform == "win32":
        cands += [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        ]
    w = shutil.which("bash")
    if w:
        cands.append(w)
    return next((c for c in cands if c and Path(c).exists()), None)


_BASH = _find_bash()


def _run(script_body: str, tmp_path: Path) -> subprocess.CompletedProcess:
    nb = _NODE_BOOTSTRAP.as_posix()
    drv = tmp_path / "drv.sh"
    drv.write_text(
        "#!/usr/bin/env bash\n"
        "set -u\n"
        # This script is POSIX-only in production; when the tests run on a
        # Windows host the env carries Windows-style paths, so normalise HOME /
        # HERMES_HOME to the shell's native (MSYS) form before sourcing so
        # realpath comparisons behave exactly as they do on Linux/macOS.
        'if command -v cygpath >/dev/null 2>&1; then\n'
        '  HOME="$(cygpath -u "$HOME")"; HERMES_HOME="$(cygpath -u "$HERMES_HOME")"\n'
        '  [ -n "${HERMES_PYTHON:-}" ] && HERMES_PYTHON="$(cygpath -u "$HERMES_PYTHON")"\n'
        '  export HOME HERMES_HOME HERMES_PYTHON\n'
        'fi\n'
        f'source "{nb}"\n' + script_body,
        encoding="utf-8",
    )
    home = tmp_path / "home"
    env = {
        **os.environ,
        "HOME": str(home),
        "HERMES_HOME": str(home / ".hermes"),
        # The whole-tree verifier (node_tree_marker.py) is invoked via this
        # interpreter — the SAME algorithm as the Python resolver, delegated
        # because Stage-Python precedes Node in install.sh.
        "HERMES_PYTHON": sys.executable,
        # Neutralise any ambient opt-in so the heal path is the secure default.
        "HERMES_NODE_MIN_VERSION": "18",
    }
    env.pop("_HERMES_SC_BOOTSTRAP_OVERRIDE", None)
    return subprocess.run(
        [_BASH, str(drv)], capture_output=True, text=True, env=env, timeout=90
    )


# A managed "node" that records every execution so a test can prove zero-exec.
_FAKE_NODE = (
    'mkdir -p "$HERMES_HOME/node/bin"\n'
    'SENT="$HOME/exec_sentinel"\n'
    'fake="$HERMES_HOME/node/bin/node"\n'
    'printf \'#!/bin/sh\\necho ran >> "%s"\\necho v99.9.9\\n\' "$SENT" > "$fake"\n'
    'chmod +x "$fake"\n'
)


@pytest.mark.skipif(_BASH is None, reason="bash unavailable")
@pytest.mark.live_system_guard_bypass
def test_have_modern_node_rejects_unmarked_and_tampered_managed(tmp_path):
    body = _FAKE_NODE + (
        'export PATH="$HERMES_HOME/node/bin:$PATH"\n'
        # 1) unmarked managed node on PATH -> not modern, ZERO execution
        'rm -f "$SENT"\n'
        'if _nb_have_modern_node; then echo C1_MODERN; else echo C1_NOTMODERN; fi\n'
        '[ -f "$SENT" ] && echo C1_EXECUTED || echo C1_NOEXEC\n'
        # 2) WHOLE-TREE marked -> modern, and NOW it is executed (trusted). The
        #    marker binds node + npm/npx + npm CLI JS via the SAME algorithm as
        #    the Python resolver (node_tree_marker.py), not just the node bytes.
        '_nb_write_node_whole v99.9.9\n'
        'rm -f "$SENT"\n'
        'if _nb_have_modern_node; then echo C2_MODERN; else echo C2_NOTMODERN; fi\n'
        '[ -f "$SENT" ] && echo C2_EXECUTED || echo C2_NOEXEC\n'
        # 3) tamper after marking (bytes drift) -> marker mismatch -> not modern,
        #    ZERO execution
        'printf "#extra\\n" >> "$fake"\n'
        'rm -f "$SENT"\n'
        'if _nb_have_modern_node; then echo C3_MODERN; else echo C3_NOTMODERN; fi\n'
        '[ -f "$SENT" ] && echo C3_EXECUTED || echo C3_NOEXEC\n'
    )
    r = _run(body, tmp_path)
    out = r.stdout
    assert "C1_NOTMODERN" in out, (out, r.stderr)
    assert "C1_NOEXEC" in out, (out, r.stderr)
    assert "C2_MODERN" in out, (out, r.stderr)
    assert "C2_EXECUTED" in out, (out, r.stderr)
    assert "C3_NOTMODERN" in out, (out, r.stderr)
    assert "C3_NOEXEC" in out, (out, r.stderr)


@pytest.mark.skipif(_BASH is None, reason="bash unavailable")
@pytest.mark.live_system_guard_bypass
def test_whole_tree_marker_rejects_npm_cli_tamper_same_size(tmp_path):
    """The whole-tree marker binds the npm CLI JS, so a tampered npm library file
    — node binary untouched, SAME SIZE, mtime restored — fails the gate and the
    managed node is NEVER executed. Proves the content-hash (no size/mtime cache)
    property is enforced through the shell path."""
    body = _FAKE_NODE + (
        'cli="$HERMES_HOME/node/lib/node_modules/npm/lib/cli.js"\n'
        'mkdir -p "$(dirname "$cli")"\n'
        'printf "console.log(1)AAAA\\n" > "$cli"\n'
        'export PATH="$HERMES_HOME/node/bin:$PATH"\n'
        '_nb_write_node_whole v99.9.9\n'
        'rm -f "$SENT"\n'
        'if _nb_have_modern_node; then echo M_MODERN; else echo M_NOTMODERN; fi\n'
        '[ -f "$SENT" ] && echo M_EXECUTED || echo M_NOEXEC\n'
        # same-size content swap, mtime restored from an OUT-OF-TREE reference
        'cp "$cli" "$HOME/cli.ref"\n'
        'printf "console.log(1)BBBB\\n" > "$cli"\n'   # identical length
        'touch -r "$HOME/cli.ref" "$cli" 2>/dev/null || true\n'
        'rm -f "$SENT"\n'
        'if _nb_have_modern_node; then echo T_MODERN; else echo T_NOTMODERN; fi\n'
        '[ -f "$SENT" ] && echo T_EXECUTED || echo T_NOEXEC\n'
    )
    r = _run(body, tmp_path)
    out = r.stdout
    assert "M_MODERN" in out, (out, r.stderr)
    assert "M_EXECUTED" in out, (out, r.stderr)
    assert "T_NOTMODERN" in out, (out, r.stderr)  # npm CLI tamper caught by whole-tree
    assert "T_NOEXEC" in out, (out, r.stderr)      # node never executed after rejection


@pytest.mark.skipif(_BASH is None, reason="bash unavailable")
@pytest.mark.live_system_guard_bypass
def test_whole_tree_fails_closed_without_python(tmp_path):
    """With no usable Python/verifier, the whole-tree check fails closed — a
    managed node is NOT trusted (even if per-binary marked) and NOT executed."""
    body = _FAKE_NODE + (
        'export PATH="$HERMES_HOME/node/bin:$PATH"\n'
        '_nb_write_marker "$fake" v99.9.9\n'   # per-binary marker only
        # Force no python: HERMES_PYTHON points nowhere, and mask python/python3.
        'export HERMES_PYTHON=/nonexistent/python\n'
        'python() { return 127; }; python3() { return 127; }\n'
        'command() { if [ "$1" = -v ] && { [ "$2" = python ] || [ "$2" = python3 ] || [ "$2" = /nonexistent/python ]; }; then return 1; fi; builtin command "$@"; }\n'
        'rm -f "$SENT"\n'
        'if _nb_have_modern_node; then echo P_MODERN; else echo P_NOTMODERN; fi\n'
        '[ -f "$SENT" ] && echo P_EXECUTED || echo P_NOEXEC\n'
    )
    r = _run(body, tmp_path)
    out = r.stdout
    assert "P_NOTMODERN" in out, (out, r.stderr)   # fail closed without python
    assert "P_NOEXEC" in out, (out, r.stderr)


@pytest.mark.skipif(_BASH is None, reason="bash unavailable")
@pytest.mark.live_system_guard_bypass
def test_under_managed_node_root_detects_managed_and_ignores_operator(tmp_path):
    body = _FAKE_NODE + (
        'op="$HOME/opnode"; printf "#!/bin/sh\\necho v20\\n" > "$op"; chmod +x "$op"\n'
        'if _nb_under_managed_node_root "$fake"; then echo FAKE_UNDER; else echo FAKE_OUT; fi\n'
        'if _nb_under_managed_node_root "$op"; then echo OP_UNDER; else echo OP_OUT; fi\n'
    )
    r = _run(body, tmp_path)
    assert "FAKE_UNDER" in r.stdout, (r.stdout, r.stderr)
    assert "OP_OUT" in r.stdout, (r.stdout, r.stderr)


@pytest.mark.skipif(_BASH is None, reason="bash unavailable")
@pytest.mark.live_system_guard_bypass
def test_explicit_managed_block_gate_and_heal_fail_closed(tmp_path):
    body = _FAKE_NODE + (
        # explicit managed block gate: unmarked -> skipped (never entered)
        'if [ -x "$HERMES_HOME/node/bin/node" ] && _nb_marker_ok "$HERMES_HOME/node/bin/node"; '
        'then echo BLOCK_TAKEN; else echo BLOCK_SKIPPED; fi\n'
        '_nb_write_marker "$fake" v99.9.9\n'
        'if [ -x "$HERMES_HOME/node/bin/node" ] && _nb_marker_ok "$HERMES_HOME/node/bin/node"; '
        'then echo BLOCK_TAKEN2; else echo BLOCK_SKIPPED2; fi\n'
        # needs_heal reports true for an unmarked tree WITHOUT executing it;
        # heal then fails closed under the secure default (no override) and
        # never runs the managed node.
        'rm -f "$fake.provenance.json"\n'
        'rm -f "$SENT"\n'
        'if _nb_managed_node_needs_heal; then echo NEEDSHEAL; else echo NOHEAL; fi\n'
        '[ -f "$SENT" ] && echo HEALPROBE_EXECUTED || echo HEALPROBE_NOEXEC\n'
        'rm -f "$SENT"\n'
        'if heal_managed_node >/dev/null 2>&1; then echo HEALED; else echo HEAL_FAILCLOSED; fi\n'
        '[ -f "$SENT" ] && echo HEAL_EXECUTED || echo HEAL_NOEXEC\n'
    )
    r = _run(body, tmp_path)
    out = r.stdout
    assert "BLOCK_SKIPPED" in out and "BLOCK_TAKEN2" in out, (out, r.stderr)
    assert "NEEDSHEAL" in out, (out, r.stderr)
    assert "HEALPROBE_NOEXEC" in out, (out, r.stderr)
    assert "HEAL_FAILCLOSED" in out, (out, r.stderr)
    assert "HEAL_NOEXEC" in out, (out, r.stderr)

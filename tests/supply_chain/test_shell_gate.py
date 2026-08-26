"""Behavioral tests for the shell installer supply-chain gate.

Exercises scripts/lib/supply-chain-gate.sh through a real bash process. The big
installer scripts (setup-hermes.sh, install.sh, node-bootstrap.sh) inline the
same opt-in logic; this proves the shared decision.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_GATE = Path(__file__).resolve().parents[2] / "scripts" / "lib" / "supply-chain-gate.sh"


def _find_bash() -> str | None:
    # On Windows prefer Git Bash (MSYS) over the WSL launcher: WSL filters
    # Windows env vars and remaps paths, which breaks this subprocess harness.
    candidates: list[str] = []
    if sys.platform == "win32":
        candidates += [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        ]
    found = shutil.which("bash")
    if found:
        candidates.append(found)
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return None


_BASH = _find_bash()

pytestmark = pytest.mark.skipif(_BASH is None, reason="bash not available")


def _run(snippet: str, env_extra: dict | None = None) -> int:
    env = {"PATH": os.environ.get("PATH", "")}
    if env_extra:
        env.update(env_extra)
    # Inline the gate script rather than sourcing by path: avoids Windows/WSL
    # path-translation differences for `source` while running the real logic.
    script = _GATE.read_text(encoding="utf-8")
    result = subprocess.run(
        [_BASH, "-c", f"{script}\n{snippet}"],
        capture_output=True,
        env=env,
    )
    return result.returncode


def test_gate_fails_closed_by_default():
    assert _run('sc_gate_install uv "" "install uv"') == 1


def test_gate_allows_existing_operator_executable():
    assert _run('sc_gate_install uv "/usr/bin/uv" "install uv"') == 0


def test_gate_allows_on_bootstrap_opt_in():
    # The internal bridge set by --allow-unverified-bootstrap (not a user env var).
    assert _run('sc_gate_install uv "" "install uv"', {"_HERMES_SC_BOOTSTRAP_OVERRIDE": "1"}) == 0


def test_gate_opt_in_accepts_truthy_bridge_values():
    for value in ("true", "yes", "on", "TRUE", "On"):
        assert _run("sc_opt_in", {"_HERMES_SC_BOOTSTRAP_OVERRIDE": value}) == 0


def test_removed_env_vars_do_not_open_gate():
    # The old user-facing env vars are no longer honored by the shell gate.
    assert _run('sc_gate_install uv "" "install uv"', {"HERMES_ALLOW_UNVERIFIED_BOOTSTRAP": "1"}) == 1
    assert _run('sc_gate_install uv "" "install uv"', {"HERMES_SUPPLY_CHAIN_ENFORCE": "0"}) == 1


def test_opt_in_false_by_default():
    assert _run("sc_opt_in") == 1


# --- Termux dependency gate (WP4 A7) --------------------------------------

def test_termux_deps_gate_fails_closed_by_default():
    # No hashed graph, no opt-in → disabled.
    assert _run('sc_termux_deps_gate ""') == 1


def test_termux_deps_gate_opens_on_bootstrap_opt_in():
    assert _run('sc_termux_deps_gate ""', {"_HERMES_SC_BOOTSTRAP_OVERRIDE": "1"}) == 0


def test_termux_deps_gate_opens_with_committed_hashed_graph(tmp_path):
    graph = tmp_path / "requirements-termux.hashes.txt"
    graph.write_text("hermes-agent==1.0 --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8")
    # A real --require-hashes graph opens the gate even without opt-in.
    assert _run(f'sc_termux_deps_gate "{graph.as_posix()}"') == 0


def test_termux_deps_gate_rejects_versionpin_only_graph(tmp_path):
    # A version-constrained file WITHOUT --hash pins must NOT open the gate.
    graph = tmp_path / "constraints-termux.txt"
    graph.write_text("ipython<10\njedi>=0.18.1,<0.20\n", encoding="utf-8")
    assert _run(f'sc_termux_deps_gate "{graph.as_posix()}"') == 1


def test_termux_gate_blocks_pip_subprocess_by_default(tmp_path):
    """No pip subprocess runs by default: the gate exits before pip is reached."""
    sentinel = tmp_path / "pip_ran"
    # Stub `pip` on PATH; if the gate let control through, this would run and
    # create the sentinel. The guard must exit(1) first, leaving it absent.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    pip_stub = bindir / "pip"
    pip_stub.write_text(f'#!/usr/bin/env bash\ntouch "{sentinel.as_posix()}"\n', encoding="utf-8")
    pip_stub.chmod(0o755)
    snippet = (
        'if sc_termux_deps_gate ""; then pip install -e .; else exit 3; fi'
    )
    rc = _run(snippet, {"PATH": f"{bindir.as_posix()}:" + os.environ.get("PATH", "")})
    assert rc == 3, "gate must fail closed (exit before the install branch)"
    assert not sentinel.exists(), "pip must NOT run under the secure default"


def test_termux_gate_runs_pip_subprocess_on_opt_in(tmp_path):
    """With break-glass opt-in, control reaches the pip subprocess."""
    sentinel = tmp_path / "pip_ran"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    pip_stub = bindir / "pip"
    pip_stub.write_text(f'#!/usr/bin/env bash\ntouch "{sentinel.as_posix()}"\n', encoding="utf-8")
    pip_stub.chmod(0o755)
    snippet = (
        'if sc_termux_deps_gate ""; then pip install -e .; else exit 3; fi'
    )
    rc = _run(
        snippet,
        {
            "_HERMES_SC_BOOTSTRAP_OVERRIDE": "1",
            "PATH": f"{bindir.as_posix()}:" + os.environ.get("PATH", ""),
        },
    )
    assert rc == 0
    assert sentinel.exists(), "pip must run once the operator opts in"


def test_install_sh_termux_block_gates_before_pip():
    """install.sh's Termux branch fails closed before the pip upgrade line."""
    text = (Path(__file__).resolve().parents[2] / "scripts" / "install.sh").read_text(
        encoding="utf-8"
    )
    # The override/hashed-graph guard must appear BEFORE the first Termux
    # `pip install --upgrade pip` in the same install path.
    guard = text.find("Termux dependency install is disabled by default")
    pip_upgrade = text.find('"$PIP_PYTHON" -m pip install --upgrade pip')
    assert guard != -1 and pip_upgrade != -1
    assert guard < pip_upgrade, "the fail-closed guard must precede the pip upgrade"

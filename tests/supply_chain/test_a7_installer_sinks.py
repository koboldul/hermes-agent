"""WP4 A7: installer sink gating — executable branch tests.

These EXTRACT the real shell functions from scripts/install.sh and run them
through a bash process with a stubbed ``uv`` executable, proving that under the
secure default NO install subprocess runs, and that the explicit
``--allow-unverified-bootstrap`` bridge re-enables it. Not source-text
assertions — the actual function body executes against a recording stub.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_INSTALL_SH = _ROOT / "scripts" / "install.sh"


def _find_bash() -> str | None:
    candidates: list[str] = []
    if sys.platform == "win32":
        candidates += [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        ]
    found = shutil.which("bash")
    if found:
        candidates.append(found)
    for c in candidates:
        if c and Path(c).exists():
            return c
    return None


_BASH = _find_bash()
pytestmark = pytest.mark.skipif(_BASH is None, reason="bash not available")


def _extract_function(name: str) -> str:
    """Return the text of a top-level ``name() { ... }`` shell function whose
    closing brace is at column 0 (all install.sh functions are)."""
    text = _INSTALL_SH.read_text(encoding="utf-8")
    m = re.search(rf"(?m)^{re.escape(name)}\(\)\s*\{{", text)
    assert m, f"function {name} not found in install.sh"
    start = m.start()
    close = re.search(r"(?m)^\}", text[start:])
    assert close, f"unterminated function {name}"
    return text[start : start + close.end()]


_STUBS = r"""
log_info(){ :; }; log_warn(){ :; }; log_success(){ :; }; log_error(){ :; }
prompt_yes_no(){ return 1; }
run_playwright_install(){ shift; "$@"; }
restore_dirty_lockfiles(){ :; }
run_with_timeout(){ shift; "$@"; }
install_uv(){ :; }
"""


def _run_function(
    name: str,
    *,
    env_extra: dict,
    install_dir: Path,
    home: Path,
    uv_stub_body: str | None = None,
    cwd: Path | None = None,
    extra_setup: str = "",
) -> subprocess.CompletedProcess:
    body = _extract_function(name)
    sentinel = install_dir / "UV_STUB_CALLED"
    uvstub = install_dir / "uvstub.sh"
    default_stub = f'#!/usr/bin/env bash\necho "$@" >> "{sentinel.as_posix()}"\n'
    uvstub.write_text(
        uv_stub_body.format(sentinel=sentinel.as_posix()) if uv_stub_body else default_stub,
        encoding="utf-8",
    )
    uvstub.chmod(0o755)
    (install_dir / "venv" / "bin").mkdir(parents=True, exist_ok=True)
    script = "\n".join([
        "set +u",
        _STUBS,
        f'INSTALL_DIR="{install_dir.as_posix()}"',
        f'HERMES_HOME="{home.as_posix()}"',
        'USE_VENV=false',
        'SKIP_BROWSER=false',
        'DISTRO="ubuntu"',
        f'UV_CMD="{uvstub.as_posix()}"',
        f'PYTHON_PATH="{uvstub.as_posix()}"',
        'NODE_DEPS_TIMEOUT=60',
        extra_setup,
        body,
        f"{name} || true",
    ])
    env = dict(os.environ)
    env.pop("_HERMES_SC_BOOTSTRAP_OVERRIDE", None)  # controlled per-test below
    env.update(env_extra)
    # Run from a script FILE (not `bash -c`): the extracted function body
    # contains a here-string / heredoc that `bash -c` mis-line-counts.
    harness = install_dir / "harness.sh"
    harness.write_text(script + "\n", encoding="utf-8")
    return subprocess.run(
        [_BASH, str(harness)], capture_output=True, text=True, env=env, timeout=60,
        cwd=str(cwd) if cwd else None,
    )


def _uv_called(install_dir: Path) -> bool:
    return (install_dir / "UV_STUB_CALLED").exists()


# --- install_desktop_voice_deps -------------------------------------------

def test_voice_deps_no_subprocess_by_default(tmp_path):
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    _run_function("install_desktop_voice_deps", env_extra={}, install_dir=install_dir, home=tmp_path / "h")
    assert not _uv_called(install_dir), "voice/wake pre-install must NOT run uv under the secure default"


def test_voice_deps_runs_uv_with_bootstrap_optin(tmp_path):
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    _run_function(
        "install_desktop_voice_deps",
        env_extra={"_HERMES_SC_BOOTSTRAP_OVERRIDE": "1"},
        install_dir=install_dir, home=tmp_path / "h",
    )
    assert _uv_called(install_dir), "with the opt-in the voice/wake pre-install reaches uv"


# --- install_browser_use_cli ----------------------------------------------

def test_browser_use_install_no_subprocess_by_default(tmp_path):
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    home = tmp_path / "h"
    (home / "bin").mkdir(parents=True)
    _run_function("install_browser_use_cli", env_extra={}, install_dir=install_dir, home=home)
    assert not _uv_called(install_dir), "browser-use install must NOT run uv under the secure default"


def test_browser_use_install_runs_uv_with_bootstrap_optin(tmp_path):
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    home = tmp_path / "h"
    (home / "bin").mkdir(parents=True)
    _run_function(
        "install_browser_use_cli",
        env_extra={"_HERMES_SC_BOOTSTRAP_OVERRIDE": "1"},
        install_dir=install_dir, home=home,
    )
    assert _uv_called(install_dir), "with the opt-in the browser-use install reaches uv"


# --- install_deps: uv.lock failure aborts BEFORE the unlocked tier cascade -

# uv stub: the hash-verified `sync` fails; a tier `pip install` would record.
_UV_SYNC_FAILS = (
    "#!/usr/bin/env bash\n"
    "case \"$1\" in\n"
    "  sync) exit 1 ;;\n"
    "  pip)  echo \"$@\" >> \"{sentinel}\"; exit 0 ;;\n"
    "  *) exit 0 ;;\n"
    "esac\n"
)


@pytest.mark.live_system_guard_bypass
def test_install_deps_aborts_before_tier_cascade_by_default(tmp_path):
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "uv.lock").write_text("# lock\n", encoding="utf-8")

    r = _run_function(
        "install_deps",
        env_extra={},
        install_dir=install_dir, home=tmp_path / "h",
        uv_stub_body=_UV_SYNC_FAILS,
        cwd=proj,
        extra_setup='DISTRO="linux"',
    )
    # The hash-verified sync failed; under the secure default the unlocked
    # `uv pip install` tier cascade must NOT run.
    assert not _uv_called(install_dir), "unlocked tier cascade must not run by default"


@pytest.mark.live_system_guard_bypass
def test_install_deps_runs_tier_cascade_with_bootstrap_optin(tmp_path):
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "uv.lock").write_text("# lock\n", encoding="utf-8")

    _run_function(
        "install_deps",
        env_extra={"_HERMES_SC_BOOTSTRAP_OVERRIDE": "1"},
        install_dir=install_dir, home=tmp_path / "h",
        uv_stub_body=_UV_SYNC_FAILS,
        cwd=proj,
        extra_setup='DISTRO="linux"',
    )
    assert _uv_called(install_dir), "with the opt-in the tier cascade runs after a failed lock sync"


@pytest.mark.live_system_guard_bypass
def test_install_deps_aborts_when_uv_lock_missing_by_default(tmp_path):
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    proj = tmp_path / "proj"
    proj.mkdir()  # NO uv.lock

    _run_function(
        "install_deps",
        env_extra={},
        install_dir=install_dir, home=tmp_path / "h",
        uv_stub_body=_UV_SYNC_FAILS,
        cwd=proj,
        extra_setup='DISTRO="linux"',
    )
    assert not _uv_called(install_dir), "missing uv.lock must abort before the unlocked cascade"


# --- setup-hermes.sh Termux exits BEFORE any pip upgrade/install -----------

def test_setup_hermes_termux_no_subprocess_by_default(tmp_path):
    """Run the real setup-hermes.sh Termux gate + first pip sink with a
    recording python stub; under the secure default it must exit before ANY
    pip upgrade/install."""
    setup = (_ROOT / "setup-hermes.sh").read_text(encoding="utf-8")
    # The INSTALL-path Termux block (not the earlier detection ones) is the one
    # that exports ANDROID_API_LEVEL. Extract from there through the first pip
    # upgrade line and close the `if is_termux`.
    start = setup.index("if is_termux; then\n    export ANDROID_API_LEVEL")
    pip_marker = setup.index('"$SETUP_PYTHON" -m pip install --upgrade pip', start)
    block = setup[start : setup.index("\n", pip_marker)] + "\nfi\n"

    sentinel = tmp_path / "PY_CALLED"
    pystub = tmp_path / "pystub.sh"
    pystub.write_text(f'#!/usr/bin/env bash\necho "$@" >> "{sentinel.as_posix()}"\n', encoding="utf-8")
    pystub.chmod(0o755)

    harness = "\n".join([
        "set +u",
        'RED=""; CYAN=""; NC=""; GREEN=""; YELLOW=""',
        'is_termux(){ return 0; }',
        'getprop(){ echo 30; }',
        f'SETUP_PYTHON="{pystub.as_posix()}"',
        block,
    ])
    r = subprocess.run(
        [_BASH, "-c", harness], capture_output=True, text=True,
        env={"PATH": os.environ.get("PATH", "")}, timeout=30, cwd=str(tmp_path),
    )
    assert not sentinel.exists(), "Termux path must exit BEFORE any pip upgrade/install by default"
    assert r.returncode != 0, "secure default fails closed (exit non-zero)"


def test_setup_hermes_termux_runs_with_bootstrap_optin(tmp_path):
    setup = (_ROOT / "setup-hermes.sh").read_text(encoding="utf-8")
    start = setup.index("if is_termux; then\n    export ANDROID_API_LEVEL")
    pip_marker = setup.index('"$SETUP_PYTHON" -m pip install --upgrade pip', start)
    block = setup[start : setup.index("\n", pip_marker)] + "\nfi\n"

    sentinel = tmp_path / "PY_CALLED"
    pystub = tmp_path / "pystub.sh"
    pystub.write_text(f'#!/usr/bin/env bash\necho "$@" >> "{sentinel.as_posix()}"\nexit 0\n', encoding="utf-8")
    pystub.chmod(0o755)

    harness = "\n".join([
        "set +u",
        'RED=""; CYAN=""; NC=""; GREEN=""; YELLOW=""',
        'is_termux(){ return 0; }',
        'getprop(){ echo 30; }',
        f'SETUP_PYTHON="{pystub.as_posix()}"',
        block,
    ])
    subprocess.run(
        [_BASH, "-c", harness], capture_output=True, text=True,
        env={"PATH": os.environ.get("PATH", ""), "_HERMES_SC_BOOTSTRAP_OVERRIDE": "1"},
        timeout=30, cwd=str(tmp_path),
    )
    assert sentinel.exists(), "with the opt-in the Termux path runs the pip upgrade"

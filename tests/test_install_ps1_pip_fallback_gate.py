"""Behavioral tests for install.ps1's unverified-pip-fallback gate (WP4 A7).

These EXECUTE the real PowerShell functions (they are not source-text
assertions). install.ps1 is dot-sourced with the internal
``_HERMES_PS_DOTSOURCE_ONLY`` bridge so every function is defined without
running the installer, then the pip-fallback gate is driven against stubs.

The secure default must:
  * report the fallback as NOT allowed,
  * make ``Assert-UnverifiedPipFallbackAllowed`` throw (which, in the real
    dependency install, propagates to the venv-transaction rollback), and
  * make ``Install-DesktopVoiceDeps`` skip the unverified pre-install WITHOUT
    invoking uv — proving no install subprocess runs by default.

Only the explicit ``-AllowUnverifiedBootstrap`` bridge
(``_HERMES_SC_BOOTSTRAP_OVERRIDE=1``) opens the path.

Windows PowerShell only; skipped elsewhere (the shell installer has its own
gate covered by tests/supply_chain/test_shell_gate.py).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_INSTALL_PS1 = Path(__file__).resolve().parents[1] / "scripts" / "install.ps1"


def _find_powershell() -> str | None:
    for name in ("pwsh", "powershell"):
        found = shutil.which(name)
        if found:
            return found
    default = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    return default if Path(default).exists() else None


_PS = _find_powershell()

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or _PS is None,
    reason="requires Windows PowerShell to execute install.ps1 functions",
)


def _run_ps(body: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["_HERMES_PS_DOTSOURCE_ONLY"] = "1"  # define funcs, don't run the installer
    if env_extra:
        env.update(env_extra)
    script = f". '{_INSTALL_PS1}'\n{body}"
    return subprocess.run(
        [_PS, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
    )


def test_fallback_not_allowed_by_default():
    r = _run_ps("if (Test-UnverifiedPipFallbackAllowed) { exit 10 } else { exit 11 }")
    assert r.returncode == 11, (r.returncode, r.stdout, r.stderr)


def test_fallback_allowed_with_bootstrap_bridge():
    r = _run_ps(
        "if (Test-UnverifiedPipFallbackAllowed) { exit 10 } else { exit 11 }",
        {"_HERMES_SC_BOOTSTRAP_OVERRIDE": "1"},
    )
    assert r.returncode == 10, (r.returncode, r.stdout, r.stderr)


def test_assert_throws_by_default():
    r = _run_ps(
        "try { Assert-UnverifiedPipFallbackAllowed -Context 't'; exit 20 } catch { exit 21 }"
    )
    assert r.returncode == 21, (r.returncode, r.stdout, r.stderr)


def test_assert_passes_with_bootstrap_bridge():
    r = _run_ps(
        "try { Assert-UnverifiedPipFallbackAllowed -Context 't'; exit 20 } catch { exit 21 }",
        {"_HERMES_SC_BOOTSTRAP_OVERRIDE": "1"},
    )
    assert r.returncode == 20, (r.returncode, r.stdout, r.stderr)


def _fake_uv(tmp_path: Path) -> tuple[Path, Path]:
    """A real fake ``uv.ps1`` OUTSIDE any managed root, plus its call-log path.

    A ``.ps1`` (not a ``.cmd``) so ``& $script:UvCmd ...`` runs it IN-PROCESS in
    PowerShell rather than spawning cmd.exe — the hermetic test env drops the
    env vars cmd.exe needs, so a ``.cmd`` child dies. Test-UvCmdTrusted accepts a
    non-managed operator path, so Resolve-UvCmd's per-call revalidation keeps it
    (a scriptblock stub would be dropped — in production ``$script:UvCmd`` is
    always a string path or "uv", never a scriptblock). Each invocation appends a
    line to the sentinel, so the test can count real ``& $script:UvCmd`` runs.
    """
    uv = tmp_path / "uv.ps1"
    sentinel = tmp_path / "uv_calls.txt"
    uv.write_text(
        f"Add-Content -LiteralPath '{sentinel}' -Value 'call'\r\n", encoding="ascii"
    )
    return uv, sentinel


def _uv_call_count(sentinel: Path) -> int:
    if not sentinel.exists():
        return 0
    return len([ln for ln in sentinel.read_text().splitlines() if ln.strip()])


def _desktop_voice_body(install_dir: Path, uv: Path) -> str:
    # Stub uv as a REAL executable path (see _fake_uv). If the gate lets control
    # through, `& $UvCmd pip install ...` runs it and appends to the sentinel.
    return (
        f"$script:UvCmd = '{uv}'\n"
        f"$InstallDir = '{install_dir}'\n"
        "Install-DesktopVoiceDeps *> $null\n"
    )


def test_desktop_voice_deps_skips_uv_by_default(tmp_path):
    install_dir = tmp_path / "install"
    (install_dir / "venv").mkdir(parents=True)
    uv, sentinel = _fake_uv(tmp_path)
    r = _run_ps(_desktop_voice_body(install_dir, uv))
    assert _uv_call_count(sentinel) == 0, (
        "voice/wake pre-install must NOT invoke uv under the secure default",
        r.returncode,
        r.stdout,
        r.stderr,
    )


def test_desktop_voice_deps_runs_uv_with_bootstrap_bridge(tmp_path):
    install_dir = tmp_path / "install"
    (install_dir / "venv").mkdir(parents=True)
    uv, sentinel = _fake_uv(tmp_path)
    r = _run_ps(
        _desktop_voice_body(install_dir, uv),
        {"_HERMES_SC_BOOTSTRAP_OVERRIDE": "1"},
    )
    assert _uv_call_count(sentinel) >= 1, (
        "with -AllowUnverifiedBootstrap the voice/wake pre-install must reach uv",
        r.returncode,
        r.stdout,
        r.stderr,
    )


def _install_browser_use_body(home: Path, install_dir: Path, uv: Path) -> str:
    return (
        f"$script:UvCmd = '{uv}'\n"
        f"$HermesHome = '{home}'\n"
        f"$InstallDir = '{install_dir}'\n"
        "Install-BrowserUseCli *> $null\n"
    )


def test_install_browser_use_no_uv_by_default(tmp_path):
    home = tmp_path / "h"
    (home / "bin").mkdir(parents=True)
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    uv, sentinel = _fake_uv(tmp_path)
    r = _run_ps(_install_browser_use_body(home, install_dir, uv))
    assert _uv_call_count(sentinel) == 0, (
        "Install-BrowserUseCli must make ZERO uv calls under the secure default",
        r.returncode, r.stdout, r.stderr,
    )


def test_install_browser_use_runs_uv_with_bootstrap_bridge(tmp_path):
    home = tmp_path / "h"
    (home / "bin").mkdir(parents=True)
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    uv, sentinel = _fake_uv(tmp_path)
    r = _run_ps(
        _install_browser_use_body(home, install_dir, uv),
        {"_HERMES_SC_BOOTSTRAP_OVERRIDE": "1"},
    )
    assert _uv_call_count(sentinel) >= 1, (
        "with -AllowUnverifiedBootstrap Install-BrowserUseCli must reach uv",
        r.returncode, r.stdout, r.stderr,
    )


def test_install_browser_use_unmarked_managed_does_not_shortcircuit(tmp_path):
    """An existing managed browser-use.exe with no verifiable marker (no venv
    python to check it) must NOT be trusted as 'already installed'; the secure
    default still makes zero uv calls (falls through to the gate)."""
    home = tmp_path / "h"
    bindir = home / "bin"
    bindir.mkdir(parents=True)
    (bindir / "browser-use.exe").write_text("unmarked", encoding="utf-8")
    install_dir = tmp_path / "install"
    install_dir.mkdir()  # no venv/Scripts/python.exe → marker unverifiable
    uv, sentinel = _fake_uv(tmp_path)
    r = _run_ps(_install_browser_use_body(home, install_dir, uv))
    assert _uv_call_count(sentinel) == 0, (
        "an unverifiable managed browser-use must not short-circuit or call uv",
        r.returncode, r.stdout, r.stderr,
    )

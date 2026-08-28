"""Behavioral tests for install.ps1's repository ZIP fallback gate."""

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

pytestmark = pytest.mark.windows_only


def _run_ps(body: str, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    assert sys.platform == "win32"
    assert _PS is not None
    env = dict(os.environ)
    env["_HERMES_PS_DOTSOURCE_ONLY"] = "1"
    env.pop("_HERMES_SC_BOOTSTRAP_OVERRIDE", None)
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


def _repository_body(install_dir: Path, download_sentinel: Path) -> str:
    return "\n".join(
        [
            f"$InstallDir = '{install_dir}'",
            "function global:git { $global:LASTEXITCODE = 1 }",
            (
                "function global:Invoke-WebRequest { "
                f"Set-Content -LiteralPath '{download_sentinel}' -Value 'called'; "
                "throw 'test download stop' }"
            ),
            "Install-Repository",
        ]
    )


def test_repository_zip_fallback_does_not_download_by_default(tmp_path):
    install_dir = tmp_path / "install"
    download_sentinel = tmp_path / "download-called"

    result = _run_ps(_repository_body(install_dir, download_sentinel))

    assert result.returncode != 0
    assert not download_sentinel.exists()
    assert "Repository ZIP fallback is disabled by default" in result.stderr


def test_repository_zip_fallback_requires_explicit_override(tmp_path):
    install_dir = tmp_path / "install"
    download_sentinel = tmp_path / "download-called"

    result = _run_ps(
        _repository_body(install_dir, download_sentinel),
        {"_HERMES_SC_BOOTSTRAP_OVERRIDE": "1"},
    )

    assert result.returncode != 0
    assert download_sentinel.exists()
    assert "Repository ZIP fallback is disabled by default" not in result.stderr

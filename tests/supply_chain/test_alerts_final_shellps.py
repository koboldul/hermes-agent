"""Alert 1c: the pre-config shell / PowerShell fast paths verify a managed
uv/node's provenance marker+digest BEFORE executing it, so an unmarked/tampered
managed binary is never run (not even for a --version probe).

These EXECUTE the real installer helper functions (extracted from install.sh /
dot-sourced from install.ps1) — they are behavioral, not source-text assertions.
A fake managed binary writes a sentinel IFF it is executed; the gate must keep
that sentinel absent while the marker is missing, and allow execution once a
matching marker exists.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_INSTALL_SH = _REPO / "scripts" / "install.sh"
_INSTALL_PS1 = _REPO / "scripts" / "install.ps1"


def _find_bash() -> str | None:
    cands = []
    if sys.platform == "win32":
        cands += [r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"]
    w = shutil.which("bash")
    if w:
        cands.append(w)
    for c in cands:
        if c and Path(c).exists():
            return c
    return None


_BASH = _find_bash()


@pytest.mark.skipif(_BASH is None, reason="bash unavailable")
@pytest.mark.live_system_guard_bypass
def test_shell_fast_path_does_not_execute_unmarked_managed_binary(tmp_path):
    sentinel = tmp_path / "SENTINEL"
    script = tmp_path / "drive.sh"
    script.write_text(
        f'''#!/usr/bin/env bash
set -u
INSTALL_SH="{_INSTALL_SH.as_posix()}"
SENTINEL="{sentinel.as_posix()}"
work="{tmp_path.as_posix()}/w"; mkdir -p "$work"
helpers="$work/helpers.sh"
start=$(grep -n '^_sc_sha256() {{' "$INSTALL_SH" | head -1 | cut -d: -f1)
tail -n +"$start" "$INSTALL_SH" | awk '{{print}} /_sc_write_managed_marker\\(\\) {{/{{inw=1}} inw && /^}}$/{{exit}}' > "$helpers"
. "$helpers"

uv="$work/uv"
cat > "$uv" <<EOF
#!/bin/sh
echo RAN > "$SENTINEL"
echo "uv 1.0.0"
EOF
chmod +x "$uv"

rm -f "$SENTINEL"
# Fast-path pattern used by install.sh: verify BEFORE executing.
if [ -x "$uv" ] && _sc_verify_managed_marker "$uv"; then "$uv" --version >/dev/null 2>&1; fi
if [ -f "$SENTINEL" ]; then echo "FAIL_UNMARKED_EXECUTED"; exit 1; fi

# Now mark it: the same fast path SHOULD execute (marker matches digest).
_sc_write_managed_marker "$uv" uv 1.0.0 test || {{ echo FAIL_WRITE; exit 1; }}
if [ -x "$uv" ] && _sc_verify_managed_marker "$uv"; then "$uv" --version >/dev/null 2>&1; fi
if [ ! -f "$SENTINEL" ]; then echo "FAIL_MARKED_NOT_EXECUTED"; exit 1; fi

# Tamper after marking: gate must refuse again (no execution).
rm -f "$SENTINEL"
cat > "$uv" <<EOF
#!/bin/sh
echo RAN > "$SENTINEL"
echo evil
EOF
chmod +x "$uv"
if [ -x "$uv" ] && _sc_verify_managed_marker "$uv"; then "$uv" --version >/dev/null 2>&1; fi
if [ -f "$SENTINEL" ]; then echo "FAIL_TAMPERED_EXECUTED"; exit 1; fi
echo "OK"
''',
        encoding="utf-8",
    )
    r = subprocess.run([_BASH, str(script)], capture_output=True, text=True, timeout=120)
    assert "OK" in r.stdout and r.returncode == 0, (r.returncode, r.stdout, r.stderr)


def _find_powershell() -> str | None:
    for name in ("pwsh", "powershell"):
        f = shutil.which(name)
        if f:
            return f
    default = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    return default if Path(default).exists() else None


_PS = _find_powershell()


@pytest.mark.skipif(
    sys.platform != "win32" or _PS is None,
    reason="requires Windows PowerShell to execute install.ps1 functions",
)
@pytest.mark.live_system_guard_bypass
def test_ps_fast_path_does_not_execute_unmarked_managed_binary(tmp_path):
    sentinel = tmp_path / "SENTINEL"
    uv = tmp_path / "uv.cmd"  # a .cmd writes the sentinel IFF executed
    uv.write_text(f"@echo RAN> \"{sentinel}\"\r\n@echo uv 1.0.0\r\n", encoding="ascii")
    body = f'''
$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false
$uv = "{uv}"
$sentinel = "{sentinel}"
Remove-Item -LiteralPath $sentinel -Force -ErrorAction SilentlyContinue
# Unmarked: the gate is false AND the guarded fast path must not execute uv.
if (Test-ManagedMarker $uv) {{ Write-Output "FAIL_UNMARKED_TRUE"; exit 1 }}
if ((Test-Path $uv) -and (Test-ManagedMarker $uv)) {{ & $uv | Out-Null }}
if (Test-Path $sentinel) {{ Write-Output "FAIL_UNMARKED_EXECUTED"; exit 1 }}
# Marked: the gate is true (execution allowed).
Write-ManagedMarker -Binary $uv -Component uv -Version "1.0.0" -Provenance test
if (-not (Test-ManagedMarker $uv)) {{ Write-Output "FAIL_MARKED_FALSE"; exit 1 }}
# Tamper: the gate is false again, and the guarded fast path must not execute.
Set-Content -LiteralPath $uv -Value "@echo RAN> `"$sentinel`"" -Encoding ascii
Remove-Item -LiteralPath $sentinel -Force -ErrorAction SilentlyContinue
if (Test-ManagedMarker $uv) {{ Write-Output "FAIL_TAMPERED_TRUE"; exit 1 }}
if ((Test-Path $uv) -and (Test-ManagedMarker $uv)) {{ & $uv | Out-Null }}
if (Test-Path $sentinel) {{ Write-Output "FAIL_TAMPERED_EXECUTED"; exit 1 }}
Write-Output "OK"
'''
    env = dict(os.environ)
    env["_HERMES_PS_DOTSOURCE_ONLY"] = "1"
    script = f". '{_INSTALL_PS1}'\n{body}"
    r = subprocess.run(
        [_PS, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, env=env, timeout=180,
    )
    assert "OK" in r.stdout and r.returncode == 0, (r.returncode, r.stdout, r.stderr)


@pytest.mark.skipif(
    sys.platform != "win32" or _PS is None,
    reason="requires Windows PowerShell to execute install.ps1 functions",
)
@pytest.mark.live_system_guard_bypass
def test_ps_resolve_uvcmd_revalidates_and_rejects_unmarked_managed(tmp_path):
    """A1: Resolve-UvCmd re-verifies the cached $script:UvCmd on EVERY call and
    never leaves an unmarked/tampered managed uv selected. Test-UvCmdTrusted is
    the predicate; a managed-rooted uv without a valid marker is not trusted."""
    hermes = tmp_path / "hermes"
    (hermes / "bin").mkdir(parents=True)
    managed = hermes / "bin" / "uv.exe"
    managed.write_bytes(b"fake-managed-uv-bytes\r\n")  # never executed
    operator = tmp_path / "opuv.exe"
    operator.write_bytes(b"operator-uv-bytes\r\n")
    body = f'''
$ErrorActionPreference = "Continue"
$HermesHome = "{hermes}"
$script:HermesHome = "{hermes}"
$managed = "{managed}"
$op = "{operator}"

# Unmarked managed uv -> NOT trusted.
if (Test-UvCmdTrusted $managed) {{ Write-Output "FAIL_UNMARKED_TRUSTED"; exit 1 }}
# A cached unmarked managed uv must be DROPPED by Resolve-UvCmd, never kept.
$script:UvCmd = $managed
try {{ Resolve-UvCmd }} catch {{ }}
if ($script:UvCmd -eq $managed) {{ Write-Output "FAIL_KEPT_UNMARKED_MANAGED"; exit 1 }}

# Mark it -> trusted, and Resolve-UvCmd now keeps the cached value.
Write-ManagedMarker -Binary $managed -Component uv -Version "1.0.0" -Provenance test
if (-not (Test-UvCmdTrusted $managed)) {{ Write-Output "FAIL_MARKED_NOT_TRUSTED"; exit 1 }}
$script:UvCmd = $managed
Resolve-UvCmd
if ($script:UvCmd -ne $managed) {{ Write-Output "FAIL_MARKED_DROPPED"; exit 1 }}

# Tamper after marking -> revalidation drops it again.
Set-Content -LiteralPath $managed -Value "tampered-bytes" -Encoding ascii
$script:UvCmd = $managed
try {{ Resolve-UvCmd }} catch {{ }}
if ($script:UvCmd -eq $managed) {{ Write-Output "FAIL_KEPT_TAMPERED"; exit 1 }}

# An operator uv OUTSIDE any managed root is trusted as-is.
if (-not (Test-UvCmdTrusted $op)) {{ Write-Output "FAIL_OPERATOR_NOT_TRUSTED"; exit 1 }}

Write-Output "OK"
'''
    env = dict(os.environ)
    env["_HERMES_PS_DOTSOURCE_ONLY"] = "1"
    script = f". '{_INSTALL_PS1}'\n{body}"
    r = subprocess.run(
        [_PS, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, env=env, timeout=180,
    )
    assert "OK" in r.stdout and r.returncode == 0, (r.returncode, r.stdout, r.stderr)

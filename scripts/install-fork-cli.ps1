# CLI-only installer for the koboldul/hermes-agent fork.
#
# Copies the exact tracked Git commit from this checkout, creates a locked
# Python environment with uv, and installs a user-level hermes launcher.
# It does not install Desktop, Node dependencies, browser payloads, services,
# plugins, skills, or optional dependency groups.

[CmdletBinding()]
param(
    [string]$SourceDir = "",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "hermes-fork\hermes-agent"),
    [string]$HermesHome = (Join-Path $env:LOCALAPPDATA "hermes-fork"),
    [string]$PythonVersion = "3.12",
    [switch]$NoPath,
    [switch]$NoUserEnvironment,
    [switch]$PreferConfiguredPip,
    [switch]$Plan
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $SourceDir) {
    $SourceDir = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory=$true)] [string]$Command,
        [Parameter(Mandatory=$true)] [string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE"
    }
}

function Move-DirectoryWithRetry {
    param(
        [Parameter(Mandatory=$true)] [string]$Source,
        [Parameter(Mandatory=$true)] [string]$Destination
    )

    $lastError = $null
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            [IO.Directory]::Move($Source, $Destination)
            return
        } catch {
            $lastError = $_
            if ($attempt -lt 30) {
                Start-Sleep -Milliseconds 500
            }
        }
    }
    throw $lastError
}

function Remove-DirectoryWithRetry {
    param([Parameter(Mandatory=$true)] [string]$Path)

    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            return $true
        } catch {
            if ($attempt -lt 30) {
                Start-Sleep -Milliseconds 500
            }
        }
    }
    return $false
}

$source = (Resolve-Path -LiteralPath $SourceDir).Path
$git = (Get-Command git -ErrorAction Stop).Source
$tar = (Get-Command tar -ErrorAction Stop).Source
$uv = (Get-Command uv -ErrorAction Stop).Source
$origin = (& $git -C $source remote get-url origin).Trim()
if ($LASTEXITCODE -ne 0 -or $origin -notmatch "github\.com[:/]koboldul/hermes-agent(?:\.git)?$") {
    throw "Source checkout origin is not koboldul/hermes-agent: $origin"
}

$commit = (& $git -C $source rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch "^[0-9a-f]{40}$") {
    throw "Could not resolve an exact 40-character source commit."
}

$install = [IO.Path]::GetFullPath($InstallDir)
$hermesHomePath = [IO.Path]::GetFullPath($HermesHome)
$bin = Join-Path $hermesHomePath "bin"
$venv = Join-Path $install "venv"
$venvPython = Join-Path $venv "Scripts\python.exe"
$launcherScript = Join-Path $bin "hermes.ps1"
$launcher = Join-Path $bin "hermes.cmd"

if ($Plan) {
    [pscustomobject]@{
        repository = "koboldul/hermes-agent"
        commit = $commit
        source = $source
        install_dir = $install
        hermes_home = $hermesHomePath
        uv = $uv
        tar = $tar
        python = $PythonVersion
        launcher = $launcher
        add_to_path = -not ($NoPath -or $NoUserEnvironment)
        set_user_hermes_home = -not $NoUserEnvironment
        dependency_route = if ($PreferConfiguredPip -or $env:PIP_INDEX_URL -or $env:PIP_EXTRA_INDEX_URL) {
            "configured pip channel, constrained by uv.lock hashes"
        } else {
            "artifact URLs from uv.lock"
        }
    } | ConvertTo-Json
    exit 0
}

$parent = Split-Path -Parent $install
New-Item -ItemType Directory -Force -Path $parent | Out-Null
New-Item -ItemType Directory -Force -Path $hermesHomePath | Out-Null

$nonce = [Guid]::NewGuid().ToString("N")
$stage = Join-Path $parent ".hermes-agent.stage-$nonce"
$backup = Join-Path $parent ".hermes-agent.backup-$nonce"
$archive = Join-Path $parent ".hermes-agent-$nonce.tar"
$requirements = Join-Path $parent ".hermes-agent-$nonce-requirements.txt"
$wheelhouse = Join-Path $parent ".hermes-agent-$nonce-wheels"
$hadExisting = Test-Path -LiteralPath $install
$installedNewTree = $false

try {
    Invoke-NativeChecked -Command $git -Arguments @(
        "-C", $source,
        "archive",
        "--format=tar",
        "--output=$archive",
        $commit
    )

    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    Invoke-NativeChecked -Command $tar -Arguments @(
        "-xf", $archive,
        "-C", $stage
    )

    foreach ($required in @("pyproject.toml", "uv.lock", "hermes_cli\main.py")) {
        if (-not (Test-Path -LiteralPath (Join-Path $stage $required) -PathType Leaf)) {
            throw "Copied source is incomplete: missing $required"
        }
    }

    if ($hadExisting) {
        Move-DirectoryWithRetry -Source $install -Destination $backup
    }
    Move-DirectoryWithRetry -Source $stage -Destination $install
    $installedNewTree = $true

    $previousProjectEnvironment = $env:UV_PROJECT_ENVIRONMENT
    $previousPythonDownloads = $env:UV_PYTHON_DOWNLOADS
    $previousNativeTls = $env:UV_NATIVE_TLS
    $previousConcurrentDownloads = $env:UV_CONCURRENT_DOWNLOADS
    $previousHttpRetries = $env:UV_HTTP_RETRIES
    $previousHermesHome = $env:HERMES_HOME
    try {
        $env:UV_PROJECT_ENVIRONMENT = $venv
        $env:UV_PYTHON_DOWNLOADS = "never"
        $env:UV_NATIVE_TLS = "true"
        $env:UV_CONCURRENT_DOWNLOADS = "1"
        $env:UV_HTTP_RETRIES = "3"
        $env:HERMES_HOME = $hermesHomePath

        Invoke-NativeChecked -Command $uv -Arguments @(
            "venv",
            $venv,
            "--python", $PythonVersion
        )

        $syncArguments = @(
            "sync",
            "--project", $install,
            "--frozen",
            "--no-dev",
            "--python", $PythonVersion
        )
        $synced = $false
        $directAttempts = if ($PreferConfiguredPip -or $env:PIP_INDEX_URL -or $env:PIP_EXTRA_INDEX_URL) { 0 } else { 2 }
        for ($attempt = 1; $attempt -le $directAttempts; $attempt++) {
            & $uv @syncArguments
            if ($LASTEXITCODE -eq 0) {
                $synced = $true
                break
            }
            if ($attempt -lt 2) {
                Write-Warning "Direct uv download failed; retrying frozen graph."
                Start-Sleep -Seconds (2 * $attempt)
            }
        }

        if (-not $synced) {
            Write-Warning "Direct artifact download failed; trying a hash-checked wheelhouse through the configured pip channel."
            Invoke-NativeChecked -Command $uv -Arguments @(
                "export",
                "--project", $install,
                "--frozen",
                "--no-dev",
                "--no-emit-project",
                "--no-emit-workspace",
                "--format", "requirements.txt",
                "--output-file", $requirements
            )

            $pythonForDownload = (& $uv python find --no-python-downloads $PythonVersion).Trim()
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pythonForDownload -PathType Leaf)) {
                throw "Could not resolve an existing Python $PythonVersion interpreter for wheel download."
            }

            New-Item -ItemType Directory -Force -Path $wheelhouse | Out-Null
            Invoke-NativeChecked -Command $pythonForDownload -Arguments @(
                "-m", "pip",
                "download",
                "--disable-pip-version-check",
                "--require-hashes",
                "--only-binary=:all:",
                "--dest", $wheelhouse,
                "--requirement", $requirements
            )

            if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
                throw "uv did not create the expected virtual-environment Python: $venvPython"
            }

            Invoke-NativeChecked -Command $venvPython -Arguments @(
                "-m", "ensurepip", "--upgrade"
            )
            Invoke-NativeChecked -Command $venvPython -Arguments @(
                "-m", "pip", "install",
                "--disable-pip-version-check",
                "--no-index",
                "--find-links", $wheelhouse,
                "--require-hashes",
                "--requirement", $requirements
            )
        }

        if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
            throw "Dependency installation completed without creating $venvPython"
        }

        $sitePackages = (& $venvPython -c "import site; print(site.getsitepackages()[0])").Trim()
        if ($LASTEXITCODE -ne 0 -or -not $sitePackages) {
            throw "Could not resolve the virtual environment's site-packages directory."
        }
        Set-Content -LiteralPath (Join-Path $sitePackages "hermes-fork-source.pth") -Value $install -Encoding UTF8

        & $venvPython -P -m hermes_cli.main --help *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Installed Hermes CLI failed its launch check."
        }
    } finally {
        $env:UV_PROJECT_ENVIRONMENT = $previousProjectEnvironment
        $env:UV_PYTHON_DOWNLOADS = $previousPythonDownloads
        $env:UV_NATIVE_TLS = $previousNativeTls
        $env:UV_CONCURRENT_DOWNLOADS = $previousConcurrentDownloads
        $env:UV_HTTP_RETRIES = $previousHttpRetries
        $env:HERMES_HOME = $previousHermesHome
    }

    $sourceRecord = [ordered]@{
        repository = "https://github.com/koboldul/hermes-agent"
        commit = $commit
        installed_at = [DateTime]::UtcNow.ToString("o")
        dependency_source = "uv.lock"
        optional_groups = @()
    }
    $sourceRecord | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $install "INSTALL-SOURCE.json") -Encoding UTF8

    New-Item -ItemType Directory -Force -Path $bin | Out-Null
    @"
`$env:HERMES_HOME = '$($hermesHomePath.Replace("'", "''"))'
& '$($venvPython.Replace("'", "''"))' -P -m hermes_cli.main @args
exit `$LASTEXITCODE
"@ | Set-Content -LiteralPath $launcherScript -Encoding UTF8
    @"
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0hermes.ps1" %*
"@ | Set-Content -LiteralPath $launcher -Encoding Ascii

    if (-not ($NoPath -or $NoUserEnvironment)) {
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $pathEntries = @($userPath -split ";" | Where-Object { $_ })
        if (-not ($pathEntries | Where-Object { $_.TrimEnd("\") -ieq $bin.TrimEnd("\") })) {
            $updatedPath = if ($userPath) { "$bin;$userPath" } else { $bin }
            [Environment]::SetEnvironmentVariable("Path", $updatedPath, "User")
        }
    }

    if (-not $NoUserEnvironment) {
        [Environment]::SetEnvironmentVariable("HERMES_HOME", $hermesHomePath, "User")
        $env:HERMES_HOME = $hermesHomePath
        if (-not (($env:Path -split ";") | Where-Object { $_.TrimEnd("\") -ieq $bin.TrimEnd("\") })) {
            $env:Path = "$bin;$env:Path"
        }
    }

    if ($hadExisting -and (Test-Path -LiteralPath $backup)) {
        if (-not (Remove-DirectoryWithRetry -Path $backup)) {
            Write-Warning "Install succeeded, but Windows still holds the old backup: $backup"
        }
    }

    Write-Host "Hermes fork CLI installed." -ForegroundColor Green
    Write-Host "  Commit: $commit"
    Write-Host "  App:    $install"
    Write-Host "  Home:   $hermesHomePath"
    Write-Host "  CLI:    $launcher"
    if (-not ($NoPath -or $NoUserEnvironment)) {
        Write-Host "Open a new terminal, then run: hermes setup"
    }
} catch {
    $installFailure = $_
    if ($installedNewTree -and (Test-Path -LiteralPath $install)) {
        if (-not (Remove-DirectoryWithRetry -Path $install)) {
            $recovery = if ($hadExisting -and (Test-Path -LiteralPath $backup)) {
                "The previous install is preserved at $backup."
            } else {
                "No previous install existed."
            }
            throw "Install failed and the replacement at $install could not be removed. $recovery Original error: $($installFailure.Exception.Message)"
        }
    }
    if ($hadExisting -and (Test-Path -LiteralPath $backup)) {
        try {
            Move-DirectoryWithRetry -Source $backup -Destination $install
        } catch {
            throw "Install failed; the previous install is preserved at $backup but automatic restore to $install failed. Original error: $($installFailure.Exception.Message)"
        }
    }
    throw $installFailure
} finally {
    if (Test-Path -LiteralPath $archive) {
        Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $requirements) {
        Remove-Item -LiteralPath $requirements -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $wheelhouse) {
        Remove-Item -LiteralPath $wheelhouse -Recurse -Force -ErrorAction SilentlyContinue
    }
}

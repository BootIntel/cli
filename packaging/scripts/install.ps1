# bootintel-cli Windows installer.
#
# Usage:
#   iwr -useb https://raw.githubusercontent.com/bootintel/cli/main/packaging/scripts/install.ps1 | iex
#
# For supply-chain safety, pin to a specific release tag or commit:
#   iwr -useb https://raw.githubusercontent.com/bootintel/cli/cli-v0.3.0/packaging/scripts/install.ps1 | iex
#
# Env overrides:
#   $env:BOOTINTEL_VERSION      pin a specific version (default: latest)
#   $env:BOOTINTEL_INSTALL_DIR  override install location
#                                 (default: $env:USERPROFILE\.local\bin)
#   $env:BOOTINTEL_TARBALL      install from a local .zip (skips all network).
#                                 See "offline install" below.
#
# Flags:
#   -Force       overwrite an existing install without asking (equiv to
#                install.sh's BOOTINTEL_FORCE=1)
#   -WhatIf      dry-run; prints what would happen without touching disk
#
# What it does:
#   1. Detects arch ($env:PROCESSOR_ARCHITECTURE == AMD64 required today;
#      ARM64 errors out with a `cargo install` fallback hint).
#   2. Resolves the latest release from the GitHub API (or the pinned
#      version if BOOTINTEL_VERSION is set).
#   3. Downloads the .zip + SHA256SUMS to a temp dir.
#   4. Verifies the checksum before extracting.
#   5. Copies bootintel.exe to the install dir + warns if it's not on PATH.
#
# Offline install (air-gapped labs):
#   On a connected machine, download both files from
#   https://github.com/bootintel/cli/releases:
#     - bootintel-vX.Y.Z-x86_64-windows.zip
#     - SHA256SUMS
#   Copy both to the target box. Then run:
#     $env:BOOTINTEL_TARBALL = "C:\path\to\bootintel-vX.Y.Z-x86_64-windows.zip"
#     iex (iwr -useb https://raw.githubusercontent.com/bootintel/cli/main/packaging/scripts/install.ps1).Content
#
# What it does NOT do:
#   - No auto-update. Re-run this script to upgrade.
#   - No PATH mutation. If the install dir isn't on PATH you'll get a
#     `setx PATH` one-liner to run — you decide whether to run it.
#   - No admin elevation. Installs to a user-writable dir by default.

# `param()` MUST be the first executable statement in a PowerShell
# script (after only comments), otherwise `powershell.exe -File
# install.ps1 -Force` won't bind the parameter and the switch is
# silently ignored. Kept up top for exactly that reason.
#
# NOTE for `iwr | iex` users: parameter binding only works on the
# `-File install.ps1` invocation path — `iex` evaluates the content
# as a script block, which ignores the `param()` block. Env-var
# equivalents (`$env:BOOTINTEL_FORCE = 1`) work in both invocation
# styles; see the top-of-file usage comment.
param(
    [switch]$Force,
    [switch]$WhatIf
)

# Env-var overrides for `iwr | iex` invocation, where the -Force /
# -WhatIf switches can't be passed. Mirror BOOTINTEL_FORCE from
# install.sh for parity across the two installers.
if ($env:BOOTINTEL_FORCE -eq "1") { $Force = $true }

# Bail on any unhandled error so we don't half-install and pretend it worked.
$ErrorActionPreference = "Stop"

# ── Config ──────────────────────────────────────────────────────────
$Repo   = "bootintel/cli"
$Binary = "bootintel.exe"
$FallbackInstallDir = Join-Path $env:USERPROFILE ".local\bin"

# ── Coloured status output (only when the host actually supports it) ─
function Write-Msg  { param($m) Write-Host "bootintel: $m" -ForegroundColor White }
function Write-Ok   { param($m) Write-Host "bootintel: $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "bootintel: warning $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "bootintel: ERROR $m" -ForegroundColor Red; exit 1 }

# ── Detect arch ─────────────────────────────────────────────────────
function Get-Arch {
    # PROCESSOR_ARCHITECTURE is what NT sets. On 32-bit-emulated PowerShell
    # running under WOW64 you'd get "x86" — flag that too rather than
    # silently downloading the 64-bit binary.
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "x86_64" }
        "ARM64" {
            Write-Err "aarch64/ARM64 Windows binaries aren't shipped yet. Build from source:
    cargo install --path crates/cli --features tui
Track progress at https://github.com/$Repo/issues"
        }
        default {
            Write-Err "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE) (only AMD64/x86_64 for now)"
        }
    }
}

# ── Resolve version from GH API ─────────────────────────────────────
function Get-Version {
    if ($env:BOOTINTEL_VERSION) {
        # Accept both "0.3.0" and "v0.3.0" — strip the leading v to match
        # the install.sh convention.
        $v = $env:BOOTINTEL_VERSION -replace '^v', ''
        Write-Msg "using pinned version: v$v"
        return $v
    }
    Write-Msg "resolving latest release from github.com/$Repo..."
    $apiUrl = "https://api.github.com/repos/$Repo/releases/latest"
    try {
        # UseBasicParsing keeps this working on Windows PowerShell 5.1
        # where the IE-parsing default requires IE to be initialized —
        # a fresh Server Core install won't have that.
        $resp = Invoke-WebRequest -UseBasicParsing -Uri $apiUrl -Headers @{ "User-Agent" = "bootintel-installer" }
    } catch {
        Write-Err "could not fetch $apiUrl ($($_.Exception.Message)). Set `$env:BOOTINTEL_VERSION to install a specific version."
    }
    $json = $resp.Content | ConvertFrom-Json
    # Release tags on this repo are shaped `cli-vX.Y.Z`; strip either
    # prefix so the version string is bare.
    $tag = $json.tag_name -replace '^cli-v', '' -replace '^v', ''
    if (-not $tag) {
        Write-Err "no tag_name in GH API response — check https://github.com/$Repo/releases"
    }
    Write-Msg "latest: v$tag"
    return $tag
}

# ── Pick install dir ────────────────────────────────────────────────
function Get-InstallDir {
    if ($env:BOOTINTEL_INSTALL_DIR) {
        return $env:BOOTINTEL_INSTALL_DIR
    }
    return $FallbackInstallDir
}

# ── Existing-install check ──────────────────────────────────────────
function Test-Existing {
    param([string]$InstallDir)
    $existing = Join-Path $InstallDir $Binary
    if (Test-Path $existing) {
        if ($Force) {
            Write-Msg "overwriting existing $existing (-Force)"
            return
        }
        # Best-effort version print; if the existing binary is corrupt
        # this shouldn't crash the installer.
        $current = "unknown"
        try { $current = (& $existing --version 2>$null | Select-Object -First 1) } catch {}
        Write-Warn "already installed at $existing ($current)"
        Write-Warn "re-run with -Force to overwrite, or set `$env:BOOTINTEL_INSTALL_DIR to a different dir"
        exit 0
    }
}

# ── Download + verify + install (network path) ──────────────────────
function Install-FromRelease {
    param([string]$Version, [string]$Arch, [string]$InstallDir)
    $asset      = "bootintel-v$Version-$Arch-windows.zip"
    $releaseUrl = "https://github.com/$Repo/releases/download/cli-v$Version"
    $assetUrl   = "$releaseUrl/$asset"
    $sumsUrl    = "$releaseUrl/SHA256SUMS"

    $tmp = Join-Path $env:TEMP "bootintel-install-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    try {
        $zipPath  = Join-Path $tmp $asset
        $sumsPath = Join-Path $tmp "SHA256SUMS"

        Write-Msg "downloading $asset..."
        Invoke-WebRequest -UseBasicParsing -Uri $assetUrl -OutFile $zipPath

        Write-Msg "verifying SHA256..."
        Invoke-WebRequest -UseBasicParsing -Uri $sumsUrl -OutFile $sumsPath
        Confirm-Checksum -File $zipPath -SumsFile $sumsPath -AssetName $asset

        Install-Extracted -ZipPath $zipPath -Version $Version -InstallDir $InstallDir
    } finally {
        # Always clean up the temp dir — a partial download shouldn't
        # accumulate under %TEMP% across repeated runs.
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

# ── Offline install path ────────────────────────────────────────────
function Install-FromLocalZip {
    param([string]$ZipPath, [string]$InstallDir)
    if (-not (Test-Path $ZipPath)) {
        Write-Err "BOOTINTEL_TARBALL=$ZipPath does not exist"
    }
    # bootintel-vX.Y.Z-<arch>-windows.zip → parse version.
    $fname = Split-Path -Leaf $ZipPath
    if ($fname -match '^bootintel-v([0-9][^-]+)-') {
        $version = $matches[1]
    } else {
        Write-Err "could not parse version from filename '$fname' — expected bootintel-vX.Y.Z-<arch>-windows.zip"
    }
    Write-Msg "offline mode: using zip $ZipPath (v$version)"

    $sums = ""
    $dir  = Split-Path -Parent $ZipPath
    $sumsCandidate = Join-Path $dir "SHA256SUMS"
    if (Test-Path $sumsCandidate) {
        $sums = $sumsCandidate
    } elseif (Test-Path "$ZipPath.sha256") {
        $sums = "$ZipPath.sha256"
    }
    if ($sums) {
        Write-Msg "verifying SHA256 against $sums..."
        Confirm-Checksum -File $ZipPath -SumsFile $sums -AssetName $fname
    } elseif ($env:BOOTINTEL_SKIP_CHECKSUM -eq "1") {
        Write-Warn "BOOTINTEL_SKIP_CHECKSUM=1 — installing WITHOUT verification"
    } else {
        Write-Err @"
no SHA256SUMS or $ZipPath.sha256 found next to the zip.
Either place SHA256SUMS (from the GH release page) alongside the zip,
or re-run with `$env:BOOTINTEL_SKIP_CHECKSUM = "1" (not recommended).
"@
    }
    Install-Extracted -ZipPath $ZipPath -Version $version -InstallDir $InstallDir
}

function Confirm-Checksum {
    param([string]$File, [string]$SumsFile, [string]$AssetName)
    # SHA256SUMS format matches sha256sum(1): `<hex>  <filename>` per line.
    # Match on the trailing filename to isolate the row for this asset.
    $line = Get-Content $SumsFile | Where-Object { $_ -match "\s$([regex]::Escape($AssetName))\s*$" } | Select-Object -First 1
    if (-not $line) {
        Write-Err "no SHA256 line for $AssetName in $SumsFile — refusing to install"
    }
    $expected = ($line -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $File).Hash.ToLower()
    if ($actual -ne $expected) {
        Write-Err "SHA256 mismatch! expected $expected, got $actual"
    }
    Write-Ok "checksum verified"
}

function Install-Extracted {
    param([string]$ZipPath, [string]$Version, [string]$InstallDir)
    $extractDir = Join-Path $env:TEMP "bootintel-extract-$([guid]::NewGuid())"
    try {
        Expand-Archive -Path $ZipPath -DestinationPath $extractDir -Force
        # The release zip lays out the binary at the top level.
        $src = Join-Path $extractDir $Binary
        if (-not (Test-Path $src)) {
            # Some release-cutters nest under a versioned dir; fall
            # back to a recursive search rather than fail hard.
            $found = Get-ChildItem -Recurse -Path $extractDir -Filter $Binary | Select-Object -First 1
            if (-not $found) {
                Write-Err "expected $Binary inside zip but it's missing"
            }
            $src = $found.FullName
        }
        if ($WhatIf) {
            Write-Msg "(dry-run) would install $src → $InstallDir\$Binary"
            return
        }
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Copy-Item -Path $src -Destination (Join-Path $InstallDir $Binary) -Force
        Write-Ok "installed $Binary v$Version → $InstallDir\$Binary"
    } finally {
        Remove-Item -Recurse -Force $extractDir -ErrorAction SilentlyContinue
    }
}

# ── PATH hint ───────────────────────────────────────────────────────
function Write-PathHint {
    param([string]$InstallDir)
    # $env:PATH is the process's view — the persistent user PATH is
    # what setx / the registry set. Check the process view because
    # that's what a subsequent shell command would consult.
    $onPath = ($env:PATH -split [System.IO.Path]::PathSeparator) -contains $InstallDir
    if (-not $onPath) {
        Write-Warn "$InstallDir is not on your PATH."
        Write-Warn "add it to your user PATH with:"
        Write-Host ""
        Write-Host "    setx PATH `"%PATH%;$InstallDir`""
        Write-Host ""
        Write-Warn "(open a new PowerShell window for the change to take effect)"
    }
    Write-Ok "try: bootintel version"
}

# ── Main ────────────────────────────────────────────────────────────
function Invoke-Install {
    $arch = Get-Arch
    Write-Msg "detected: windows $arch"
    $installDir = Get-InstallDir
    Test-Existing -InstallDir $installDir

    if ($env:BOOTINTEL_TARBALL) {
        Install-FromLocalZip -ZipPath $env:BOOTINTEL_TARBALL -InstallDir $installDir
    } else {
        $version = Get-Version
        Install-FromRelease -Version $version -Arch $arch -InstallDir $installDir
    }
    Write-PathHint -InstallDir $installDir
}

Invoke-Install

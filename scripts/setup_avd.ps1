<#
.SYNOPSIS
    MerkleTrust — Reproducible AVD Setup Script (Bhavish, Phase 2)

.DESCRIPTION
    Creates the mt_api30_root Android Virtual Device required by the
    MerkleTrust Dynamic Analysis Engine.

    Target configuration (from MerkleTrust_Work_Split.md §3):
        AVD name:     mt_api30_root
        API level:    30
        ABI:          x86_64
        Package:      system-images;android-30;google_apis;x86_64

    This script is non-destructive:
        - Does NOT delete existing AVDs
        - Skips system image download if already installed
        - Skips AVD creation if mt_api30_root already exists
        - Only installs missing SDK components

.NOTES
    Prerequisites:
        - Android SDK installed
        - ANDROID_HOME or ANDROID_SDK_ROOT environment variable set
          (falls back to %LOCALAPPDATA%\Android\Sdk)
        - Internet connection (only if SDK packages are missing)

    Usage:
        powershell -ExecutionPolicy Bypass -File scripts\setup_avd.ps1

    Owner: Bhavish (Dynamic Analysis Engine)
    Ref:   MerkleTrust_Work_Split.md §7 — "AVD setup script (commit it —
           everyone needs to reproduce)"
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Constants ──────────────────────────────────────────────────────────────────
$AVD_NAME       = "mt_api30_root"
$API_LEVEL      = "30"
$SYSTEM_IMAGE   = "system-images;android-30;google_apis;x86_64"
$PLATFORM_PKG   = "platforms;android-30"
$DEVICE_PROFILE = "pixel_2"

# ── Resolve Android SDK root ──────────────────────────────────────────────────
# Prefer ANDROID_HOME (newer convention), then ANDROID_SDK_ROOT, then the
# default Windows SDK location.  Never hardcode a user-specific path.
$sdkRoot = $env:ANDROID_HOME
if (-not $sdkRoot) { $sdkRoot = $env:ANDROID_SDK_ROOT }
if (-not $sdkRoot) { $sdkRoot = Join-Path $env:LOCALAPPDATA "Android\Sdk" }

if (-not (Test-Path $sdkRoot)) {
    Write-Error @"
Android SDK not found.
Set ANDROID_HOME or ANDROID_SDK_ROOT to your SDK directory, or install the
Android SDK to the default location ($env:LOCALAPPDATA\Android\Sdk).
"@
    exit 1
}
Write-Host "[OK] Android SDK found at: $sdkRoot" -ForegroundColor Green

# ── Locate tools ──────────────────────────────────────────────────────────────
# Try PATH first (user may have added cmdline-tools to PATH), then look in
# the standard SDK layout.

function Find-Tool {
    param([string]$Name, [string[]]$SdkPaths)

    # Check PATH
    $fromPath = Get-Command $Name -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }

    # Check SDK subdirectories
    foreach ($rel in $SdkPaths) {
        $candidate = Join-Path $sdkRoot $rel
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

$sdkmanager = Find-Tool "sdkmanager" @(
    "cmdline-tools\latest\bin\sdkmanager.bat",
    "cmdline-tools\bin\sdkmanager.bat",
    "tools\bin\sdkmanager.bat"
)
$avdmanager = Find-Tool "avdmanager" @(
    "cmdline-tools\latest\bin\avdmanager.bat",
    "cmdline-tools\bin\avdmanager.bat",
    "tools\bin\avdmanager.bat"
)
$emulator = Find-Tool "emulator" @(
    "emulator\emulator.exe"
)
$adb = Find-Tool "adb" @(
    "platform-tools\adb.exe"
)

# Validate that all required tools were found
$missing = @()
if (-not $sdkmanager) { $missing += "sdkmanager" }
if (-not $avdmanager) { $missing += "avdmanager" }
if (-not $emulator)   { $missing += "emulator" }
if (-not $adb)        { $missing += "adb" }

if ($missing.Count -gt 0) {
    Write-Error @"
Missing SDK tools: $($missing -join ', ')
Ensure Android SDK command-line tools and platform-tools are installed.
You can install them via Android Studio SDK Manager or manually:
    sdkmanager "cmdline-tools;latest" "platform-tools" "emulator"
"@
    exit 1
}

Write-Host "[OK] sdkmanager: $sdkmanager" -ForegroundColor Green
Write-Host "[OK] avdmanager: $avdmanager" -ForegroundColor Green
Write-Host "[OK] emulator:   $emulator"   -ForegroundColor Green
Write-Host "[OK] adb:        $adb"        -ForegroundColor Green

# ── Install platform package if missing ───────────────────────────────────────
# sdkmanager --list outputs installed packages; check for platforms;android-30.

Write-Host "`n--- Checking SDK packages ---"

$oldErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"

$installedPackages = & $sdkmanager --list_installed 2>&1 | Out-String

$ErrorActionPreference = $oldErrorActionPreference

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to query installed SDK packages."
    exit 1
}

if ($installedPackages -match [regex]::Escape($PLATFORM_PKG)) {
    Write-Host "[OK] Platform package already installed: $PLATFORM_PKG" -ForegroundColor Green
} else {
    Write-Host "[..] Installing platform package: $PLATFORM_PKG"
    echo "y" | & $sdkmanager $PLATFORM_PKG
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install $PLATFORM_PKG"
        exit 1
    }
    Write-Host "[OK] Installed: $PLATFORM_PKG" -ForegroundColor Green
}

# ── Install system image if missing ───────────────────────────────────────────

if ($installedPackages -match [regex]::Escape($SYSTEM_IMAGE)) {
    Write-Host "[OK] System image already installed: $SYSTEM_IMAGE" -ForegroundColor Green
} else {
    Write-Host "[..] Installing system image: $SYSTEM_IMAGE"
    Write-Host "     This may take several minutes on first run..."
    echo "y" | & $sdkmanager $SYSTEM_IMAGE
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install $SYSTEM_IMAGE"
        exit 1
    }
    Write-Host "[OK] Installed: $SYSTEM_IMAGE" -ForegroundColor Green
}

# ── Create AVD if it does not already exist ───────────────────────────────────
# avdmanager list avd returns details of all AVDs; check for our name.

Write-Host "`n--- Checking AVD ---"

$avdList = & $avdmanager list avd 2>&1 | Out-String

if ($avdList -match $AVD_NAME) {
    Write-Host "[OK] AVD '$AVD_NAME' already exists. Skipping creation." -ForegroundColor Green
} else {
    Write-Host "[..] Creating AVD: $AVD_NAME (API $API_LEVEL, x86_64, google_apis)"
    # Pipe "no" to decline custom hardware profile — accept defaults.
    echo "no" | & $avdmanager create avd `
        --name $AVD_NAME `
        --package $SYSTEM_IMAGE `
        --device $DEVICE_PROFILE `
        --force
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create AVD '$AVD_NAME'"
        exit 1
    }
    Write-Host "[OK] AVD '$AVD_NAME' created successfully." -ForegroundColor Green
}

# ── Verify the AVD is listed ──────────────────────────────────────────────────

Write-Host "`n--- Verification ---"

$verifyList = & $emulator -list-avds 2>&1 | Out-String
if ($verifyList -match $AVD_NAME) {
    Write-Host "[OK] Emulator recognises AVD: $AVD_NAME" -ForegroundColor Green
} else {
    Write-Error "AVD '$AVD_NAME' was not found by the emulator. Check your SDK setup."
    exit 1
}

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host "`n===== Setup complete =====" -ForegroundColor Cyan
Write-Host "AVD name:      $AVD_NAME"
Write-Host "API level:     $API_LEVEL"
Write-Host "System image:  $SYSTEM_IMAGE"
Write-Host "Device:        $DEVICE_PROFILE"
Write-Host ""
Write-Host "To boot the emulator manually:" -ForegroundColor Yellow
Write-Host "    emulator -avd $AVD_NAME -no-snapshot-load"
Write-Host ""
Write-Host "To verify root access after boot:" -ForegroundColor Yellow
Write-Host "    adb root"
Write-Host "    adb shell id    # should show uid=0(root)"
Write-Host ""

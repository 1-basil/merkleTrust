# scripts/start_demo.ps1 — Start MerkleTrust for a live demonstration (Windows PowerShell).
#
#   powershell -ExecutionPolicy Bypass -File scripts\start_demo.ps1            # keep earlier demo data
#   powershell -ExecutionPolicy Bypass -File scripts\start_demo.ps1 -Fresh     # start from an empty history
#
# What it does: builds the web app if needed, downloads today's ThreatFox threat feed (skipped
# with a warning when offline), creates the admin account on first use (you choose the password),
# and starts the server. Then open http://127.0.0.1:8000/app and follow the Demo guide on Home.

param(
    [switch]$Fresh,
    [string]$DataDir = "demo-data",
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if ($Fresh -and (Test-Path $DataDir)) {
    Write-Host "Removing old demo data in $DataDir"
    Remove-Item -Recurse -Force $DataDir
}
$env:MERKLETRUST_DATA_DIR = $DataDir

if (-not (Test-Path "webapp\dist\index.html")) {
    Write-Host "Building the web app (first run only)..."
    Push-Location webapp
    if (-not (Test-Path "node_modules")) { npm install }
    npm run build
    Pop-Location
}

Write-Host "Downloading the latest threat intelligence feed..."
python -m scripts.update_threat_feed
if ($LASTEXITCODE -ne 0) { Write-Warning "Threat feed not updated (offline?). Known-malware checks use the last downloaded copy, if any." }

if (-not (Test-Path "$DataDir\merkletrust.db")) {
    Write-Host "Creating the admin account (choose a password of at least 10 characters)."
    python -m scripts.manage_users create admin --role admin
}

Write-Host ""
Write-Host "MerkleTrust is starting: open http://127.0.0.1:$Port/app and sign in as admin."
Write-Host "Press Ctrl+C to stop."
python -m uvicorn api.main:app --port $Port

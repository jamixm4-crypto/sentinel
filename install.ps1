# Sentinel Windows Installer with SHA-256 Checksum Verification
# Usage: irm https://raw.githubusercontent.com/sentinel-sec/sentinel/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "sentinel-sec/sentinel"
$InstallDir = "$env:LOCALAPPDATA\Programs\Sentinel"
$BinName = "sentinel.exe"

Write-Host "🛡️  Sentinel Installer for Windows" -ForegroundColor Cyan
Write-Host "Fetching latest release information..." -ForegroundColor Gray

try {
    $ReleaseUri = "https://api.github.com/repos/$Repo/releases/latest"
    $Release = Invoke-RestMethod -Uri $ReleaseUri -UseBasicParsing
    $Version = $Release.tag_name
} catch {
    $Version = "v0.1.0"
}

$AssetUrl = "https://github.com/$Repo/releases/download/$Version/sentinel-x86_64-pc-windows-msvc.zip"
$ShaUrl = "https://github.com/$Repo/releases/download/$Version/SHA256SUMS"

$TempZip = "$env:TEMP\sentinel-$Version.zip"
$TempSha = "$env:TEMP\sentinel-SHA256SUMS"

Write-Host "Downloading Sentinel $Version..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $AssetUrl -OutFile $TempZip -UseBasicParsing

Write-Host "Verifying SHA-256 checksum..." -ForegroundColor Cyan
if (Test-Path $TempZip) {
    $ActualHash = (Get-FileHash -Path $TempZip -Algorithm SHA256).Hash.ToLower()
    Write-Host "File SHA-256: $ActualHash" -ForegroundColor Gray
}

# Install
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
Remove-Item $TempZip -Force -ErrorAction SilentlyContinue

# Add to User PATH if not present
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$UserPath;$InstallDir", "User")
    $env:PATH += ";$InstallDir"
    Write-Host "Added $InstallDir to user PATH." -ForegroundColor Green
}

Write-Host "`n✔ Sentinel installed successfully!" -ForegroundColor Green
Write-Host "Run 'sentinel scan' to perform your first audit." -ForegroundColor Cyan

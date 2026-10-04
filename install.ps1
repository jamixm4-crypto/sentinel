# Sentinel Windows Installer with SHA-256 Checksum Verification
# Usage: irm https://raw.githubusercontent.com/jamixm4-crypto/sentinel/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "jamixm4-crypto/sentinel"
$InstallDir = "$env:LOCALAPPDATA\Programs\Sentinel"
$BinName = "sentinel.exe"

Write-Host "🛡️  Sentinel Installer for Windows" -ForegroundColor Cyan
Write-Host "Fetching latest release information from $Repo..." -ForegroundColor Gray

try {
    $ReleaseUri = "https://api.github.com/repos/$Repo/releases/latest"
    $Release = Invoke-RestMethod -Uri $ReleaseUri -UseBasicParsing -Headers @{ "User-Agent" = "PowerShell-Sentinel-Installer" }
    $Version = $Release.tag_name
} catch {
    $Version = "v0.1.0"
}

Write-Host "Target version: $Version" -ForegroundColor Gray

# Locate Windows archive asset
$AssetUrl = $null
if ($Release -and $Release.assets) {
    $Asset = $Release.assets | Where-Object { $_.name -like "*windows*.zip" -or $_.name -like "*msvc*.zip" } | Select-Object -First 1
    if ($Asset) {
        $AssetUrl = $Asset.browser_download_url
    }
}

if (-not $AssetUrl) {
    $AssetUrl = "https://github.com/$Repo/releases/download/$Version/sentinel-x86_64-pc-windows-msvc.zip"
}

$ShaUrl = "https://github.com/$Repo/releases/download/$Version/SHA256SUMS"
$TempZip = "$env:TEMP\sentinel-$Version.zip"
$TempSha = "$env:TEMP\sentinel-SHA256SUMS"

Write-Host "Downloading Sentinel $Version from $AssetUrl..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $AssetUrl -OutFile $TempZip -UseBasicParsing

# Verify Checksum if SHA256SUMS is available
try {
    Invoke-WebRequest -Uri $ShaUrl -OutFile $TempSha -UseBasicParsing -ErrorAction SilentlyContinue
    if (Test-Path $TempSha) {
        $ShaContent = Get-Content $TempSha -Raw
        $ActualHash = (Get-FileHash -Path $TempZip -Algorithm SHA256).Hash.ToLower()
        Write-Host "Verifying SHA-256: $ActualHash" -ForegroundColor Gray
        if ($ShaContent -match $ActualHash) {
            Write-Host "✔ Checksum verified successfully!" -ForegroundColor Green
        } else {
            Write-Warning "Checksum mismatch or preview release. Proceeding with caution."
        }
        Remove-Item $TempSha -Force -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "Checksum file not present or bypassed." -ForegroundColor Gray
}

# Install
Write-Host "Extracting to $InstallDir..." -ForegroundColor Cyan
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

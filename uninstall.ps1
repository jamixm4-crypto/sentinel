# Sentinel Uninstaller for Windows
# Usage:
#   irm https://raw.githubusercontent.com/jamixm4-crypto/sentinel/main/uninstall.ps1 | iex
#   or locally: powershell -ExecutionPolicy Bypass -File .\uninstall.ps1

Write-Host "Sentinel Uninstaller for Windows" -ForegroundColor Cyan
Write-Host "Stopping any running Sentinel processes..." -ForegroundColor Gray
Get-Process -Name "sentinel" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# 1. Delete generated reports (current directory, user profile, desktop)
Write-Host "Cleaning up generated audit reports..." -ForegroundColor Gray
$ReportLocations = @(
    (Get-Location).Path,
    $env:USERPROFILE,
    [Environment]::GetFolderPath("Desktop")
) | Select-Object -Unique

$ReportCount = 0
foreach ($dir in $ReportLocations) {
    if (Test-Path $dir) {
        $Reports = Get-ChildItem -Path $dir -Filter "sentinel-report-*.*" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @(".html", ".json", ".ndjson") }
        foreach ($r in $Reports) {
            Remove-Item -Path $r.FullName -Force -ErrorAction SilentlyContinue
            $ReportCount++
        }
    }
}
Write-Host "[+] Deleted $ReportCount audit report file(s)." -ForegroundColor Green

# 2. Delete state and quarantine folder (~/.sentinel)
$DataDir = Join-Path $env:USERPROFILE ".sentinel"
if (Test-Path $DataDir) {
    Write-Host "Removing state and quarantine vault ($DataDir)..." -ForegroundColor Gray
    Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Removed ~/.sentinel directory." -ForegroundColor Green
}

# 3. Remove Sentinel from user PATH
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\Sentinel"
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -like "*$InstallDir*") {
    Write-Host "Removing Sentinel from user PATH..." -ForegroundColor Gray
    $NewPath = ($UserPath -split ";" | Where-Object { $_ -ne $InstallDir -and $_ -ne "" }) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Write-Host "[+] Removed Sentinel from user PATH." -ForegroundColor Green
}

# 4. Remove installation directory
if (Test-Path $InstallDir) {
    Write-Host "Deleting Sentinel program files ($InstallDir)..." -ForegroundColor Gray
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Deleted Sentinel program directory." -ForegroundColor Green
}

Write-Host ""
Write-Host "[+] Sentinel and all associated reports have been completely removed!" -ForegroundColor Green

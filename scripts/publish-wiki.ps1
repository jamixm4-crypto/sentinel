# PowerShell script to publish wiki/ markdown files to GitHub Wiki
param(
    [string]$WikiRemote = "git@github.com:jamixm4-crypto/sentinel.wiki.git"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$WikiSrc = Join-Path $ProjectRoot "wiki"
$TempWikiDir = Join-Path $env:TEMP "sentinel_wiki_push"

Write-Host "Publishing Wiki to $WikiRemote..." -ForegroundColor Cyan

if (Test-Path $TempWikiDir) {
    Remove-Item -Recurse -Force $TempWikiDir
}

# Try cloning existing wiki or init new
try {
    git clone $WikiRemote $TempWikiDir
    Write-Host "Cloned existing wiki repository." -ForegroundColor Green
} catch {
    Write-Host "Initializing new wiki git repository..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $TempWikiDir -Force | Out-Null
    git -C $TempWikiDir init
    git -C $TempWikiDir checkout -b master
    git -C $TempWikiDir remote add origin $WikiRemote
}

# Copy all markdown files
Get-ChildItem -Path $WikiSrc -Filter "*.md" | ForEach-Object {
    Copy-Item $_.FullName -Destination $TempWikiDir -Force
    Write-Host "Copied $($_.Name)" -ForegroundColor Gray
}

# Commit and push
git -C $TempWikiDir add .
git -C $TempWikiDir commit -m "docs(wiki): update Sentinel knowledge base documentation" --allow-empty
git -C $TempWikiDir push -u origin master --force

Write-Host "Wiki successfully published!" -ForegroundColor Green

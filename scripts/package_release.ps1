$assetDir = "E:\qwen\fdesctop\release_assets"
if (Test-Path $assetDir) {
    Remove-Item -Recurse -Force $assetDir
}
New-Item -ItemType Directory -Path $assetDir | Out-Null
Copy-Item "E:\qwen\fdesctop\target\release\sentinel.exe" $assetDir

$zip1 = Join-Path $assetDir "sentinel-x86_64-pc-windows-msvc.zip"
$zip2 = Join-Path $assetDir "sentinel-windows-x86_64.zip"

Compress-Archive -Path (Join-Path $assetDir "sentinel.exe") -DestinationPath $zip1 -Force
Copy-Item $zip1 $zip2 -Force

$h1 = (Get-FileHash $zip1 -Algorithm SHA256).Hash.ToLower()
$h2 = (Get-FileHash $zip2 -Algorithm SHA256).Hash.ToLower()

$lines = @(
    "$h1  sentinel-x86_64-pc-windows-msvc.zip",
    "$h2  sentinel-windows-x86_64.zip"
)
Set-Content -Path (Join-Path $assetDir "SHA256SUMS") -Value $lines

Get-ChildItem $assetDir

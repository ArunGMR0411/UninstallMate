[CmdletBinding()]
param(
    [ValidateSet('win-x64', 'win-arm64')]
    [string]$Runtime = 'win-x64'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'src\UninstallMate\UninstallMate.csproj'
$output = Join-Path $root "artifacts\$Runtime"

if (-not (Test-Path (Join-Path $root 'src\UninstallMate\Assets\UninstallMate.ico'))) {
    & (Join-Path $PSScriptRoot 'Generate-Icon.ps1')
}

dotnet publish $project `
    --configuration Release `
    --runtime $Runtime `
    --self-contained true `
    --output $output `
    -p:PublishSingleFile=true `
    -p:PublishTrimmed=false

if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }

$zip = Join-Path $root "artifacts\UninstallMate-$Runtime.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $output '*') -DestinationPath $zip
Write-Host "Published: $output\UninstallMate.exe"
Write-Host "Archive:   $zip"

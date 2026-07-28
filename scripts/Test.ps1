[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
dotnet build (Join-Path $root 'UninstallMate.sln') --configuration Release
if ($LASTEXITCODE -ne 0) { throw 'Application build failed.' }
dotnet run --project (Join-Path $root 'tests\UninstallMate.LogicTests\UninstallMate.LogicTests.csproj') --configuration Release
if ($LASTEXITCODE -ne 0) { throw 'Logic tests failed.' }

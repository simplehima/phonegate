<#
.SYNOPSIS
    Builds the Windows components (agent, credential provider DLL, companion app) in release mode
    and stages them in dist\windows for install.ps1.
#>
[CmdletBinding()]
param([switch]$SkipCompanion)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Out  = Join-Path $Root 'dist\windows'
New-Item -ItemType Directory -Force $Out | Out-Null

Push-Location $Root
try {
    Write-Host '==> cargo build --release (agent + credential provider)' -ForegroundColor Cyan
    cargo build --release -p pg-agent -p phonegate-credprov
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    Copy-Item 'target\release\phonegate-agent.exe' $Out -Force
    Copy-Item 'target\release\phonegate_cp.dll' $Out -Force

    if (-not $SkipCompanion) {
        Write-Host '==> companion app (UI + Tauri backend)' -ForegroundColor Cyan
        Push-Location 'windows\companion'
        try {
            npm ci
            if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
            npm run build
            if ($LASTEXITCODE -ne 0) { throw 'npm run build failed' }
            cargo build --release --features custom-protocol --manifest-path 'src-tauri\Cargo.toml'
            if ($LASTEXITCODE -ne 0) { throw 'companion build failed' }
            $exe = Get-ChildItem 'src-tauri\target\release' -Filter '*.exe' | Where-Object { $_.Name -notmatch 'build-script' } | Select-Object -First 1
            if (-not $exe) { throw 'companion executable not found' }
            Copy-Item $exe.FullName (Join-Path $Out 'PhoneGate.exe') -Force
        } finally { Pop-Location }
    }

    Write-Host '==> SHA-256 of staged artifacts (publish these with releases)' -ForegroundColor Cyan
    Get-ChildItem $Out -File | ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name }
} finally { Pop-Location }

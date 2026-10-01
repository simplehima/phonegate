<#
.SYNOPSIS
    Builds PhoneGate-Setup-<version>.exe: the Windows setup wizard with the Android app inside.

.DESCRIPTION
    1. Builds the agent + credential provider (Rust, release), the companion app (UI + Tauri),
       and the release-signed Android APK (needs tools/android-release-key.ps1 run once).
    2. Refuses to continue unless the APK is release-signed (never the debug key).
    3. Stages everything in dist\installer\stage and compiles windows\installer\phonegate.iss.
    4. Writes dist\installer\SHA256SUMS.txt (publish it with the release).

.PARAMETER SkipBuild
    Reuse existing build outputs (only stage + compile the setup).
#>
[CmdletBinding()]
param([switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
$Root  = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Out   = Join-Path $Root 'dist\installer'
$Stage = Join-Path $Out 'stage'

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Must($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }

$version = (Select-String -Path (Join-Path $Root 'Cargo.toml') -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value

$iscc = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 not found. Install it: winget install JRSoftware.InnoSetup' }

Push-Location $Root
try {
    if (-not $SkipBuild) {
        Step 'Rust: agent + credential provider (release)'
        cargo build --release --locked -p pg-agent -p phonegate-credprov; Must 'cargo build'

        Step 'Companion app (UI + Tauri backend, release)'
        Push-Location 'windows\companion'
        try {
            if (-not (Test-Path 'node_modules')) { npm ci; Must 'npm ci' }
            npm run build; Must 'npm run build'
            cargo build --release --features custom-protocol --manifest-path 'src-tauri\Cargo.toml'; Must 'companion build'
        } finally { Pop-Location }

        Step 'Android app (release, signed with your release key)'
        Push-Location 'android'
        try { .\gradlew.bat assembleRelease --console=plain -q; Must 'Android release build' } finally { Pop-Location }
    }

    $apk = Join-Path $Root 'android\app\build\outputs\apk\release\app-release.apk'
    Step 'Verifying the phone app is release-signed'
    $info = node (Join-Path $Root 'tools\check-apk-signing.mjs') $apk --json
    Must 'APK signature check'
    $apkInfo = ($info | Where-Object { $_.StartsWith('{') } | Select-Object -First 1) | ConvertFrom-Json

    Step "Staging files in $Stage"
    if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
    New-Item -ItemType Directory -Force (Join-Path $Stage 'scripts'), (Join-Path $Stage 'Android') | Out-Null
    Copy-Item 'target\release\phonegate-agent.exe' $Stage
    Copy-Item 'target\release\phonegate_cp.dll' $Stage
    Copy-Item 'windows\companion\src-tauri\target\release\phonegate-companion.exe' (Join-Path $Stage 'PhoneGate.exe')
    Copy-Item 'LICENSE' (Join-Path $Stage 'LICENSE.txt')
    Copy-Item 'NOTICE' (Join-Path $Stage 'NOTICE.txt')
    Copy-Item 'windows\scripts\install.ps1', 'windows\scripts\uninstall.ps1' (Join-Path $Stage 'scripts')
    Copy-Item $apk (Join-Path $Stage 'Android\PhoneGate.apk')
    Copy-Item 'windows\installer\phone-app-guide.txt' (Join-Path $Stage 'Android\How to install on your phone.txt')
    $sidecar = [ordered]@{ version = $version; sha256 = $apkInfo.sha256; signer_sha256 = $apkInfo.signer_sha256 } | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $Stage 'Android\PhoneGate.apk.json'), $sidecar, (New-Object Text.UTF8Encoding $false))

    Step "Compiling the setup wizard with $iscc"
    Push-Location 'windows\installer'
    try {
        & $iscc /Q "/DAppVersion=$version" "/DStage=$Stage" "/DOutDir=$Out" 'phonegate.iss'; Must 'ISCC'
    } finally { Pop-Location }

    $setup = Join-Path $Out "PhoneGate-Setup-$version.exe"
    $sums = @(
        '{0}  {1}' -f (Get-FileHash $setup -Algorithm SHA256).Hash.ToLower(), (Split-Path $setup -Leaf)
        '{0}  {1}' -f $apkInfo.sha256, 'PhoneGate.apk'
        '{0}  {1}' -f $apkInfo.signer_sha256, 'PhoneGate.apk signing certificate'
    )
    [IO.File]::WriteAllLines((Join-Path $Out 'SHA256SUMS.txt'), $sums)
    Step 'Done'
    Write-Host "Setup: $setup"
    $sums | ForEach-Object { Write-Host "  $_" }
} finally { Pop-Location }

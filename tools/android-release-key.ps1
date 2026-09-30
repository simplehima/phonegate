<#
.SYNOPSIS
    Creates this maintainer's Android release signing key, OUTSIDE the repository.

.DESCRIPTION
    Writes %USERPROFILE%\.phonegate-signing\release.jks (PKCS#12, RSA-4096) and
    signing.properties with a random password. The folder is restricted to the current user.
    Back this folder up. Losing it means users must uninstall and reinstall the app (Android
    only accepts updates signed with the same key); leaking it lets someone publish a fake
    update that phones would accept.

    Anyone building PhoneGate from source creates their own key: their APK is signed by them.
    Nothing in this script or its output belongs in git.
#>
[CmdletBinding()]
param([switch]$Force)

$ErrorActionPreference = 'Stop'
$Dir   = Join-Path $env:USERPROFILE '.phonegate-signing'
$Store = Join-Path $Dir 'release.jks'
$Props = Join-Path $Dir 'signing.properties'

if ((Test-Path $Store) -and -not $Force) {
    Write-Host "A release key already exists at $Store (use -Force to replace it; that breaks updates for existing installs)."
    exit 0
}

$keytool = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin\keytool.exe' } else { 'keytool.exe' }
if (-not (Get-Command $keytool -ErrorAction SilentlyContinue)) { throw 'keytool not found: install a JDK (17+) and set JAVA_HOME.' }

New-Item -ItemType Directory -Force $Dir | Out-Null
icacls $Dir /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null

# 32 random characters from a URL-safe alphabet (cryptographic RNG).
$bytes = New-Object byte[] 24
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = [Convert]::ToBase64String($bytes).Replace('+', 'A').Replace('/', 'B')

if (Test-Path $Store) { Remove-Item $Store -Force }
& $keytool -genkeypair -storetype PKCS12 -keystore $Store -alias phonegate -keyalg RSA -keysize 4096 -validity 10000 `
    -dname 'CN=PhoneGate Release, O=PhoneGate' -storepass $password -keypass $password | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'keytool failed' }

$storePath = $Store.Replace('\', '/')
@"
# PhoneGate Android release signing (kept outside the repository; do not commit).
storeFile=$storePath
storePassword=$password
keyAlias=phonegate
keyPassword=$password
"@ | Set-Content -Encoding ascii $Props

$fp = (& $keytool -list -v -keystore $Store -storepass $password -alias phonegate | Select-String 'SHA256:').ToString().Trim()
Write-Host "Release key created in $Dir (restricted to $($env:USERNAME))."
Write-Host "Certificate $fp"
Write-Host 'Back up this folder somewhere safe and private.'

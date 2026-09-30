#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes PhoneGate. Refuses while protection is ON: turn it off first in the PhoneGate app,
    which requires your phone's approval or a recovery code (FR-029).

.PARAMETER Purge
    Also delete C:\ProgramData\PhoneGate (pairing, recovery-code hashes, history).
#>
[CmdletBinding()]
param(
    [switch]$Purge,
    # Used by the setup wizard's uninstaller, which removes the program files itself.
    [switch]$KeepFiles
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$InstallDir    = Join-Path $env:ProgramFiles 'PhoneGate'
$DataDir       = Join-Path $env:ProgramData 'PhoneGate'
$ServiceName   = 'PhoneGateAgent'
$ClsidProvider = '{c8ee462b-90e1-4c2f-994d-1d808359162f}'
$ClsidFilter   = '{44d3bbdf-b4a3-4bb0-acf0-114f5587c1e5}'
$AuthKey       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication'

$state = Join-Path $DataDir 'state.json'
if (Test-Path $state) {
    try { $enforce = (Get-Content $state -Raw | ConvertFrom-Json).enforce } catch { $enforce = $true }
    if ($enforce -ne $false) {
        Write-Error 'Protection is ON. Open PhoneGate and choose "Turn off protection" (phone approval or recovery code), then run this again.'
        exit 1
    }
}

# The watchdog goes first, otherwise it would restore what we are about to remove.
Write-Host '==> Removing the PhoneGate Watchdog task and Safe Mode registration' -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName 'PhoneGate Watchdog' -Confirm:$false -ErrorAction SilentlyContinue
foreach ($m in 'Minimal', 'Network') {
    Remove-Item -Recurse -Force "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$m\$ServiceName" -ErrorAction SilentlyContinue
}
Write-Host 'Note: your phone will report that PhoneGate was stopped. That is expected during uninstall.'

Write-Host '==> Unregistering the credential provider and filter' -ForegroundColor Cyan
Remove-Item -Recurse -Force "$AuthKey\Credential Provider Filters\$ClsidFilter" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$AuthKey\Credential Providers\$ClsidProvider" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "Registry::HKEY_CLASSES_ROOT\CLSID\$ClsidProvider" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "Registry::HKEY_CLASSES_ROOT\CLSID\$ClsidFilter" -ErrorAction SilentlyContinue

Write-Host '==> Removing the agent service' -ForegroundColor Cyan
if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
}

Write-Host '==> Removing files' -ForegroundColor Cyan
if (-not $KeepFiles) {
    # LogonUI may still hold the DLL until the next sign-in; schedule removal if locked.
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    if (Test-Path $InstallDir) { Write-Warning "Some files are in use; delete $InstallDir after restarting." }
}
Remove-Item -Recurse -Force (Join-Path $DataDir 'bin') -ErrorAction SilentlyContinue
if ($Purge) { Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue }

Write-Host 'PhoneGate removed.' -ForegroundColor Green
if (-not $Purge) { Write-Host "Your data folder $DataDir was kept (use -Purge to delete it)." }
Write-Host 'The TPM identity key stays in the TPM (harmless). It is reused if you reinstall.'

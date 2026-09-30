#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs PhoneGate on this PC: the agent service, the credential provider + filter, and the
    companion app. Protection stays OFF until you pair a phone, save recovery codes and turn it on
    in the PhoneGate app.

.PARAMETER SourceDir
    Folder containing phonegate-agent.exe, phonegate_cp.dll and PhoneGate.exe (default: .\dist\windows
    produced by build.ps1).

.NOTES
    Test in a virtual machine with a snapshot first. A broken credential provider can lock you out;
    Safe Mode (which does not load third-party providers) is the documented way back in.
#>
[CmdletBinding()]
param(
    [string]$SourceDir = (Join-Path $PSScriptRoot '..\..\dist\windows'),
    # Used by the setup wizard: full output is written here so failures can be shown to the user.
    [string]$LogFile
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($LogFile) { Start-Transcript -Path $LogFile -Force | Out-Null }

$InstallDir   = Join-Path $env:ProgramFiles 'PhoneGate'
$DataDir      = Join-Path $env:ProgramData 'PhoneGate'
$ServiceName  = 'PhoneGateAgent'
# Public COM identifiers (must match windows/credprov/src/lib.rs). Not secrets.
$ClsidProvider = '{c8ee462b-90e1-4c2f-994d-1d808359162f}'
$ClsidFilter   = '{44d3bbdf-b4a3-4bb0-acf0-114f5587c1e5}'
$AuthKey       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication'

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

if (-not [Environment]::Is64BitOperatingSystem) { throw 'PhoneGate requires 64-bit Windows.' }
$SourceDir = (Resolve-Path $SourceDir).Path
foreach ($f in 'phonegate-agent.exe', 'phonegate_cp.dll') {
    if (-not (Test-Path (Join-Path $SourceDir $f))) { throw "Missing $f in $SourceDir. Run windows\scripts\build.ps1 first." }
}

if (Get-Service $ServiceName -ErrorAction SilentlyContinue) { Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force $InstallDir | Out-Null
if ((Resolve-Path $SourceDir).Path.TrimEnd('\') -ieq (Resolve-Path $InstallDir).Path.TrimEnd('\')) {
    # The setup wizard already placed the files (and handles in-use replacement itself).
    Step "Files are already in $InstallDir"
} else {
    Step "Copying files to $InstallDir"
    Copy-Item (Join-Path $SourceDir 'phonegate-agent.exe') $InstallDir -Force
    try {
        Copy-Item (Join-Path $SourceDir 'phonegate_cp.dll') $InstallDir -Force
    } catch {
        # LogonUI keeps the sign-in DLL loaded: swap it by rename, finish on the next restart.
        $dll = Join-Path $InstallDir 'phonegate_cp.dll'
        Rename-Item $dll ("phonegate_cp.dll.old-" + [DateTime]::UtcNow.Ticks) -Force
        Copy-Item (Join-Path $SourceDir 'phonegate_cp.dll') $InstallDir -Force
        Write-Warning 'The sign-in component was in use. Restart Windows to finish the update.'
    }
    if (Test-Path (Join-Path $SourceDir 'PhoneGate.exe')) { Copy-Item (Join-Path $SourceDir 'PhoneGate.exe') $InstallDir -Force }
}

# Program Files is already admin-writable only; make it explicit (no inherited user write).
icacls $InstallDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null

Step "Securing data folder $DataDir (SYSTEM + Administrators only)"
New-Item -ItemType Directory -Force $DataDir | Out-Null
icacls $DataDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

Step 'Registering the PhoneGate agent service (LocalSystem, automatic, restart on failure)'
$bin = '"' + (Join-Path $InstallDir 'phonegate-agent.exe') + '"'
if (-not (Get-Service $ServiceName -ErrorAction SilentlyContinue)) {
    New-Service -Name $ServiceName -BinaryPathName $bin -DisplayName 'PhoneGate Agent' `
        -Description 'Holds the TPM identity key and relays phone approvals for the PhoneGate sign-in gate.' `
        -StartupType Automatic | Out-Null
} else {
    sc.exe config $ServiceName binPath= $bin start= auto | Out-Null
}
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
sc.exe sidtype $ServiceName unrestricted | Out-Null

Step 'Registering the credential provider and filter COM classes'
$dll = Join-Path $InstallDir 'phonegate_cp.dll'
foreach ($c in @(@{ Id = $ClsidProvider; Name = 'PhoneGate Credential Provider' }, @{ Id = $ClsidFilter; Name = 'PhoneGate Credential Provider Filter' })) {
    $k = "Registry::HKEY_CLASSES_ROOT\CLSID\$($c.Id)"
    New-Item -Force $k | Out-Null
    Set-ItemProperty $k -Name '(default)' -Value $c.Name
    New-Item -Force "$k\InprocServer32" | Out-Null
    Set-ItemProperty "$k\InprocServer32" -Name '(default)' -Value $dll
    Set-ItemProperty "$k\InprocServer32" -Name 'ThreadingModel' -Value 'Apartment'
}
New-Item -Force "$AuthKey\Credential Providers\$ClsidProvider" | Out-Null
Set-ItemProperty "$AuthKey\Credential Providers\$ClsidProvider" -Name '(default)' -Value 'PhoneGate'
New-Item -Force "$AuthKey\Credential Provider Filters\$ClsidFilter" | Out-Null
Set-ItemProperty "$AuthKey\Credential Provider Filters\$ClsidFilter" -Name '(default)' -Value 'PhoneGate'

Step 'Creating the protected backup copy and its fingerprint manifest (watchdog source)'
$BinDir = Join-Path $DataDir 'bin'
New-Item -ItemType Directory -Force $BinDir | Out-Null
$files = [ordered]@{}
foreach ($f in 'phonegate-agent.exe', 'phonegate_cp.dll') {
    Copy-Item (Join-Path $InstallDir $f) $BinDir -Force
    $files[$f] = (Get-FileHash (Join-Path $InstallDir $f) -Algorithm SHA256).Hash.ToLower()
}
# Written without a byte-order mark (Windows PowerShell's utf8 encoding would add one).
[IO.File]::WriteAllText((Join-Path $BinDir 'manifest.json'), (@{ files = $files } | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))

Step 'Registering the agent to start in Safe Mode (so it can raise the alarm there)'
foreach ($m in 'Minimal', 'Network') {
    $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$m\$ServiceName"
    New-Item -Force $k | Out-Null
    Set-ItemProperty $k -Name '(default)' -Value 'Service'
}

Step 'Registering the PhoneGate Watchdog (SYSTEM, at startup and every 5 minutes)'
$TaskName = 'PhoneGate Watchdog'
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
$action   = New-ScheduledTaskAction -Execute (Join-Path $BinDir 'phonegate-agent.exe') -Argument '--watchdog'
$triggers = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5))
)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings `
    -Description 'Restores PhoneGate if it is stopped or removed, and reports every repair to your phone.' | Out-Null

Step 'Starting the agent'
Start-Service $ServiceName

Step 'Checking the security posture'
$warnings = @()
try {
    $bl = (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus
    if ("$bl" -ne 'On') { $warnings += 'BitLocker is OFF: someone with physical access could remove PhoneGate offline. Turn on BitLocker with a startup PIN.' }
} catch { $warnings += 'Could not read BitLocker status.' }
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue).UEFISecureBootEnabled -ne 1) {
    $warnings += 'Secure Boot is off or unknown.'
}
$pwless = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' -ErrorAction SilentlyContinue).DevicePasswordLessBuildVersion
if ($pwless -eq 2) {
    $warnings += 'Windows is set to "only allow Windows Hello sign-in". Turn that off in Settings > Accounts > Sign-in options so the password tile (which PhoneGate wraps) is available.'
}
foreach ($w in $warnings) { Write-Warning $w }

Write-Host ''
Write-Host 'PhoneGate is installed. Protection is OFF.' -ForegroundColor Green
Write-Host 'Next: open PhoneGate (Start menu or' (Join-Path $InstallDir 'PhoneGate.exe') ') as administrator,'
Write-Host 'set your relay server, pair your phone, save your recovery codes, then turn protection on.'
if ($LogFile) { Stop-Transcript | Out-Null }

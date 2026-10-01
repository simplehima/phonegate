; PhoneGate setup wizard (Inno Setup 6). Built by windows\installer\build-installer.ps1, which
; stages every file under dist\installer\stage and passes /DStage, /DOutDir and /DAppVersion.
;
; The heavy lifting (service, sign-in tile, watchdog, Safe Mode registration, ACLs) is done by
; the same tested scripts used for manual installs: scripts\install.ps1 / scripts\uninstall.ps1.
; Protection is always left OFF by setup.

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef Stage
  #define Stage "..\..\dist\installer\stage"
#endif
#ifndef OutDir
  #define OutDir "..\..\dist\installer"
#endif

[Setup]
AppId={{d4242890-754a-4a35-aec4-12951c8544be}
AppName=PhoneGate
AppVersion={#AppVersion}
AppVerName=PhoneGate {#AppVersion}
AppPublisher=PhoneGate contributors
AppPublisherURL=https://github.com/simplehima/phonegate
AppSupportURL=https://github.com/simplehima/phonegate/issues
; The scripts and the credential provider registration expect this exact location.
DefaultDirName={commonpf64}\PhoneGate
DisableDirPage=yes
DisableProgramGroupPage=yes
DefaultGroupName=PhoneGate
PrivilegesRequired=admin
; The sign-in component is x64 code loaded by LogonUI: x64 Windows only (not ARM64).
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
; Windows 10 22H2 (build 19045) or newer.
MinVersion=10.0.19045
LicenseFile={#Stage}\LICENSE.txt
InfoBeforeFile=before-install.txt
WizardStyle=modern
WizardImageFile=art\wizard-side@1x.bmp,art\wizard-side@2x.bmp
WizardSmallImageFile=art\wizard-header@1x.bmp,art\wizard-header@2x.bmp
SetupIconFile=..\companion\src-tauri\icons\icon.ico
UninstallDisplayIcon={app}\PhoneGate.exe
UninstallDisplayName=PhoneGate
CloseApplications=yes
RestartApplications=no
Compression=lzma2/max
SolidCompression=yes
OutputDir={#OutDir}
OutputBaseFilename=PhoneGate-Setup-{#AppVersion}
OutputManifestFile=PhoneGate-Setup-manifest.txt
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=This will install PhoneGate {#AppVersion} on your computer.%n%nPhoneGate keeps this PC locked until you approve each unlock on your Android phone.%n%nThe phone app is included: setup shows you where it is at the end.
FinishedLabel=PhoneGate is installed. Protection is still OFF.%n%nNext: copy the phone app to your Android phone, then open PhoneGate here to pair your phone, save your recovery codes, and turn protection on.

[Files]
Source: "{#Stage}\phonegate-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
; LogonUI keeps this DLL loaded: replace it at the next restart when it is in use.
Source: "{#Stage}\phonegate_cp.dll"; DestDir: "{app}"; Flags: ignoreversion restartreplace uninsrestartdelete
Source: "{#Stage}\PhoneGate.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Stage}\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Stage}\scripts\install.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "{#Stage}\scripts\uninstall.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "{#Stage}\Android\PhoneGate.apk"; DestDir: "{app}\Android"; Flags: ignoreversion
Source: "{#Stage}\Android\PhoneGate.apk.json"; DestDir: "{app}\Android"; Flags: ignoreversion
Source: "{#Stage}\Android\How to install on your phone.txt"; DestDir: "{app}\Android"; Flags: ignoreversion

[Tasks]
; Offered on the "Select Additional Tasks" page, checked by default.
Name: "restorepoint"; Description: "Create a Windows System Restore point first (strongly recommended)"; GroupDescription: "Safety net:"

[Icons]
Name: "{autoprograms}\PhoneGate"; Filename: "{app}\PhoneGate.exe"; Comment: "Pair your phone and manage PhoneGate"
Name: "{autoprograms}\PhoneGate phone app (APK)"; Filename: "{app}\Android"; Comment: "The PhoneGate app to copy to your Android phone"

[Run]
Filename: "{app}\PhoneGate.exe"; Description: "Open PhoneGate to pair your phone"; Flags: postinstall nowait skipifsilent shellexec
Filename: "{win}\explorer.exe"; Parameters: "/select,""{app}\Android\PhoneGate.apk"""; Description: "Show the phone app (PhoneGate.apk) so you can copy it to your phone"; Flags: postinstall nowait skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\uninstall.ps1"" -KeepFiles"; RunOnceId: "PhoneGateUnregister"; Flags: runhidden waituntilterminated

[Code]
const
  ServiceName = 'PhoneGateAgent';
  TaskName = 'PhoneGate Watchdog';

function PowerShell: String;
begin
  Result := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
end;

function StatePath: String;
begin
  Result := ExpandConstant('{commonappdata}\PhoneGate\state.json');
end;

{ True when state.json says protection is on. A present but unreadable file counts as on
  (fail-secure), matching the credential provider's own rule. }
function ProtectionIsOn: Boolean;
var
  S: AnsiString;
  T: String;
begin
  Result := False;
  if not FileExists(StatePath) then Exit;
  if not LoadStringFromFile(StatePath, S) then begin
    Result := True;
    Exit;
  end;
  T := String(S);
  StringChangeEx(T, ' ', '', True);
  StringChangeEx(T, #9, '', True);
  StringChangeEx(T, #13, '', True);
  StringChangeEx(T, #10, '', True);
  Result := (Pos('"enforce":true', T) > 0) or (Pos('"enforce":false', T) = 0);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
  Ps, Script: String;
begin
  Result := '';
  { A System Restore point, before anything is installed. It is what let the owner recover a
    bad install by hand once; offer it up front. Never block the install if it can't be made. }
  if WizardIsTaskSelected('restorepoint') then begin
    WizardForm.StatusLabel.Caption := 'Creating a System Restore point...';
    Ps := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
    { Enable protection on the system drive, lift the once-per-24h throttle for this one point,
      then create it. All best-effort. }
    Script :=
      'try {' +
      '  Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue;' +
      '  New-ItemProperty -Path ''HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'' -Name SystemRestorePointCreationFrequency -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;' +
      '  Checkpoint-Computer -Description "Before installing PhoneGate" -RestorePointType "APPLICATION_INSTALL";' +
      '} catch {}';
    Exec(Ps, '-NoProfile -ExecutionPolicy Bypass -Command "' + Script + '"', '', SW_HIDE, ewWaitUntilTerminated, Code);
  end;
  { Upgrade: pause the watchdog so it doesn't restore old files mid-copy, then stop the
    service so its executable can be replaced. install.ps1 re-registers and restarts both.
    The phone will report that PhoneGate was stopped; that's expected during an update. }
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/Change /TN "' + TaskName + '" /DISABLE', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop ' + ServiceName, '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(2000);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
  Log: String;
begin
  if CurStep = ssPostInstall then begin
    Log := ExpandConstant('{app}\install-log.txt');
    WizardForm.StatusLabel.Caption := 'Registering the PhoneGate service, sign-in tile and watchdog...';
    if not Exec(PowerShell,
        '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\scripts\install.ps1') +
        '" -SourceDir "' + ExpandConstant('{app}') + '" -LogFile "' + Log + '"',
        '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
      MsgBox('PhoneGate''s files were copied, but registering the service or sign-in tile failed.' + #13#10#13#10 +
        'Protection is OFF, so signing in works as before.' + #13#10 +
        'Details are in:' + #13#10 + Log + #13#10#13#10 +
        'You can retry by running setup again.', mbError, MB_OK);
  end;
end;

function InitializeUninstall: Boolean;
begin
  Result := True;
  if ProtectionIsOn then begin
    MsgBox('PhoneGate protection is ON, so it can''t be uninstalled yet.' + #13#10#13#10 +
      'Open PhoneGate and choose "Turn off protection". You''ll need to approve on your phone or ' +
      'use a recovery code. Then uninstall again.', mbError, MB_OK);
    Result := False;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    if MsgBox('Also delete PhoneGate''s data on this PC (pairing, recovery-code fingerprints and history)?' + #13#10#13#10 +
        'Choose No to keep it for a later reinstall.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(ExpandConstant('{commonappdata}\PhoneGate'), True, True, True);
end;

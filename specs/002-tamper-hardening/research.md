# Research: Tamper Alarm & Hardening

## H1. Detection beats prevention against a local administrator
- **Decision**: Build detection first: signed status reports and lifecycle notices to the phone,
  with the silence alarm evaluated **on the phone**. Repair is added (watchdog) as a convenience,
  and every repair is reported.
- **Rationale**: Windows has no mechanism that lets a third-party, open-source service refuse an
  administrator. Protected Process Light for services needs a Microsoft-signed antimalware (ELAM)
  driver. Anything else on the machine (services, tasks, ACLs) can be undone by an admin.
  Evaluating silence on the phone means the attacker cannot suppress the alarm by controlling
  the PC or the relay. Silence *is* the signal.
- **Rejected**: Service DACL tricks or a hidden watchdog presented as prevention. That would be
  security theater (Constitution V: honest limits).

## H2. Telling tampering apart from normal power events
- **Decision**: The agent accepts STOP, SHUTDOWN, PRESHUTDOWN and POWEREVENT service controls.
  It sends one notice per event:
  - **STOP** → `agent-stopped` (alarm).
  - **SHUTDOWN / PRESHUTDOWN** → `shutdown`.
  - **Suspend** → `sleep`.
  - **Resume** → `resume`.
  The phone suppresses the silence alarm after `shutdown` or `sleep` until the next report.
- **Kill without notice** (TerminateProcess, deletion): no notice arrives. The phone raises the
  silence alarm after 20 minutes, which is 4 missed reports.
- **Delivery**: notices are sent best-effort within 3 s before the stop completes, and are also
  persisted to the pending-notice queue in `recovery.json`, so they are delivered on the next start
  if the relay was unreachable.

## H3. Status report integrity
- **Decision**: add a new sealed kind `status` (protocol §4.1).
  - It carries a sequence number that increases monotonically and is persisted in `state.json`.
    The phone rejects any report whose sequence is not higher than the last one it accepted.
  - All integrity fields are probed live each time, never cached from configuration.
- **Rationale**: the envelope already provides authenticity and confidentiality. The sequence
  number adds ordering, so a relay cannot replay an old "all good" report after tampering.

## H4. Watchdog
- **Decision**: a scheduled task "PhoneGate Watchdog" running as SYSTEM. It runs at startup and
  every 5 minutes, and executes `phonegate-agent.exe --watchdog`. Its logic is split in two:
  - a pure `plan(observed) -> actions` function, which is unit-tested;
  - a Windows executor that carries out the actions.
- **Protected copy**: `%ProgramData%\PhoneGate\bin\` holds the agent exe, the CP DLL and
  `manifest.json` with each file's SHA-256. The installer writes it; the ACL allows only SYSTEM and
  Administrators. The watchdog restores files only when the backup still matches the manifest.
- **Replacing an in-use DLL**: LogonUI may have the DLL loaded. The watchdog renames the file first
  (rename works on in-use files), copies the backup into place, and schedules the old copy for
  deletion on reboot.
- **Rate limit**: at most one report per item per hour, tracked in `watchdog.json`.
- **Safe Mode**: add registry keys
  `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\{Minimal,Network}\PhoneGateAgent` = `Service` so
  the agent starts in Safe Mode. The agent detects a clean boot (`GetSystemMetrics(SM_CLEANBOOT)`)
  and queues a `safe-mode-boot` notice. Third-party credential providers still do not load in
  Safe Mode; this is documented.

## H5. BitLocker helper
- **Decision**: agent control ops running as SYSTEM, using the BitLocker PowerShell module:
  1. Allow startup PINs. Set policy `HKLM\SOFTWARE\Policies\Microsoft\FVE`:
     - `UseAdvancedStartup=1`
     - `UseTPM=2`, `UseTPMPIN=2`, `UseTPMKey=2`, `UseTPMKeyPIN=2`
     - `EnableBDEWithNoTPM=0`
  2. `Add-BitLockerKeyProtector -RecoveryPasswordProtector` creates a recovery password. It is shown
     once, and its last 6 digits must be typed back.
  3. Then either:
     - `Enable-BitLocker -TpmAndPinProtector -Pin <SecureString> -EncryptionMethod XtsAes256 -UsedSpaceOnly`, or
     - when the drive is already encrypted with TPM only: `Add-BitLockerKeyProtector -TpmAndPinProtector`,
       then remove the TPM-only protector.
- **PIN handling**: the PIN goes to PowerShell over **stdin**, never on the command line. It is
  zeroized in the agent and never logged.
- **Edition check**: `Get-Command Get-BitLockerVolume` fails on Home editions. The helper then
  points to Settings > Privacy & security > Device encryption instead.
- **Testing**: the script builders and output parsers are unit-tested. A real run is a VM-only step
  (quickstart). It is never run on a developer machine.

## H6. Blocking network sign-ins
- **Decision**: grant `SeDenyNetworkLogonRight` to the well-known SID **S-1-5-113 (NT AUTHORITY\Local
  account)** through the LSA API (`LsaOpenPolicy`, `LsaAddAccountRights` / `LsaRemoveAccountRights`,
  `LsaEnumerateAccountRights`). This follows Microsoft's security baseline guidance for
  standalone PCs.
- **Side effects**, shown in the UI before confirming:
  - inbound file sharing (SMB) stops working with local accounts;
  - so do remote PowerShell and WinRM;
  - Remote Desktop with Network Level Authentication fails for local accounts, because NLA needs a
    network logon.
- **Approval**: weakening the setting (unblocking) while protection is on needs a phone approval
  or a recovery code. It uses a new scenario, `change-setting`, which the phone shows as "Change a
  security setting" with the setting name in the account field.

## H7. Phone health model
- Per PC the phone stores `last_seen_at` (phone clock), `last_seq`, `last_status`, `last_lifecycle`
  and `alert`.
- A 1-minute ticker in the foreground relay service evaluates silence:
  `now − last_seen > 20 min` **and** `last_lifecycle ∉ {shutdown, sleep}` → one alert, which is not
  repeated until a new report arrives.
- **States**:
  - OK (report within 20 min, integrity fine);
  - Asleep / Off (last lifecycle event);
  - Stopped reporting (silence alarm);
  - Tamper alert: integrity broken while enforcing, protection turned off with no
    `protection-disabled` notice in the previous 10 min, `agent-stopped`, `repaired`, or
    `safe-mode-boot`.

# Installing on Windows

**Needs:** 64-bit Windows 10 22H2 or Windows 11 (not ARM), and an administrator account.

1. Download `PhoneGate-Setup-<version>.exe` and `SHA256SUMS.txt` from
   [Releases](https://github.com/simplehima/phonegate/releases).
2. Check the file before running it, in PowerShell:
   ```powershell
   Get-FileHash .\PhoneGate-Setup-0.1.0.exe   # must match SHA256SUMS.txt
   ```
3. Run it. The setup isn't code-signed yet, so SmartScreen may say *Windows protected your PC*.
   Choose **More info → Run anyway**, but only if the hash matched.
4. Follow the wizard: Welcome → License → Information (read this before installing) → Install → Finish.
5. On the last page, tick **Show the phone app** (see [Installing the phone app](Installing-the-phone-app.md))
   and **Open PhoneGate**.

After setup, **protection is still off**: nothing changes at the lock screen until you pair your
phone and turn protection on. See [Pairing and first unlock](Pairing-and-first-unlock.md).

## What gets installed

| Where | What |
|---|---|
| `C:\Program Files\PhoneGate\` | the agent service, the sign-in component, the PhoneGate app, the phone app (`Android\PhoneGate.apk`) |
| `C:\ProgramData\PhoneGate\` | pairing and settings (SYSTEM and Administrators only), a protected backup copy used by the watchdog |
| Services | **PhoneGate Agent** (automatic, restarts on failure) |
| Task Scheduler | **PhoneGate Watchdog** (SYSTEM, at startup and every 5 minutes) |

## Updating and uninstalling

- **Update:** run the newer setup over the old one. Your pairing, recovery codes and history are
  kept. Your phone will report that PhoneGate was stopped during the update; that's expected.
- **Uninstall:** Settings → Apps → PhoneGate. This is refused while protection is on. Turn
  protection off in the app first, using your phone's approval or a recovery code.

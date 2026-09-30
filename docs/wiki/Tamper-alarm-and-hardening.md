# Tamper alarm and hardening

Nobody can stop an administrator of a PC from removing software. What PhoneGate guarantees is that
**it can't happen silently**.

- **Status reports:** every 5 minutes, and at once on any change, the PC sends the phone a signed,
  encrypted report. It covers whether protection is on, the sign-in tile and filter, the program
  files, the watchdog, drive encryption and Safe Mode.
- **Alerts:** the phone alerts you when:
  - PhoneGate is stopped;
  - its files or registration are damaged;
  - protection is turned off without your approval;
  - the PC boots into Safe Mode;
  - the watchdog repaired something;
  - no report arrives for 20 minutes.

  Normal sleep and shutdown don't trigger an alert.
- **Watchdog:** a SYSTEM task that restores the service, registration and files from a
  fingerprint-checked backup, and reports each repair.

## Hardening options (PC app → Hardening)

- **BitLocker with a startup PIN:** a guided setup. The recovery key is shown once and you type
  its last 6 digits back. Strongly recommended: without disk encryption, someone with physical
  access could remove PhoneGate offline.
- **Block network sign-ins:** stops anyone signing in over the network with just your password.
  That covers file sharing, remote PowerShell, and Remote Desktop with NLA. Those features stop
  working for local accounts while the block is on. Turning the block off while protection is on
  needs your phone.

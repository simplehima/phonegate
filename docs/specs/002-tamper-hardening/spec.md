# Feature Specification: Tamper Alarm & Hardening

**Feature Branch**: `002-tamper-hardening`

**Created**: 2026-09-27

**Status**: Draft

**Input**: User description: "PhoneGate hardening: (1) Tamper alarm — signed, encrypted heartbeat from the PC to the phone carrying integrity status; the phone alerts on unexpected silence, broken integrity, protection changes without approval, the agent being stopped (vs normal shutdown/sleep), watchdog repairs, and Safe Mode boots. (2) BitLocker + startup PIN helper with recovery key shown once and confirmed; phone warns while encryption is off. (3) Optional policy that blocks network logons for local accounts, with honest warnings. (4) Watchdog that restarts the service and restores the credential provider and binaries from a protected backup, reporting every repair; the agent runs in Safe Mode to raise the alarm there. An administrator can still defeat this; the goal is that it cannot happen silently."

## Clarifications

### Session 2026-09-27

- Q: Which hardening features should be built? → A: All four: tamper alarm, BitLocker + PIN helper, block network logons, watchdog + Safe Mode registration.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - I'm told when someone tampers with PhoneGate (Priority: P1)

Someone with admin rights stops the PhoneGate service, deletes its files, removes its sign-in
tile, or turns protection off without my approval. Within minutes my phone shows an alert naming
the PC and what happened. Normal shutdowns, restarts and sleep do **not** alarm me.

**Why this priority**: An attacker with admin rights can defeat any software on the machine. The
realistic defense is that it cannot happen silently.

**Independent Test**: With a paired PC, stop the service. The phone alerts "PhoneGate was
stopped". Put the PC to sleep: no alarm. Kill the process abruptly: the phone alerts after the
silence window.

**Acceptance Scenarios**:

1. **Given** a paired PC, **When** the PhoneGate service is stopped by someone, **Then** the phone
   shows a tamper alert within 1 minute (if the phone is online).
2. **Given** a paired PC, **When** the PC shuts down, restarts or sleeps normally, **Then** no
   alert is shown. The PC card shows "Asleep" or "Off" with a time.
3. **Given** a paired PC, **When** the agent disappears without a word (killed or deleted),
   **Then** the phone alerts once no status has arrived for 20 minutes.
4. **Given** protection is on, **When** a status report shows the sign-in tile or filter
   unregistered, or protection off without an approved disable, **Then** the phone alerts
   immediately.
5. **Given** the PC was started in Safe Mode, **When** the phone learns of it (at once with
   networking, otherwise on the next normal start), **Then** it shows a Safe Mode alert with the
   time.
6. **Given** a status message altered, replayed or forged by the relay, **Then** the phone
   discards it and never shows forged "all is well" information.

---

### User Story 2 - PhoneGate repairs itself and tells me (Priority: P1)

If PhoneGate's files, sign-in registration or service are removed or stopped, it restores
itself within 5 minutes from a protected copy, and my phone records "Repaired: …".

**Why this priority**: It turns casual or accidental removal into an event that fixes itself and
leaves a record.

**Independent Test**: Delete the sign-in tile registration and stop the service. Within 5 minutes
both are back and the phone history shows the repair.

**Acceptance Scenarios**:

1. **Given** installed, **When** the service is stopped or its registration removed, **Then**
   within 5 minutes it runs again and a repair notice reaches the phone.
2. **Given** installed, **When** the PhoneGate program files are deleted or replaced, **Then** they
   are restored from the protected copy (only if that copy is intact) and the repair is reported.
3. **Given** the owner runs the official uninstall (after turning protection off), **Then** the
   watchdog is removed first and does not fight the uninstall.

---

### User Story 3 - Turn on drive encryption with a startup PIN (Priority: P2)

The companion app shows "Drive encryption is off". I tap **Turn on BitLocker with a PIN**, choose a
PIN, and am shown a recovery key once. I type part of it back to prove I saved it. The PC asks to
restart and encrypts in the background. If BitLocker was already on without a PIN, the app adds
the PIN instead.

**Why this priority**: It closes the biggest offline hole: someone booting another OS and editing
the disk.

**Independent Test**: On a VM with a virtual TPM, run the helper. After restart, the PC asks for
the PIN before Windows starts, and the companion app shows "On, with PIN".

**Acceptance Scenarios**:

1. **Given** BitLocker is off and the edition supports it, **When** the owner completes the helper,
   **Then** the drive has a TPM+PIN protector and a recovery password, and encryption is scheduled.
2. **Given** the recovery key is shown, **When** the owner has not typed back its last 6 digits
   correctly, **Then** encryption is not started.
3. **Given** BitLocker is on with TPM only, **When** the owner completes the helper, **Then** a
   TPM+PIN protector replaces TPM-only.
4. **Given** a Windows edition without BitLocker, **Then** the helper explains that and links to
   the edition's Device Encryption settings instead.
5. **Given** drive encryption is off, **Then** the phone shows a persistent warning on that PC's
   card.

---

### User Story 4 - Stop password-only network sign-ins (Priority: P3)

I turn on **Block network sign-ins**. After that, nobody can use my password alone to reach this
PC over the network: file sharing to this PC, remote PowerShell, or Remote Desktop with network
authentication. The app warns me clearly what stops working before I confirm, and I can turn it
off again.

**Why this priority**: It closes the one sign-in path the gate cannot see, but it has side effects,
so it is opt-in.

**Independent Test**: Enable it and try `net use \\PC\c$` from another machine with correct
credentials: access is denied. Disable it: access works.

**Acceptance Scenarios**:

1. **Given** the option is off, **When** the owner enables it and confirms the warning, **Then**
   local accounts can no longer sign in over the network, and the status shows "Blocked".
2. **Given** it is on, **When** the owner disables it, **Then** the previous behavior returns.
3. **Given** protection is on, **When** someone tries to change this option, **Then** it requires
   phone approval or a recovery code, like turning protection off.

### Edge Cases

- Phone offline for hours: alerts for missed silence are computed when it reconnects, and queued
  tamper notices are delivered in order. No duplicate alarms.
- PC offline (no internet): status cannot reach the phone. After 20 minutes this reads as
  "Stopped reporting". The alert text names "no internet" as a possible cause and never claims
  certainty.
- Clock skew: silence is measured with the phone's clock, from when the phone last received a
  report.
- Relay withholds reports: that produces a (false) silence alarm, which is acceptable and
  fail-safe. It can never produce false reassurance.
- Protected backup copy itself tampered with: the watchdog does not restore from an altered copy.
  It reports "backup altered" instead.
- A watchdog repair loop, where something keeps undoing the repair: at most one notice per item
  per hour.

## Requirements *(mandatory)*

### Functional Requirements

**Status reports & alarms**

- **FR-101**: While paired, the PC MUST send the phone a status report at least every 5 minutes.
  It MUST also send one immediately on start and on any integrity change. It is end-to-end signed
  and encrypted like approval traffic.
- **FR-102**: A report MUST carry: sequence number, time, protection state, sign-in tile
  registered, filter registered, program files intact, watchdog present, drive encryption state
  (off / on without PIN / on with PIN / unknown), network sign-in block state, and Safe Mode boot
  flag.
- **FR-103**: The PC MUST send distinct notices for: normal shutdown, sleep, resume, service
  stopped by someone, agent started, watchdog repair (what was repaired), Safe Mode boot, and a
  protection or setting change.
- **FR-104**: The phone MUST alert (high priority) on: service stopped by someone; an integrity
  failure while protection is on; protection turned off without a matching approved disable;
  Safe Mode boot; watchdog repair; and no report for 20 minutes unless the last notice was a
  shutdown or sleep.
- **FR-105**: The phone MUST reject reports with lower or equal sequence numbers, and anything
  failing verification.
- **FR-106**: Each PC card on the phone MUST show last-seen time and current state (OK, Asleep,
  Off, Stopped reporting, Tamper alert), plus drive-encryption and network-sign-in warnings.

**Watchdog**

- **FR-107**: A task running as SYSTEM MUST check at startup and every 5 minutes, repairing:
  - the service (exists, automatic, running, restart-on-failure);
  - the sign-in tile and filter registration;
  - the program files, which MUST match the protected copy's recorded fingerprints (SHA-256).
- **FR-108**: The protected copy MUST be writable only by SYSTEM and Administrators. Restores MUST
  happen only when the copy's fingerprints match those recorded at install time.
- **FR-109**: Every repair MUST be recorded and reported to the phone. The same item is reported
  at most once per hour.
- **FR-110**: The agent MUST be registered to run in Safe Mode (minimal and networking). When
  started in Safe Mode it MUST record a Safe Mode notice for delivery.

**Drive encryption helper**

- **FR-111**: The companion app MUST detect drive encryption state and edition support, and offer
  enable or upgrade to TPM+PIN.
- **FR-112**: The PIN MUST be 6–20 digits and entered twice. It MUST never be stored, logged or
  sent to the phone or relay.
- **FR-113**: A recovery password MUST be created and shown once. Its last 6 digits MUST be typed
  back before encryption is started.
- **FR-114**: The helper MUST set the Windows setting that permits a startup PIN, when needed.

**Network sign-in block**

- **FR-115**: The owner MUST be able to enable and disable denying network sign-in for all local
  accounts. The UI MUST list what stops working.
- **FR-116**: While protection is on, changing this setting MUST require phone approval or a
  recovery code.

### Key Entities

- **Status Report**: Sequence number, time and integrity fields, sent PC → phone.
- **Lifecycle Notice**: Shutdown, sleep, resume, stopped, started, repaired, Safe Mode, or setting
  changed.
- **Protected Copy**: Backup of PhoneGate's program files plus their recorded fingerprints.
- **Repair Record**: What was repaired, when, and whether it was reported.
- **PC Health (phone)**: Last seen time, last sequence number, last lifecycle event, and current
  alert state.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-101**: In tests, 100% of deliberate service stops, sign-in tile removals and
  protection-off-without-approval events raise a phone alert. Stops raise it within 1 minute;
  silent kills within 21 minutes.
- **SC-102**: 0 alerts across 20 normal sleep, resume, shutdown and restart cycles.
- **SC-103**: 0 forged, altered or replayed status reports accepted in adversarial tests.
- **SC-104**: A removed service or sign-in registration is restored within 5 minutes in 100% of
  tests.
- **SC-105**: A first-time user turns on BitLocker with a PIN in under 5 minutes, excluding
  encryption time.
- **SC-106**: With network sign-in blocked, remote password-only sign-in attempts fail in 100% of
  tests.

## Assumptions

- The phone keeps its persistent relay connection (feature 001). Silence is measured on the
  phone.
- Windows editions without BitLocker (Home) get guidance only.
- The network sign-in block targets local accounts, including Microsoft-account-linked local
  profiles. Domain policies are out of scope.
- An administrator can still disable everything on the machine, including the watchdog. This
  feature guarantees detection, not prevention, and says so in the UI and SECURITY.md.

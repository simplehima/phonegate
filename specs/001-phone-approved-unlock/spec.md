# Feature Specification: Phone-Approved Windows Unlock

**Feature Branch**: `001-phone-approved-unlock`

**Created**: 2026-09-25

**Status**: Draft

**Input**: User description: "PhoneGate: When anyone tries to unlock or sign in to my Windows PC, the PC stays locked until I approve the attempt from my Android phone. Three parts: a Windows desktop component (enforces the gate at the lock/logon screen, plus a companion app for pairing, status, settings, recovery codes), an Android app (receives approval requests, shows who/what/when with number matching, approve/deny with biometric, manage paired PCs), and a self-hostable relay server both communicate through. Devices pair by scanning a QR code shown on the PC. Accounts are device key pairs — no passwords. Must remain secure when fully open source and when binaries are reverse engineered: server compromise or network attacker cannot approve, read, or replay. Owner must never be permanently locked out: offline single-use recovery codes. Denied or timed-out attempts are logged and the phone can report 'this wasn't me'. Supports multiple PCs per phone. Works for lock-screen unlock, sign-in, and remote desktop sign-in."

## Clarifications

### Session 2026-09-26

- Q: Should every unlock need a phone approval, or can a recent approval be reused? → A: Every unlock; no grace window.
- Q: Which Windows accounts should the gate protect? → A: All local, Microsoft and domain accounts.
- Q: Where will the relay run? → A: Docker on a VPS with a public HTTPS domain (automatic TLS).
- Q: How is the phone woken for background requests? → A: Persistent connection from the app to the relay (ongoing notification); no third-party push.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Approve an unlock from my phone (Priority: P1)

I sit down at my locked PC and enter my Windows credentials as usual. Instead of unlocking, the PC
shows "Waiting for approval on your phone" with a two-digit number. My phone immediately shows a
request naming the PC, the Windows account, and the time. I type the number shown on the PC screen,
confirm with my fingerprint, and the PC unlocks.

**Why this priority**: This is the product. Without it nothing else has value.

**Independent Test**: With one paired PC and phone, lock the PC, attempt to unlock, approve on the
phone, and observe the PC unlocks; repeat and deny, and observe it stays locked.

**Acceptance Scenarios**:

1. **Given** a paired PC and phone, **When** the owner enters valid Windows credentials, **Then**
   the PC stays locked and the phone shows a request with PC name, account, and time within 5
   seconds.
2. **Given** a pending request, **When** the owner types the matching number and passes biometric
   check, **Then** the PC unlocks.
3. **Given** a pending request, **When** the owner taps Deny, **Then** the PC stays locked and shows
   "Request denied".
4. **Given** a pending request, **When** the owner types a non-matching number twice, **Then** the
   request is denied and flagged as suspicious.
5. **Given** a pending request, **When** no answer arrives within the request lifetime, **Then** the
   PC stays locked and shows "Request expired — try again".
6. **Given** a phone approval, **When** the Windows credentials entered were wrong, **Then** the PC
   does not unlock (the phone approval never substitutes for the Windows password).

---

### User Story 2 - Pair my phone with my PC (Priority: P1)

On first setup I open the PhoneGate companion app on my PC, which shows a QR code. I open the
PhoneGate app on my phone, scan the code, and both screens show the same short confirmation code.
I confirm on both, and the PC shows "Paired with <phone name>". The PC then gives me recovery codes
to print or save, and asks me to type one back to prove I kept them. Only then can I turn on
protection.

**Why this priority**: Required before Story 1 can work; also the moment trust is established.

**Independent Test**: Fresh install on both devices, complete pairing, verify both devices list each
other, verify recovery-code check is enforced before protection can be enabled.

**Acceptance Scenarios**:

1. **Given** an unpaired PC, **When** the owner starts pairing, **Then** a QR code valid for at most
   5 minutes is shown.
2. **Given** a scanned QR code, **When** both devices show the same confirmation code and the owner
   confirms on both, **Then** pairing completes.
3. **Given** a QR code, **When** it is expired, reused, or scanned by a second phone after pairing
   completed, **Then** pairing is refused.
4. **Given** a completed pairing, **When** the owner has not confirmed a recovery code, **Then**
   protection cannot be enabled.

---

### User Story 3 - Get back in when my phone is unavailable (Priority: P1)

My phone is dead, lost, or has no signal, or the server is down. At the lock screen I choose "Use a
recovery code", type one of my saved codes, and the PC unlocks. That code never works again. My
phone (when it's back) is told a recovery code was used.

**Why this priority**: Without it, fail-secure design would lock the owner out permanently.

**Independent Test**: Disconnect the network, unlock with a recovery code, confirm the same code is
rejected afterwards and that remaining-code count drops.

**Acceptance Scenarios**:

1. **Given** no network, **When** the owner enters valid Windows credentials and a valid unused
   recovery code, **Then** the PC unlocks without contacting any server or phone.
2. **Given** a recovery code already used, **When** it is entered again, **Then** it is rejected.
3. **Given** 5 wrong recovery codes in a row, **When** another is entered, **Then** entry is locked
   out for increasing periods (starting at 1 minute).
4. **Given** the owner is signed in, **When** they open the companion app, **Then** they can see how
   many codes remain and generate a fresh set (which invalidates the old set).

---

### User Story 4 - Report and review suspicious attempts (Priority: P2)

A request arrives that I didn't make. I tap "This wasn't me". The attempt is denied, marked
suspicious on both devices, and the PC's history shows the time, account, and kind of sign-in.
Later I can review the full history of approved, denied, expired, and recovery-code unlocks on both
the phone and the PC.

**Why this priority**: Turns a blocked attack into actionable information.

**Independent Test**: Trigger a request, tap "This wasn't me", verify the entry appears as
suspicious in both histories.

**Acceptance Scenarios**:

1. **Given** a pending request, **When** the owner taps "This wasn't me", **Then** the attempt is
   denied and recorded as suspicious on phone and PC.
2. **Given** past attempts, **When** the owner opens history, **Then** each entry shows outcome, PC,
   account, sign-in kind (unlock, sign-in, remote), and time.

---

### User Story 5 - Protect several PCs with one phone (Priority: P2)

I pair my home desktop and my laptop with the same phone. Requests clearly say which PC they came
from. I can rename or unpair a PC from the phone, and unpairing from either side stops that PC from
sending requests to the phone.

**Why this priority**: Common real-world setup; low incremental cost.

**Independent Test**: Pair two PCs, trigger a request from each, verify correct PC names; unpair one
and verify its requests are no longer accepted.

**Acceptance Scenarios**:

1. **Given** two paired PCs, **When** each sends a request, **Then** the phone labels each with the
   correct PC name.
2. **Given** a PC unpaired on the phone, **When** that PC sends a request, **Then** the phone ignores
   it and the PC falls back to recovery-code-only unlock.

---

### User Story 6 - Remote desktop sign-in is gated too (Priority: P3)

Someone signs in to my PC over Remote Desktop with correct credentials. The session does not open
until I approve on my phone, and the request is labeled "Remote sign-in".

**Why this priority**: Closes an obvious bypass, but many home users never enable remote desktop.

**Independent Test**: Enable remote desktop, sign in remotely, verify a "Remote sign-in" request
arrives and the session only opens after approval.

**Acceptance Scenarios**:

1. **Given** remote desktop is enabled, **When** a remote sign-in with valid credentials occurs,
   **Then** the phone gets a request labeled "Remote sign-in" and the session opens only on approval.

---

### Edge Cases

- Phone clock or PC clock is wrong by minutes: requests still work within a bounded tolerance
  (±5 minutes); beyond that the request is refused with a clear clock error.
- Two unlock attempts in quick succession: only the newest request is valid; the older one is
  cancelled on the phone.
- A captured old approval is re-sent by an attacker: it is rejected.
- The relay server is replaced by an attacker's server: it cannot produce an approval, cannot read
  request details, and pairing cannot be hijacked without the owner seeing a mismatched
  confirmation code.
- New fingerprint enrolled on the phone: the phone's approval key stops working and the phone must
  be re-paired (the owner is told why).
- Phone app reinstalled or phone reset: previous pairing is gone; owner uses a recovery code and
  re-pairs.
- PC has no hardware security chip: setup warns that keys are software-protected and continues
  only with explicit acknowledgement.
- Drive encryption is off: setup warns that a person with physical access could remove protection
  offline, and links to how to turn it on.
- Many requests spammed by someone who knows the password: the phone groups them, and after 3
  unanswered/denied requests in 5 minutes the PC imposes a cool-down before sending another.
- The protection component itself fails to load: the PC must not silently fall back to
  unprotected sign-in while protection is enabled.

## Requirements *(mandatory)*

### Functional Requirements

**Enforcement (PC)**

- **FR-001**: The PC MUST require a valid phone approval (or a valid recovery code) in addition to
  valid Windows credentials for: lock-screen unlock, interactive sign-in, and remote desktop sign-in,
  for every local and domain account on the PC while protection is enabled.
- **FR-002**: While protection is enabled, all other sign-in options (password, PIN, face,
  fingerprint, security key tiles) MUST be routed through the gate; none may bypass it.
- **FR-002a**: Credential prompts that applications open inside an already signed-in session (e.g.
  "enter your password to continue") are out of scope and MUST NOT be blocked. Sign-in to Safe Mode
  MUST also be gated where Windows allows it, with the limitation documented.
- **FR-003**: Any failure (no network, server error, malformed or unverifiable response, timeout,
  unpaired phone) MUST result in the PC staying locked.
- **FR-004**: The PC MUST display a number-match value and the request status (waiting, approved,
  denied, expired, error) with a way to cancel and retry.
- **FR-005**: A request MUST expire no later than 60 seconds after creation.
- **FR-005a**: Every unlock and sign-in MUST require a fresh approval; there is no "remember me"
  or grace window.
- **FR-006**: The PC MUST accept each approval exactly once and only for the request it issued.

**Pairing & identity**

- **FR-007**: Each device MUST create its own identity keys locally; private keys MUST never leave
  the device and MUST be held in the device's hardware security module where available.
- **FR-008**: Pairing MUST happen by the phone scanning a QR code displayed on the PC, and both
  devices MUST display a matching confirmation code that the owner confirms before pairing completes.
- **FR-009**: Pairing QR codes MUST be single-use and expire within 5 minutes.
- **FR-010**: The relay server MUST identify devices only by public keys; there are no usernames or
  passwords.
- **FR-011**: A phone MUST be able to pair with multiple PCs; a PC MUST pair with exactly one phone
  at a time (re-pairing replaces the previous phone).
- **FR-011a**: At pairing the PC MUST verify that the phone's approval key is hardware-protected and
  requires biometric per use (hardware attestation); if not verifiable, the owner is warned and must
  explicitly accept a weaker pairing.
- **FR-012**: Either device MUST be able to unpair; after unpairing, the other side MUST reject
  messages from the removed device.

**Approval (phone)**

- **FR-013**: The phone MUST show an incoming request within 5 seconds of creation when online,
  including when the app is in the background or the screen is off.
- **FR-014**: The request screen MUST show PC name, Windows account name, sign-in kind, time, and
  an entry field for the number shown on the PC (no pick-list, so the number cannot be guessed).
- **FR-015**: Approving MUST require the owner to type the matching number and pass a strong
  biometric or device-credential check on every approval.
- **FR-016**: The phone MUST verify each request came from a paired PC and is not expired or
  replayed before showing it; invalid requests are discarded and not shown.
- **FR-017**: Deny and "This wasn't me" MUST be available on the request screen and in the
  notification without biometric checks.

**Security properties**

- **FR-018**: Request and response contents MUST be readable only by the two paired devices; the
  relay server sees only opaque data plus routing metadata.
- **FR-019**: A party controlling the relay server or network MUST NOT be able to create an accepted
  approval, alter a request's displayed details, or replay an old approval.
- **FR-020**: The published source code, build files, and binaries MUST contain no secret that
  grants any approval ability.
- **FR-021**: The relay MUST rate-limit per device and per network address and reject oversized
  messages.

**Recovery**

- **FR-022**: At pairing the PC MUST generate 10 single-use recovery codes, each with at least 128
  bits of entropy, shown once, stored on the PC only in a non-reversible form.
- **FR-023**: Protection MUST NOT be enabled until the owner types back one recovery code correctly.
- **FR-024**: Recovery codes MUST work fully offline and MUST be rate-limited with escalating
  lockout after 5 consecutive failures.
- **FR-025**: Using a recovery code MUST be recorded and reported to the phone when next reachable.
- **FR-026**: The owner MUST be able to regenerate codes from the companion app, invalidating the
  previous set.
- **FR-026a**: When the PC cannot reach the relay, the lock screen MUST offer an offline phone
  approval: the PC shows a QR challenge, the phone (after biometric check) shows a short response
  code the owner types on the PC. Single-use, expires in 60 seconds, rate-limited.

**History & management**

- **FR-027**: Both PC and phone MUST keep a history of attempts (approved, denied, suspicious,
  expired, recovery-code) with PC, account, sign-in kind, and time, for at least 90 days.
- **FR-028**: The companion app MUST show: pairing status, phone name, server reachability,
  protection on/off, remaining recovery codes, security warnings (no drive encryption, no hardware
  key storage), and history.
- **FR-029**: Turning protection off MUST itself require phone approval or a recovery code.
- **FR-030**: The relay server MUST be self-hostable on a VPS with a single documented command
  (container-based, with automatic HTTPS certificates for the owner's domain) and no third-party
  account required.

**Accessibility**

- **FR-031**: Phone and PC interfaces MUST support screen readers, system font scaling, light and
  dark themes, and minimum touch target sizes, meeting WCAG 2.2 AA.

### Key Entities

- **PC Identity**: A protected PC; has a display name, public keys, the one paired phone's public
  key, protection state, recovery-code verifiers, and attempt history.
- **Phone Identity**: The owner's phone; has a display name, public keys, a list of paired PCs with
  their public keys and names.
- **Pairing Session**: Short-lived offer created by a PC and shown as a QR code; single-use.
- **Approval Request**: Created by a PC for one sign-in attempt; has id, PC, account, sign-in kind,
  created/expiry time, number-match value, and one-time random value.
- **Approval Response**: Created by the phone for one request; outcome (approve, deny, not-me) bound
  to that exact request.
- **Recovery Code Set**: 10 single-use codes tied to one PC; tracks used/remaining and failures.
- **Attempt Record**: One history entry with outcome, context, and time.
- **Relay Mailbox**: Server-side routing slot per device public key holding opaque messages briefly.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: With both devices online, an owner completes an unlock (credentials → approval →
  desktop) in under 15 seconds in 95% of attempts.
- **SC-002**: Pairing a new PC and phone, including saving recovery codes, takes under 3 minutes
  for a first-time user.
- **SC-003**: In adversarial testing with full source code, a controlled relay server, and network
  access, 0 forged, altered, or replayed approvals are accepted.
- **SC-004**: With network or server down, the owner regains access with a recovery code in under
  1 minute, in 100% of tests.
- **SC-005**: While protection is enabled, 0 of the tested sign-in paths (lock screen password,
  PIN, face/fingerprint, sign-in after reboot, remote desktop, switch user) bypass the gate.
- **SC-006**: A search of the repository and built binaries finds 0 embedded secrets.
- **SC-007**: 9 of 10 test users correctly deny a request whose number does not match the PC screen.
- **SC-008**: The relay server handles 1,000 connected devices on a small single-core host with
  request delivery under 2 seconds.

## Assumptions

- The owner has an Android phone with a screen lock and fingerprint or face unlock (Android 11 or
  newer).
- The PC runs Windows 10 (22H2) or Windows 11, and the owner can install software as administrator.
- The owner self-hosts the relay server on a VPS with a domain name, reachable by both devices over
  the internet (the relay is trusted for availability only).
- Phone approval is an additional factor; the Windows password is still required (the phone does
  not replace it).
- Protection applies to all accounts on the PC; the paired phone's owner approves all of them.
- Safe Mode, offline disk access, and physical hardware attacks cannot be fully prevented by
  software; setup requires acknowledging these risks and strongly recommends drive encryption with
  a startup PIN. Documented in the project's security notes.
- Background request delivery uses a persistent connection from the phone app to the relay
  (visible as an ongoing notification); no third-party push service is used.
- Remote desktop is off by default on most home PCs; when enabled it is gated (Story 6).
- History retention default is 90 days on each device; the relay keeps no history beyond delivery.

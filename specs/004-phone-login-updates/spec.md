# Feature Specification: Phone Sign-in, Phone Disable, Update Checks, Restore Point

**Feature Branch**: `004-phone-login-updates`

**Created**: 2026-10-01

**Status**: Draft

**Input**: "allow option to login with phone like microsoft authenticator and allow option to
disengage the protection using phone app; update the version and push to git; add check for update
for both app and exe using git release; on setup ask user for taking a system restore point."

## Clarifications

### Session 2026-10-01

- Q: How should "sign in with your phone" work? → A: Owner picks per PC. Default stays password +
  phone; passwordless is an explicit opt-in for a chosen PC, with a clear warning.
- Q: Where to push and publish releases? → A: Public repo `simplehima/phonegate`; update checks
  read its public GitHub Releases.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Sign in with just my phone (opt-in, per PC) (Priority: P1)

On a PC I choose, I turn on "Sign in with my phone" in the companion. It warns me what this means,
asks for my Windows password once to store it safely, and asks me to approve the change on my
phone. After that, at the lock screen I pick the PhoneGate tile, it shows a number, I type that
number on my phone and approve with my fingerprint, and Windows signs in **without me typing my
password**.

**Why this priority**: This is the headline request: phone-as-login, like an authenticator.

**Independent Test**: Opt a PC in (simulated), lock it, approve on the phone, and confirm the
stored credential is released only after a verified approval; a denied or absent approval releases
nothing.

**Acceptance Scenarios**:

1. **Given** passwordless is on for this PC, **When** the owner approves with the matching number,
   **Then** the PC signs in without a typed password.
2. **Given** passwordless is on, **When** the approval is denied, times out, or the relay is down,
   **Then** no credential is released and the PC stays locked (recovery code still works).
3. **Given** passwordless is off (the default), **When** the owner signs in, **Then** the behavior
   is unchanged: password **and** phone approval are both required.
4. **Given** the owner turns passwordless off, **Then** the stored password is wiped and sign-in
   returns to password + phone.
5. **Given** the stored password is wrong (changed in Windows later), **When** passwordless is
   used, **Then** Windows rejects it and the tile offers to re-enter the password or use a
   recovery code — never a lockout.

---

### User Story 2 - Turn off protection from my phone (Priority: P1)

From the phone app, on a paired PC's card, I tap "Turn off protection". It asks for my fingerprint,
and the PC disables protection within a few seconds. If the PC is offline it shows as pending and
applies when the PC reconnects.

**Why this priority**: Today disable must be started at the PC; the owner wants to do it from the
phone, especially useful when locked out of a convenient path.

**Independent Test**: Send a phone-signed disable command through the relay; the PC verifies the
approve-key signature and freshness, disables, and reports it; a replayed or unsigned command is
rejected.

**Acceptance Scenarios**:

1. **Given** a paired PC with protection on, **When** the owner confirms "Turn off protection" with
   biometric on the phone, **Then** the PC disables protection and both devices log it.
2. **Given** a captured disable command, **When** it is replayed, **Then** the PC ignores it.
3. **Given** a disable command signed by anything other than this PC's paired approve key, **Then**
   the PC ignores it.
4. **Given** protection is already off, **When** a disable command arrives, **Then** it is a no-op.

---

### User Story 3 - Be told when an update is available (Priority: P2)

Both apps check for a newer release and tell me, without auto-installing. The companion shows
"Update available (v0.3.0)" with a button to open the releases page. The phone app shows the same
on its main screen. I can turn the check off.

**Why this priority**: PhoneGate isn't on a store; owners need to know about security fixes.

**Independent Test**: Point the check at a releases feed reporting a higher version and confirm the
banner appears; equal or lower reports nothing; a network error is silent.

**Acceptance Scenarios**:

1. **Given** the latest release is newer than the running version, **Then** each app shows an
   update banner linking to the release page.
2. **Given** the latest release equals or is older than the running version, **Then** no banner.
3. **Given** the update check fails (offline, rate-limited), **Then** nothing is shown and the app
   works normally.
4. **Given** the owner turned the check off, **Then** neither app contacts GitHub.

---

### User Story 4 - Setup offers a System Restore point (Priority: P1)

The setup wizard, before installing, offers to create a Windows System Restore point (checked by
default). If I leave it on, it creates one so I can roll back exactly like I had to do by hand.

**Why this priority**: A restore point is what saved the owner last time. Offer it up front.

**Independent Test**: Run setup with the box checked on a PC with System Protection on; a restore
point named for PhoneGate appears. With it off, none is created.

**Acceptance Scenarios**:

1. **Given** the box is checked and System Protection is on, **When** setup proceeds, **Then** a
   restore point "Before installing PhoneGate" is created before any file is installed.
2. **Given** System Protection is off, **When** the box is checked, **Then** setup tries to enable
   it on the system drive, and if it still cannot, explains that and continues (install not
   blocked).
3. **Given** Windows throttles restore points (one per 24h), **When** one was just made, **Then**
   setup notes the existing recent point and continues.
4. **Given** the box is unchecked, **Then** no restore point is attempted.

---

### User Story 5 - Publish the project and releases (Priority: P2)

The code is on GitHub at `simplehima/phonegate`, and each tagged release carries the setup `.exe`,
the `.apk`, and `SHA256SUMS.txt`, so the update checks and downloads work.

**Acceptance Scenarios**:

1. **Given** all gates pass, **When** the maintainer publishes, **Then** `v0.2.0` exists with the
   setup, APK and hashes attached, and the repo is public with no secrets.

### Edge Cases

- Passwordless + the owner changes their Windows password later: the stored one no longer works;
  Windows rejects it; the tile falls back to asking for the password (and offers recovery). Never a
  lockout. The companion offers "update my stored password".
- Passwordless opt-in started but the phone never approves: nothing is stored/armed; the password
  the owner typed is discarded.
- Phone disable while the PC is offline: queued by the relay (short TTL) and applied on reconnect;
  if it expires, nothing happens and the phone shows it didn't go through.
- Update check must never block app startup or sign-in, and never sends anything but a plain GET.

## Requirements *(mandatory)*

**Phone sign-in (passwordless, opt-in, per PC)**

- **FR-401**: Passwordless sign-in MUST be off by default and enabled per PC only by an explicit
  opt-in that (a) warns what it changes, (b) collects the Windows password once, and (c) requires a
  phone approval to arm.
- **FR-402**: The stored password MUST be wrapped by the PC's TPM (or DPAPI machine scope without a
  TPM) and readable only by SYSTEM; it MUST never be written in plaintext, logged, or sent to the
  phone or relay.
- **FR-403**: The stored credential MUST be released to the sign-in tile only after an approval
  that passes the normal acceptance rule (matching number, approve-key signature, unexpired,
  single-use).
- **FR-404**: Turning passwordless off MUST wipe the stored password immediately.
- **FR-405**: If Windows rejects the stored password, the tile MUST offer to re-enter the password
  or use a recovery code; it MUST NOT lock the owner out. (No password oracle may gate recovery —
  regression from 003 fix stands.)

**Phone-initiated disable**

- **FR-406**: The phone app MUST offer, per paired PC, "Turn off protection", requiring biometric
  (approve key) to send a signed disable command.
- **FR-407**: The PC MUST disable only on a command signed by the pinned approve key, fresh
  (≤120 s), and single-use; replayed or wrongly-signed commands MUST be ignored.
- **FR-408**: A phone disable MUST be recorded on both devices and leave protection off (same state
  as a companion-initiated disable).

**Update checks**

- **FR-409**: Each app MUST, when enabled, check the latest GitHub release of `simplehima/phonegate`
  and show a non-blocking banner when it is newer than the running version, linking to the release.
- **FR-410**: The check MUST be a plain unauthenticated GET, MUST fail silently, MUST be toggleable,
  and MUST never auto-download or auto-install.

**Setup restore point**

- **FR-411**: Setup MUST offer (default on) to create a System Restore point before installing,
  enabling System Protection on the system drive if needed, and MUST continue (not block the
  install) if a restore point cannot be made, explaining why.

**Release**

- **FR-412**: The version MUST be bumped consistently across the workspace, Android and the
  companion. The repo MUST be pushed to public `simplehima/phonegate` and a `v<version>` release
  MUST carry the setup exe, APK and SHA256SUMS. No secret may be published (the scanner gate holds).

## Success Criteria *(mandatory)*

- **SC-401**: With passwordless on, 100% of sign-ins that get a matching approval succeed with no
  typed password; 0 credential releases occur without a verified approval (adversarial test).
- **SC-402**: 0 replayed or wrongly-signed phone disable commands are honored.
- **SC-403**: The update banner appears only when the release is strictly newer, in 100% of tests.
- **SC-404**: A first-time user who leaves the restore-point box checked gets a usable restore
  point without any manual step.

## Assumptions

- Passwordless stores the interactive password; this is the accepted trade for authenticator-style
  convenience, confined to PCs the owner opts in. Documented in SECURITY.md.
- Update checks contact `api.github.com` only; this is the first time either app talks to anything
  but the owner's relay, and it is optional and off-switchable.
- The maintainer's machine is authenticated to GitHub as `simplehima` (gh CLI).

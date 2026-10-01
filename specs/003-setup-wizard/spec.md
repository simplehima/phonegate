# Feature Specification: Windows Setup Wizard with Bundled Phone App

**Feature Branch**: `003-setup-wizard`

**Created**: 2026-09-29

**Status**: Draft

**Input**: User description: "create a setup wizard for the app windows and bundle in it the apk so user can move it to phone"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Install PhoneGate on Windows with a normal setup wizard (Priority: P1)

I download one `PhoneGate-Setup.exe` and run it. A familiar Windows wizard walks me through five
steps:

1. Welcome.
2. The license.
3. A plain "Before you install" page: try it on a spare PC or VM first, keep your recovery codes,
   and protection stays off until you turn it on.
4. The install itself.
5. A finish page.

When it's done, the PhoneGate service, sign-in tile, watchdog and companion app are installed,
**protection is still off**, and I'm offered to open PhoneGate to pair my phone.

**Why this priority**: Today installation means running PowerShell scripts, which is too
technical for a first-time user.

**Independent Test**: On a clean Windows VM, run the setup exe, click through, and confirm:

- the service is running;
- the sign-in tile is registered;
- the watchdog task exists;
- the companion app opens;
- the lock screen still works with just a password, because protection is off.

**Acceptance Scenarios**:

1. **Given** a 64-bit Windows 10 22H2+ or 11 PC, **When** the owner runs setup as administrator,
   **Then** the wizard shows its pages and installs everything, and at the end protection is off.
2. **Given** a 32-bit or older Windows, **When** setup runs, **Then** it refuses with a clear
   message.
3. **Given** PhoneGate is already installed, **When** a newer setup runs, **Then** it upgrades in
   place and keeps pairing, recovery codes and history.
4. **Given** protection is ON, **When** the owner tries to uninstall from Settings > Apps,
   **Then** uninstall stops and explains how to turn protection off first (phone approval or
   recovery code).
5. **Given** protection is off, **When** the owner uninstalls, **Then** the service, tile, filter,
   watchdog, Safe Mode registration and program files are removed. The data folder is kept unless
   the owner chooses to delete it.

---

### User Story 2 - Get the phone app onto my Android phone (Priority: P1)

The setup includes the PhoneGate Android app. On the finish page, and in the companion app's setup
steps, I get **Show the phone app**. It opens the folder with `PhoneGate.apk` and short
instructions for copying it to my phone and installing it:

- with a USB cable;
- with Quick Share / Nearby Share;
- through my cloud drive.

The app shows the APK's fingerprint (SHA-256) and its signing certificate, so I can check I got
the genuine file.

**Why this priority**: Pairing needs the phone app. PhoneGate isn't on an app store, so the setup
must deliver it.

**Independent Test**: After install, open the folder from the finish page, copy the APK to a
phone, install it, and confirm it opens. The fingerprint shown matches the file.

**Acceptance Scenarios**:

1. **Given** installation finished, **When** the owner ticks "Show the phone app", **Then**
   Explorer opens with `PhoneGate.apk` selected, next to a "How to install on your phone" guide.
2. **Given** the companion's setup steps, **When** the owner reaches "Get the phone app",
   **Then** it shows the APK's SHA-256 and signing-certificate fingerprint, the install steps, and
   buttons **Show the file** and **Copy fingerprint**.
3. **Given** the bundled APK, **Then** it is a release build signed with the project's release key,
   never the debug key. The debug-only preview screen is not included.

### Edge Cases

- Upgrade while the PhoneGate DLL is loaded by the sign-in screen: the file is replaced at the next
  restart, and setup says a restart is needed.
- Upgrade while the service is running: setup stops the service and the watchdog first, then
  starts them again.
- The release signing key is missing on the build machine: the build fails with instructions. It
  never falls back to a debug-signed APK.
- The owner closes setup halfway: nothing is half-registered. Registration runs only after all
  files are in place.
- The APK is transferred over an untrusted channel: the owner can compare its fingerprint with the
  one the companion shows, and the setup's own published SHA-256.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-301**: A single, self-contained setup executable MUST install every Windows component and
  the Android APK. It requires administrator rights, and only runs on 64-bit Windows 10 22H2 or
  newer.
- **FR-302**: The wizard MUST have Welcome, License (Apache-2.0), "Before you install", progress
  and Finish pages. The finish page MUST offer "Open PhoneGate" and "Show the phone app".
- **FR-303**: Setup MUST leave protection OFF, as `install.ps1` already does.
- **FR-304**: Setup MUST support in-place upgrade, preserving `%ProgramData%\PhoneGate`.
- **FR-305**: Uninstall MUST refuse while protection is on, with an explanation, and otherwise
  remove everything `uninstall.ps1` removes.
- **FR-306**: The bundled APK MUST be a release build signed with a release key kept outside the
  repository. The build MUST fail rather than ship a debug-signed APK.
- **FR-307**: The companion MUST show the APK's SHA-256 and signing-certificate SHA-256, how to
  move it to the phone, and a button that reveals the file.
- **FR-308**: The build MUST print the SHA-256 of the setup exe and of the APK, for publishing
  alongside releases.

### Key Entities

- **Setup package**: the installer executable containing the Windows binaries, scripts, license
  and APK.
- **Phone app package**: the release-signed APK plus its fingerprints.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-301**: A first-time user installs PhoneGate on Windows in under 2 minutes without opening a
  terminal.
- **SC-302**: A first-time user gets the phone app installed on their phone in under 5 minutes
  using only the bundled instructions.
- **SC-303**: 100% of builds ship a release-signed APK; 0 debug-signed APKs reach a setup package.

## Assumptions

- The setup is not code-signed yet (no certificate). Windows SmartScreen may warn, and the README
  explains this. Publishing SHA-256 hashes is the integrity check for now.
- The release signing key is generated once per maintainer and stored outside the repository.
  Anyone building from source creates their own key, so their APK is signed by them.

# Implementation Plan: Windows Setup Wizard with Bundled Phone App

**Branch**: `003-setup-wizard` | **Date**: 2026-09-29 | **Spec**: [spec.md](./spec.md)

## Summary

This feature has four parts:

- **Installer.** An Inno Setup 6 installer, `windows/installer/phonegate.iss`, wraps the existing,
  tested `install.ps1` and `uninstall.ps1`. Inno supplies the wizard pages, upgrade handling and
  the Programs & Features entry.
- **Uninstall guard.** Pascal `[Code]` refuses to uninstall while protection is on.
- **APK.** A release APK, signed with a key outside the repo (`tools/android-release-key.ps1`
  creates it), is bundled under `{app}\Android`.
- **Companion.** A new "Get the phone app" step shows the fingerprints and reveals the file.

## Technical Context

- Inno Setup 6.7 (ISCC), and PowerShell 5.1 at install time.
- Gradle release build with `apksigner` (from build-tools) to read the signing certificate.
- A Tauri command reads the APK next to the executable.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Kerckhoffs | ✅ | The signing key and passwords live in `%USERPROFILE%\.phonegate-signing\`, never in the repo; the secret scanner already flags keystores and passwords. |
| IV. Fail-secure | ✅ | Setup leaves protection off. Uninstall refuses while protection is on. The build fails rather than ship a debug APK. |
| V. Honest limits | ✅ | The unsigned setup and SmartScreen warning are documented, and hashes are published. |
| VIII. UX | ✅ | Plain-language pages, an explicit "Before you install" page, and a finish-page choice to show the phone app. |

## Structure

```text
tools/android-release-key.ps1          # one-time: create release keystore + credentials outside the repo
android/app/build.gradle.kts           # release signingConfig from env / ~/.phonegate-signing
windows/installer/phonegate.iss        # Inno Setup script (wizard, [Code] guards)
windows/installer/before-install.txt   # "Before you install" page text
windows/installer/phone-app-guide.txt  # How to install PhoneGate.apk on your phone
windows/installer/build-installer.ps1  # builds everything, stages dist/, runs ISCC, prints hashes
windows/scripts/install.ps1            # accept SourceDir == InstallDir (installer case)
windows/companion/...                  # "Get the phone app" step + apk_info / reveal_apk commands
tools/check-apk-signing.mjs            # gate: bundled APK is release-signed (not Android Debug)
tools/check-installer-manifest.mjs     # gate: setup manifest contains every component + APK
```

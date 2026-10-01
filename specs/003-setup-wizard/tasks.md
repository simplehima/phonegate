# Tasks: Windows Setup Wizard with Bundled Phone App

- [X] T301 Add `tools/android-release-key.ps1`: creates `%USERPROFILE%\.phonegate-signing\release.jks` with a random password (`keytool`), writes `signing.properties` there, and never touches the repo
- [X] T302 Add a release `signingConfig` to `android/app/build.gradle.kts`, read from `PG_SIGNING_PROPERTIES` or `~/.phonegate-signing/signing.properties`; a release task without it fails with instructions
- [X] T303 Make `windows/scripts/install.ps1` skip copying when SourceDir is the install folder (installer case) and report "restart required" if the DLL was in use
- [X] T304 Write `windows/installer/phonegate.iss`: wizard pages, x64 / Win10 22H2+ checks, files, APK + guide, run install.ps1, finish checkboxes (open companion, show APK), PrepareToInstall stops service + watchdog on upgrade, InitializeUninstall refuses while enforcing, uninstall runs uninstall.ps1, OutputManifestFile
- [X] T305 Write `windows/installer/before-install.txt` and `phone-app-guide.txt` (USB, Quick Share, cloud drive, "install unknown apps", fingerprint check)
- [X] T306 Write `windows/installer/build-installer.ps1`: build Rust release + companion + release APK, stage `dist/installer/`, run ISCC, print SHA-256 of setup and APK
- [X] T307 Add `tools/check-apk-signing.mjs` (apksigner cert must not be Android Debug) and `tools/check-installer-manifest.mjs`
- [X] T308 [P] Companion "Get the phone app" step: `apk_info` (SHA-256 + signer SHA-256 from a sidecar written at build time) and `reveal_apk` Tauri commands, UI step in setup, mock support, tests
- [X] T309 README: installing with the setup, SmartScreen note, verifying hashes, building your own signed APK
- [X] T310 Build the setup exe and run all gates

# Building from source

**Tools:**
- Rust (stable, MSVC)
- Visual Studio Build Tools (C++ workload)
- Node 20+
- JDK 17 and the Android SDK (API 36)
- Inno Setup 6 (`winget install JRSoftware.InnoSetup`)
- Docker, for the relay image

```powershell
cargo test --workspace                        # protocol, relay, engine, end-to-end (incl. hostile relay)
cd android; .\gradlew.bat testDebugUnitTest   # includes the shared protocol test vectors
```

## Your own signed release

```powershell
.\tools\android-release-key.ps1               # once: creates your release key OUTSIDE the repo
.\windows\installer\build-installer.ps1       # -> dist\installer\PhoneGate-Setup-<version>.exe + SHA256SUMS.txt
```

The build refuses to package an APK signed with the Android debug key. Back up
`%USERPROFILE%\.phonegate-signing`: Android accepts updates only when they're signed with the same
key.

## The relay binary

Run the **release** workflow (Actions tab → release → Run workflow) with a tag, or build it locally:

```bash
cargo build --release -p phonegate-relay
```

## More

- Layout: [docs/ARCHITECTURE.md](https://github.com/simplehima/phonegate/blob/main/docs/ARCHITECTURE.md)
- Specifications: [docs/specs](https://github.com/simplehima/phonegate/tree/main/docs/specs)

# Implementation Plan: Phone-Approved Windows Unlock

**Branch**: `001-phone-approved-unlock` | **Date**: 2026-09-26 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/001-phone-approved-unlock/spec.md`

## Summary

A Windows Credential Provider running in LogonUI, together with a filter, adds a mandatory phone
approval to every unlock, sign-in, and RDP sign-in on the PC. A SYSTEM service holds a TPM
identity key. It sends end-to-end signed and encrypted requests through a stateless,
self-hosted relay. The Android app shows the request, makes the owner type the number shown on the
PC, and signs the decision with a biometric-bound Keystore key. The PC checks that signature
against the key it pinned at pairing. Nothing in the source or binaries is secret, so a
compromised relay or network can only cause denial of service. Recovery works offline through
single-use recovery codes and a QR-based offline phone code. Decisions: [research.md](./research.md).

## Technical Context

**Language/Version**: Rust 1.98 (stable, MSVC) · Kotlin 2.x (Android) · TypeScript (companion UI)

**Primary Dependencies**:

- Rust: `p256`/`ecdsa`, `hkdf`, `hmac`, `sha2`, `aes-gcm`, `getrandom`, `zeroize`, `x509-parser`
  (attestation), `serde`/`serde_json`
- Relay: `axum`, `tokio`, `tokio-tungstenite`
- Agent and CP: `windows` (Win32 COM, CNG, named pipes, services)
- Companion: `tauri` 2
- Android: Jetpack Compose (Material 3), CameraX, ZXing core, OkHttp, AndroidX Biometric

**Storage**: JSON files. PC: `C:\ProgramData\PhoneGate`, ACL SYSTEM/Admins. Phone: app-private,
encrypted with a Keystore AES key. Relay: memory only.

**Testing**: `cargo test` (unit, vectors, relay integration, E2E simulation with a malicious relay).
Android: JUnit tests that consume the shared JSON vectors.

**Target Platform**: Windows 10 22H2 / 11 x64 · Android 11+ (API 30) · relay on Linux (Docker)

**Project Type**: multi-component: desktop service + COM DLL + desktop app, mobile app, web service

**Performance Goals**: request shown on the phone ≤ 5 s; the full unlock flow ≤ 15 s p95; the relay
handles 1k connections on one core.

**Constraints**: fail-closed everywhere. No blocking network I/O on LogonUI's UI thread. No secrets
in the repo. Every panic is caught at the COM boundary.

**Scale/Scope**: one owner, 1–10 PCs per phone; relay sized for about 1k devices.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | How the design complies |
|-----------|--------|-------------------------|
| I. Kerckhoffs | ✅ | All keys are generated on the device (TPM/Keystore); psk comes from the QR; the relay has no key material; a CI step scans for secrets |
| II. Untrusted relay | ✅ | Protocol §3–4: pinned keys, AEAD, signatures, single-use digests; `e2e_malicious_relay` test |
| III. Hardware keys | ✅ | Platform Crypto Provider machine key; Keystore StrongBox/TEE with per-use biometric; attestation check; the software fallback is surfaced and needs acknowledgement |
| IV. Fail-secure + recovery | ✅ | Acceptance rule §4.2 (anything else = deny); recovery codes ≥128-bit, single-use, with lockout; offline phone code; no debug bypass |
| V. OS trust boundary | ✅ | Wrapping CP + filter in LogonUI; SECURITY.md lists residual risks; setup checks BitLocker/TPM/RDP |
| VI. Test-first | ✅ | Shared vectors; negative E2E tests: tamper, replay, expiry, wrong key, wrong number |
| VII. Minimal, memory-safe | ✅ | Everything in Rust/Kotlin, including the CP; `unsafe` only at Win32 FFI call sites |
| VIII. Calm UX | ✅ | Typed number match, deny as prominent as approve, "This wasn't me", WCAG 2.2 AA; Impeccable design pass on the phone and companion UI |

**Post-design re-check**: ✅ No violations. The contracts introduce no server-side secrets, and
every accept path in §4.2 requires a hardware-key signature.

## Project Structure

### Documentation (this feature)

```text
specs/001-phone-approved-unlock/
├── plan.md  research.md  data-model.md  quickstart.md
├── contracts/ protocol.md  relay-api.md  agent-pipes.md
└── tasks.md            # /speckit-tasks
```

### Source Code (repository root)

```text
Cargo.toml                    # workspace
crates/pg-core/               # canonical encoding, crypto suite, messages, pairing, envelope,
  src/                        #   offline codes, recovery codes, attestation verify, state store,
  roots/                      #   Google attestation roots (public trust anchors)
  tests/                      #   vector generation and verification
crates/pg-sim/                # software "phone" and "PC" used by E2E tests (never shipped)
server/                       # phonegate-relay (axum)
  src/  tests/
windows/agent/                # phonegate-agent (service): TPM keys, relay client, pipes, protocol engine
windows/credprov/             # phonegate_cp.dll: wrapping CP + filter (COM, Rust)
windows/companion/            # Tauri app: src-tauri/ (Rust) + ui/ (TS, Vite)
windows/scripts/              # build / install / uninstall PowerShell
android/                      # Gradle project: app/ (Compose), protocol + crypto + keystore modules
protocol/vectors/             # JSON test vectors generated by pg-core
tests/e2e/                    # workspace-level E2E (relay + pg-sim)
deploy/                       # docker-compose.yml, Caddyfile, Dockerfile
docs/                         # SECURITY.md (threat model, residual risks), ARCHITECTURE.md
```

**Structure Decision**: This is a monorepo. One Cargo workspace holds every Rust component, so the
protocol exists in exactly one Rust implementation (`pg-core`). The Kotlin implementation is kept
honest by the shared vectors.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Four deployable components (relay, agent, CP DLL, companion) plus the Android app | The OS forces the CP to be an in-proc COM DLL. Keys and I/O must stay out of LogonUI. The owner needs a UI to pair. | Merging the agent into the CP puts network I/O and a crash risk into LogonUI. Dropping the companion leaves no UI for pairing. |

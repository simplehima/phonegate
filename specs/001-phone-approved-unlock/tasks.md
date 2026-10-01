# Tasks: Phone-Approved Windows Unlock

**Input**: Design documents from `specs/001-phone-approved-unlock/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: REQUIRED by Constitution VI. Security-critical tasks include their negative tests.

**Order note**: US2 (pairing) is executed before US1 (approve), because approval needs a pairing.
Both are P1.

## Format: `[ID] [P?] [Story] Description`

## Phase 1: Setup

- [X] T001 Create Cargo workspace `Cargo.toml` (members: crates/pg-core, crates/pg-sim, server, windows/agent, windows/credprov, tests/e2e) with a shared `[workspace.dependencies]` block and `rust-toolchain.toml` pinned to stable
- [X] T002 [P] Create `README.md`, `LICENSE` (Apache-2.0), `docs/SECURITY.md` skeleton, and `.editorconfig`
- [X] T003 [P] Create the Android Gradle project skeleton in `android/` (settings.gradle.kts, app module, minSdk 30, targetSdk 36, Compose, version catalog `android/gradle/libs.versions.toml`, Gradle wrapper)
- [X] T004 [P] Create the Tauri companion skeleton in `windows/companion/` (src-tauri Cargo + tauri.conf.json with `requireAdministrator` manifest; ui/ Vite + TypeScript)
- [X] T005 [P] Add a secret-scanning script `tools/scan-secrets.mjs` that fails on private keys, API-key patterns, and high-entropy literals in the tracked sources

## Phase 2: Foundational (blocks all stories)

- [X] T006 Implement canonical encoding `enc`/decode with strict rejection rules (protocol §2) in `crates/pg-core/src/encoding.rs`, with tests for truncation, trailing bytes, wrong count, and oversize
- [X] T007 Implement the crypto suite (SHA-256, HMAC, HKDF, AES-256-GCM, P-256 ECDSA raw r‖s sign/verify with range checks, ECDH, PUB validation, ID) in `crates/pg-core/src/crypto.rs`, with RFC 5869 HKDF and NIST GCM test cases
- [X] T008 Define a `Signer` trait (sync `sign(&[u8]) -> [u8;64]`, `public() -> PUB`) plus a software implementation `SoftSigner` in `crates/pg-core/src/signer.rs`
- [X] T009 Implement typed messages and the wire body (protocol §4.1, §5) in `crates/pg-core/src/messages.rs`: ApprovalRequest, ApprovalResponse, Cancel, Notice, Unpair, Wire
- [X] T010 Implement the sealed envelope seal/open (protocol §4), verify-before-decrypt, in `crates/pg-core/src/envelope.rs`, with tamper tests (ct, aad, sig, wrong key, wrong direction)
- [X] T011 Implement the relay server (`server/src/main.rs`, `server/src/hub.rs`, `server/src/limits.rs`) per contracts/relay-api.md: auth challenge, mailboxes, TTL queue, slots, limits, `/healthz`
- [X] T012 Implement the relay integration tests in `server/tests/relay.rs`: auth success and failure, queued delivery, slot delivery, size limit, queue cap, rate limit
- [X] T013 Implement a shared relay client (tokio WebSocket, auth, reconnect with backoff) in `crates/pg-core/src/relay_client.rs` behind the `client` feature
- [X] T014 Implement the atomic, file-locked JSON state store in `crates/pg-core/src/store.rs` (temp file + rename, exclusive lock file)
- [X] T015 Generate shared vectors `protocol/vectors/*.json` via `crates/pg-core/tests/vectors.rs` (encoding, hkdf, envelope, decision, sas, offline, recovery) using fixed keys and nonces; the test regenerates with `PG_WRITE_VECTORS=1` and otherwise verifies
- [X] T016 [P] Implement the Android protocol module: `Enc.kt`, `Crypto.kt` (HKDF, GCM, ECDSA DER↔raw, ECDH, PUB), `Envelope.kt`, `Messages.kt` in `android/app/src/main/java/dev/phonegate/protocol/`
- [X] T017 [P] Android `ProtocolVectorsTest.kt` consuming `protocol/vectors/*.json` in `android/app/src/test/java/dev/phonegate/protocol/`
- [X] T018 Implement the agent skeleton in `windows/agent/src/main.rs`: service entry (`windows-service`), console mode `--console` for development, config/state paths, logging without secrets
- [X] T019 Implement key backends in `windows/agent/src/keys.rs`: TPM (Platform Crypto Provider machine ECDSA P-256 + RSA-2048 wrap key) and a software fallback (DPAPI machine scope), selected at first start
- [X] T020 Implement pipe servers with a SYSTEM/Admin DACL and length-prefixed JSON framing in `windows/agent/src/pipes.rs`; a client helper with the server-is-SYSTEM check in `crates/pg-core/src/pipe_client.rs` (Windows only)

## Phase 3: User Story 2 — Pair phone with PC (P1)

**Goal**: QR pairing with SAS confirmation, attestation check, and recovery codes before enabling.
**Independent test**: `tests/e2e/tests/pairing.rs` pairs pg-sim phone ↔ agent engine over a real relay.

- [X] T021 [US2] Implement the pairing protocol for both roles (protocol §3), `PcPairing` and `PhonePairing` state machines, in `crates/pg-core/src/pairing.rs`, with tests: wrong QR hash, expired, reused id, bad MAC, SAS equality, confirm MAC mismatch
- [X] T022 [US2] Implement the Android attestation verifier (protocol §3.4) in `crates/pg-core/src/attestation.rs` with pinned roots in `crates/pg-core/roots/`, with tests using a generated synthetic chain (valid, wrong challenge, software level, auth timeout > 0, untrusted root)
- [X] T023 [US2] Implement the software phone for tests in `crates/pg-sim/src/lib.rs` (device/approve SoftSigners, pairing, approval decisions, offline codes)
- [X] T024 [US2] Implement the agent pairing engine and control ops `pair_start`, `pair_poll`, `pair_decide` in `windows/agent/src/engine.rs` and `windows/agent/src/control.rs`, persisting the Pairing record (data-model) with `k_pair` wrapped
- [X] T025 [US2] Implement recovery code generation, confirm, and `enable` gating (FR-022, FR-023) in `crates/pg-core/src/recovery.rs` and the agent control ops
- [X] T026 [US2] E2E test `tests/e2e/tests/pairing.rs`: full pairing via the relay, plus a malicious relay substituting the offer or join → pairing fails
- [X] T027 [P] [US2] Android keystore layer `android/.../keys/KeyManager.kt`: device/approve/wrap/offline-wrap keys (StrongBox fallback to TEE, attestation challenge, per-use biometric)
- [X] T028 [P] [US2] Android encrypted state store `android/.../data/PhoneStore.kt` (PhoneState, PairedPc per data-model)
- [X] T029 [US2] Android pairing flow `android/.../pairing/PairingController.kt` + QR scan screen (CameraX + ZXing) + SAS confirm screen
- [X] T030 [US2] Companion UI: status, pairing (QR + SAS confirm + attestation warning), recovery codes (show once, type back), enable, in `windows/companion/ui/` and `src-tauri/src/main.rs` pipe bridge

## Phase 4: User Story 1 — Approve an unlock (P1) 🎯 MVP

**Goal**: The unlock waits for a typed-number biometric approval.
**Independent test**: E2E approve, deny, not-me, expiry, replay, wrong number, and wrong key.

- [X] T031 [US1] Implement the approval engine in the agent: create the request (number 10–99, 60 s), send it, track outstanding requests, apply the acceptance rule §4.2, handle cancel/supersede and the cooldown (R8), in `windows/agent/src/engine.rs`
- [X] T032 [US1] Implement the gate pipe ops `status`, `begin`, `wait`, `cancel` in `windows/agent/src/gate.rs`
- [X] T033 [US1] E2E tests `tests/e2e/tests/approval.rs`: approve ok; deny; not-me; expired; replayed response; approve signed with the device key rejected; wrong typed number rejected; response for an unknown request; malicious relay tamper
- [X] T034 [US1] Credential Provider DLL `windows/credprov/src/`: COM exports, class factory, wrapping provider over Password `{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}`, a wrapped credential with extra fields (status text, number, cancel, "Use recovery code", "Offline code"), password pre-check via `LogonUserW`, async wait through the gate pipe, `ICredentialProviderEvents` refresh, and the KERB serialization pass-through
- [X] T035 [US1] Credential Provider filter in `windows/credprov/src/filter.rs`: while enforcing, hide every provider except PhoneGate for LOGON/UNLOCK; leave CREDUI untouched
- [X] T036 [US1] Android relay foreground service `android/.../net/RelayService.kt` (WebSocket, auth with the device key, reconnect, ongoing notification, heads-up request notification with Deny / Not me actions)
- [X] T037 [US1] Android approval screen `android/.../approve/ApproveScreen.kt`: PC, account, scenario, time, countdown, typed number entry (2 tries), BiometricPrompt with CryptoObject signing the decision with the approve key, and Deny / "This wasn't me" of equal prominence
- [X] T038 [US1] Windows install scripts `windows/scripts/install.ps1` / `uninstall.ps1` / `build.ps1` (service registration, CP COM + Credential Providers/Filters registry, ProgramData ACL, enforcement OFF by default)

## Phase 5: User Story 3 — Recovery when phone unavailable (P1)

- [X] T039 [US3] Recovery verification with lockout (protocol §7), shared by the CP and agent, in `crates/pg-core/src/recovery.rs`, with tests: success, single-use, normalization, lockout escalation, persistence
- [X] T040 [US3] Offline challenge/response (protocol §6) in `crates/pg-core/src/offline.rs`, plus agent ops `offline_begin` / `offline_verify`, with tests (valid, wrong, expired, 5-try limit, replay)
- [X] T041 [US3] CP recovery-code and offline-code UI paths (QR bitmap rendering for the offline challenge) in `windows/credprov/src/credential.rs`; if the agent is down, verify recovery directly from `recovery.json`
- [X] T042 [US3] Android offline code screen `android/.../offline/OfflineScreen.kt`: scan the PGO1 QR, verify the PC signature, biometric-unlock `k_offline`, show the 10-digit code
- [X] T043 [US3] Recovery-used notices queued and delivered to the phone (FR-025) in the agent engine and the Android history

## Phase 6: User Story 4 — Suspicious attempts & history (P2)

- [X] T044 [US4] AttemptRecord history with 90-day pruning in the agent (`history` op) and the Android store
- [X] T045 [US4] Companion history view and Android history screen with outcome badges (suspicious highlighted)

## Phase 7: User Story 5 — Multiple PCs (P2)

- [X] T046 [US5] Android multi-PC management (list, rename, unpair sending `unpair`) and per-PC relay connections in `android/.../pcs/PcListScreen.kt`
- [X] T047 [US5] Agent handling of `unpair` from the phone (fall back to recovery-only) and phone-side ignoring of requests from unpaired PCs, with E2E test

## Phase 8: User Story 6 — Remote desktop (P3)

- [X] T048 [US6] Scenario detection in the CP (`CPUS_LOGON` in a remote session → `remote`, client address via WTS API) and the `UpdateRemoteCredential` filter path in `windows/credprov/src/`

## Phase 9: Polish & Cross-cutting

- [X] T049 [P] Disable-protection flow (FR-029) in the agent (`disable_begin/wait/recovery`) and companion
- [X] T050 [P] `security_check` op (TPM, BitLocker, Secure Boot, RDP, passwordless-only) and companion warnings
- [X] T051 [P] Deployment files `deploy/Dockerfile`, `deploy/docker-compose.yml`, `deploy/Caddyfile`, `deploy/.env.example`
- [X] T052 [P] `docs/SECURITY.md` (threat model, guarantees, residual risks R15, hardening checklist) and `docs/ARCHITECTURE.md`
- [X] T053 Impeccable design pass (critique → polish → harden → accessibility audit) on the companion UI and the Android UI
- [X] T054 Run the quickstart §1 validation; `cargo clippy -D warnings`; Android lint; the secret scan

## Dependencies

Setup → Foundational → US2 → US1 (MVP) → US3 → {US4, US5, US6} → Polish.
Android tasks marked [P] can run in parallel with the Rust tasks in the same phase.

## Parallel Examples

- Phase 2: T016/T017 (Android protocol) in parallel with T011/T012 (relay).
- US2: T027/T028 (Android keys and store) in parallel with T021–T026 (Rust pairing).

## Implementation Strategy

1. **MVP**: through US1. Pair, approve or deny at the lock screen, tested E2E with the simulation.
2. US3 before any real-machine use: never enable enforcement without working recovery.
3. Then history, multi-PC, RDP, and polish.

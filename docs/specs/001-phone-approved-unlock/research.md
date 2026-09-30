# Research: Phone-Approved Windows Unlock

Every decision below assumes the attacker has the full source, can reverse engineer every binary,
may control the relay server and the network, and may sit in front of the PC.

## R1. Where the gate is enforced on Windows

- **Decision**: A *wrapping* Credential Provider (CP) that wraps the built-in Password provider,
  plus a Credential Provider **Filter** that hides every other provider for `CPUS_LOGON` and
  `CPUS_UNLOCK_WORKSTATION`. `CPUS_CREDUI` is left untouched: Microsoft requires it, and in-session
  prompts are out of scope (FR-002a). The CP collects the password, checks it locally, runs the phone
  step, and only then returns the packed `KERB_INTERACTIVE_UNLOCK_LOGON` from `GetSerialization`.
- **Rationale**: The CP runs in `LogonUI.exe` as SYSTEM on the secure desktop, before a session is
  shown. The user cannot kill it from the locked session. Duo and privacyIDEA use the same pattern.
- **Alternatives rejected**: A post-login full-screen overlay. The session already exists, so
  killing the process, Task Manager, or Ctrl+Alt+Del gets around it; it is not a security boundary.
  A filter alone without a wrapper cannot add a step.
- **Sources**: Microsoft ICredentialProviderFilter docs; Microsoft Windows-classic-samples
  CredentialProvider helpers (KERB serialization); Duo RDP/Windows Logon FAQ; privacyIDEA CP.

## R2. Implementation language for the Credential Provider

- **Decision**: Rust `cdylib` using the `windows` crate's COM support (`#[implement]`). Every COM
  entry point is wrapped in `catch_unwind` and returns `E_FAIL` instead of unwinding into LogonUI.
- **Rationale**: Constitution VII (memory safety). It shares the `pg-core` crate (protocol, recovery
  verification, state store) with the agent, and uses one build system (cargo) with no CMake/MSBuild.
- **Alternatives rejected**: The C++ sample-based CP is proven but unsafe, and would duplicate the
  recovery and verification logic in a second language.

## R3. Network I/O and keys live in a SYSTEM service, not in LogonUI

- **Decision**: `phonegate-agent`, a Windows service running as LocalSystem, owns the TPM key, the
  relay connection, and protocol state. The CP talks to it over a named pipe
  (`\\.\pipe\phonegate.gate`). The pipe's DACL allows only SYSTEM and Administrators. The CP checks
  that the pipe *server* process token is SYSTEM (`GetNamedPipeServerProcessId`) so a squatting
  user process cannot impersonate the agent.
- **Rationale**: A hang or crash in LogonUI locks everyone out, so blocking I/O stays out of it.
  Keys and state stay in one place.
- **Fallback**: If the agent is unreachable while enforcement is on, the CP offers *recovery code
  only*. It verifies the code itself from the SYSTEM-only state file. It never fails open.

## R4. PC keys

- **Decision**: An ECDSA P-256 identity key, created as a machine key (`NCRYPT_MACHINE_KEY_FLAG`) in
  the **Microsoft Platform Crypto Provider** (TPM), non-exportable, created by the SYSTEM service.
  A TPM RSA-2048 key wraps local secrets (the pairing secret) with OAEP. Without a TPM, the
  fallback is a software key protected by DPAPI machine scope. The companion shows this clearly and
  it needs explicit acknowledgement.
- **Rationale**: A TPM ECDH path through the platform provider is poorly documented. Ephemeral ECDH
  in software, authenticated by TPM signatures, avoids it.
- **Notes**: TPM ops take hundreds of ms, which is acceptable at connect and request time. SYSTEM
  code can still *use* the key: a local admin compromise is a residual risk.

## R5. Phone keys

- **Decision**: The phone keeps three Android Keystore keys, StrongBox-backed when available with
  TEE fallback:
  - `approve`: EC P-256 sign. `setUserAuthenticationRequired(true)`,
    `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL)`,
    `setInvalidatedByBiometricEnrollment(true)`, `setUnlockedDeviceRequired(true)`. It signs APPROVE
    only, through `BiometricPrompt` with a `CryptoObject`.
  - `device`: EC P-256 sign, no user auth. It is used for relay login and for DENY / NOT_ME, which
    need no biometric by design (FR-017).
  - `wrap`: AES-256-GCM, no user auth. It encrypts the pairing secrets at rest in app storage.
  - `offline-wrap`: AES-256-GCM with per-use biometric auth. It encrypts the offline-code key, so
    offline codes need a biometric too.
- **Attestation**: The `approve` and `device` keys are generated with an attestation challenge bound
  to the pairing. The PC verifies the chain up to Google's pinned roots and checks the key
  description: security level TEE/StrongBox, user-auth required, auth timeout 0. If that fails, the
  owner sees a warning and must accept explicitly (FR-011a).
- **Rejected**: Play Integrity. It needs Google credentials on the server and Play distribution,
  which breaks self-hosting and F-Droid.

## R6. Cryptographic suite

- **Decision**: P-256 ECDSA (SHA-256) for all signatures. Both TPM and Keystore support it natively.
  Ephemeral P-256 ECDH at pairing. HKDF-SHA256 derives all keys. AES-256-GCM encrypts everything.
  HMAC-SHA256 is used for the pairing MAC and offline codes.
- **Libraries**: Rust uses RustCrypto (`p256`, `ecdsa`, `hkdf`, `sha2`, `aes-gcm`, `hmac`) and
  `getrandom`. Android uses JCA/Keystore (`SHA256withECDSA`, `ECDH`, `AES/GCM/NoPadding`,
  `HmacSHA256`) with HKDF implemented over `Mac` and pinned by shared test vectors.
- **Canonical encoding**: Signed and MAC'd bytes use a deterministic length-prefixed encoding. There
  is no signed JSON, so the Rust and Kotlin sides cannot drift through serializer differences.
  See [contracts/protocol.md](./contracts/protocol.md).

## R7. Pairing protocol

- **Decision**: The QR code holds the protocol version, relay URL, a 16-byte pairing id, a 32-byte
  one-time pairing secret (`psk`), the SHA-256 of the PC public key, and the PC name. Flow:
  1. The PC posts a signed `PairOffer` with its public key and an ephemeral ECDH key.
  2. The phone checks the PC key hash from the QR, generates its keys (attested, challenge bound to
     the psk), and sends `PairJoin`, encrypted and MAC'd under psk-derived keys.
  3. Both sides derive `K_pair = HKDF(ikm = ECDH, salt = psk, info = transcript hash)` and show a
     6-digit confirmation code (SAS) derived from `K_pair`.
  4. The owner confirms on both devices, and each side sends a key-confirmation MAC.
  The QR is single-use and expires in 5 minutes.
- **Rationale**: The QR is an authentic out-of-band channel, so the relay can never learn the psk or
  swap keys. The SAS and key confirmation are defense in depth against a photographed QR. FIDO
  hybrid (caBLE) and Signal safety numbers work the same way.

## R8. Approval protocol and push fatigue

- **Decision**: For each attempt the PC sends a signed and encrypted `ApprovalRequest`. It carries:
  a 16-byte id, a 32-byte nonce, the PC and phone ids, issued/expiry times (60 s), the scenario, the
  account, the PC name, the remote address if any, and a 2-digit match number. The phone makes the
  owner **type** the number shown on the PC (no pick-list). It then signs
  `ApprovalResponse{request_digest, decision, typed_number, time}`: APPROVE with the `approve` key
  after a biometric, DENY/NOT_ME with the `device` key. The PC accepts a response exactly once, only
  for an outstanding request, before expiry, with the right key for the decision.
- **Rationale**: Microsoft Authenticator uses number matching and CISA recommends it. A signature
  bound to the request digest makes forgery and replay impossible without the phone's hardware key.
- **Spam control**: After 3 denied or expired requests in 5 minutes, the agent imposes an escalating
  cool-down (60 s, doubling, capped at 30 min).

## R9. Password check before a push

- **Decision**: Inside LogonUI, before contacting the phone, the CP calls
  `LogonUserW(LOGON32_LOGON_NETWORK)` with the typed credentials. `ERROR_LOGON_FAILURE` means we show
  "wrong password" and send no push. Any other result goes on to the phone step, and LSA still does
  the authoritative check after serialization. The password never leaves LogonUI.
- **Rationale**: This stops push-spam from people who don't know the password, and keeps FR-001
  intact: the phone never replaces the password.

## R10. Push delivery

- **Decision** (clarified): The Android app keeps a persistent WebSocket to the relay from a
  foreground service (`specialUse`), reconnecting with backoff and pinging every 30 s.
- **Rejected**: FCM needs a sender service-account key tied to one Firebase project. That means a
  central project, or every self-hoster rebuilding the app. UnifiedPush is deferred to later.

## R11. Relay server

- **Decision**: Rust (`axum` + `tokio`), **stateless and without persistence**.
  - Devices log in by signing a server challenge. The mailbox id is `SHA-256(SEC1 pubkey)`.
  - Messages are opaque blobs held in memory for at most 300 s, max 64 KiB each and 64 queued per
    mailbox.
  - Anyone may use a pairing slot. Its contents are protected by the psk.
  - Rate limits apply per IP and per mailbox.
  - It is deployed with Docker and Caddy, with automatic Let's Encrypt TLS (clarified).
- **Rationale**: Nothing to steal. A compromised relay can only drop or delay messages.

## R12. Recovery

- **Decision**:
  - **Recovery codes**: 10 codes of 128-bit random, Crockford base32 in groups of 4 (26 characters).
    They are stored as `SHA-256(pc_salt ‖ code)` and compared in constant time. They are
    single-use, with a lockout after 5 failures (1 min, doubling, capped at 24 h) that persists
    across reboots.
  - **Offline phone code** (FR-026a): the CP shows a QR with a TPM-signed offline challenge. The
    phone verifies it, asks for a biometric (unlocks `offline-wrap`), and shows
    `HOTP-like HMAC(K_offline, challenge)` truncated to 10 digits. `K_offline` is derived from
    `K_pair`. The challenge is single-use, lasts 60 s, and allows 5 tries.
- **Rationale**: 128-bit codes cannot be brute-forced offline even from a stolen state file, so a
  fast hash is enough.

## R13. Companion desktop app

- **Decision**: A Tauri 2 app (Rust backend, web UI), running elevated (`requireAdministrator`). It
  talks to the agent over `\\.\pipe\phonegate.control`, which is allowed only for Administrators and
  SYSTEM. Turning protection off needs a phone approval or a recovery code (FR-029).
- **Rationale**: WebView2 ships with Windows 11. A web UI lets us meet a high, WCAG-compliant design
  bar, and the Rust backend reuses `pg-core`.

## R14. Android UI stack

- **Decision**: Kotlin, Jetpack Compose (Material 3), CameraX with ZXing core for QR (no Google
  Play Services dependency), OkHttp WebSocket, and Room-free storage (a JSON file encrypted by the
  `wrap` key). minSdk 30 (Android 11), because `setUserAuthenticationParameters` needs API 30.

## R15. Residual risks (documented in SECURITY.md; software cannot close them)

- A local admin or SYSTEM on an already-unlocked PC can unregister the CP or use the TPM key.
- Physical access without BitLocker pre-boot authentication: replacing utilman/sethc, offline
  registry edits, or removing the CP. Mitigation: BitLocker TPM+PIN, Secure Boot, a firmware
  password, and Kernel DMA Protection. Setup checks these and warns.
- Safe Mode or WinRE paths may skip third-party providers. The Windows password is still needed;
  the second factor may be skipped. Documented, with hardening steps.
- Network logons (SMB, WinRM, runas) accept the Windows password without the phone. Documented,
  with the recommendation to restrict "Access this computer from the network".
- A compromised phone OS or TEE extraction, and social engineering (someone reading the number to
  the owner).
- A malicious update of PhoneGate itself (supply chain). Mitigation: signed, reproducible releases.

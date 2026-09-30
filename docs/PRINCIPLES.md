# PhoneGate Engineering Principles

## Core Principles

### I. Kerckhoffs by Construction (NON-NEGOTIABLE)
Security MUST rest solely on key material generated on the user's own devices at pairing time.
Publishing the complete source code, build scripts, binaries, and server configuration MUST give an
attacker no ability to approve, forge, decrypt, or replay anything.
- The repository, build outputs, and server config MUST contain zero secrets that grant approval
  power (no API keys, shared HMAC keys, hard-coded salts used as secrets, or "obfuscated" keys).
- Obfuscation, anti-debugging, or "security through secrecy" MUST NOT be counted as a control.
- Rationale: the project is open source; the only defensible position is one that survives full
  disclosure.

### II. The Relay Is Untrusted
The self-hosted server is a message relay and nothing more. A fully compromised server MAY drop or
delay messages (denial of service) but MUST NOT be able to forge an approval, read request contents,
replay an old approval, or substitute a device key after pairing.
- Every approval request and response MUST be end-to-end signed and encrypted between paired devices.
- Device identities MUST be pinned at pairing via an out-of-band channel (QR code on the PC screen),
  never learned from the server.
- Server accounts are identified by public keys; the server stores no passwords.

### III. Hardware-Rooted Keys
- PC keys MUST live in the TPM (Microsoft Platform Crypto Provider), non-exportable. A software-key
  fallback is permitted only when no TPM exists, MUST be clearly surfaced to the user, and MUST be
  protected with DPAPI machine scope.
- Phone signing keys MUST live in Android Keystore (StrongBox when available), non-exportable, and
  MUST require strong biometric (or device credential) authentication for every single use.
- Keys MUST be invalidated when new biometrics are enrolled.

### IV. Fail-Secure with Honest Recovery
- No valid approval means no unlock. Timeouts, network errors, server errors, parse errors, and
  signature failures MUST all result in denial.
- Offline recovery MUST exist so an owner is never permanently locked out: single-use, high-entropy
  (≥128-bit) recovery codes, verified locally, rate-limited, and never transmitted to the server.
- There MUST be no hidden bypass, debug flag, or "master key" in any build.

### V. Enforcement at the OS Trust Boundary
- Gating MUST be implemented as a Windows Credential Provider (and Credential Provider Filter)
  hosted by LogonUI, so it runs before the user session is revealed and cannot be killed from it.
- A user-mode overlay MUST NOT be presented as a security control.
- Residual risks that software cannot solve (no BitLocker, physical disk access, Safe Mode, DMA,
  local admin tampering after login) MUST be documented in SECURITY.md and surfaced during setup.

### VI. Test-First for Security-Critical Code
- Protocol, cryptography, replay protection, expiry, pairing, and recovery logic MUST have automated
  tests written alongside or before the implementation, including negative tests (tampered payload,
  wrong key, expired, replayed, wrong device, malformed input).
- Shared protocol test vectors MUST be consumed by every implementation (Rust and Kotlin) so the
  two sides cannot silently diverge.

### VII. Minimal, Auditable, Memory-Safe
- Prefer memory-safe languages (Rust for server and Windows components, Kotlin for Android). Unsafe
  or C/C++ code MUST be confined to the thinnest possible OS-interop shim and justified.
- Use well-reviewed cryptographic libraries only (RustCrypto/ring, Android Keystore/JCA). No
  hand-rolled primitives. Dependencies MUST be pinned via lockfiles.

### VIII. Calm, Unambiguous, Accessible UX
- The phone approval screen MUST make the request context impossible to misread: PC name, account,
  time, and a number-match code shown on the PC that the user must select on the phone.
- Deny MUST be as easy as Approve; an unexpected request MUST offer "This wasn't me".
- Interfaces MUST meet WCAG 2.2 AA (contrast, touch targets ≥48dp, screen-reader labels) and work
  in light and dark themes.

## Security Requirements

- Transport: TLS 1.3 to the relay in production; E2E protection does not depend on TLS.
- Approvals carry: request id, 256-bit nonce, PC id, phone id, issued-at, expires-at (≤120 s),
  event context, number-match value; responses bind the SHA-256 of the exact request.
- Every consumed nonce MUST be recorded and rejected on reuse; clocks are checked with bounded skew.
- The relay MUST rate-limit per device and per IP and cap message sizes.
- Logs MUST NOT contain plaintext request contents, keys, or recovery codes.

## Development Workflow & Quality Gates

- A change is not done until: all unit tests pass (`cargo test`, Gradle unit tests), protocol test
  vectors pass on both sides, and `cargo clippy` / Android lint report no errors.
- Security-sensitive changes require a review pass against this constitution before merge.
- Credential Provider changes MUST be tested in a VM with a snapshot before any real machine; the
  installer MUST refuse to enable enforcement until pairing and a recovery code are verified.

## Governance

This constitution supersedes other practices in this repository. Amendments require a pull request
that states the change, rationale, and migration impact, and bumps the version: MAJOR for removing or
redefining a principle, MINOR for adding a principle or materially expanding guidance, PATCH for
clarifications. Every plan MUST include a Constitution Check; violations MUST be listed with
justification in the plan's Complexity Tracking table or the plan is rejected.

**Version**: 1.0.0 | **Ratified**: 2026-09-25 | **Last Amended**: 2026-09-25

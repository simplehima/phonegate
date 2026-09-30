# PhoneGate Security Model

PhoneGate keeps a Windows PC locked until its owner approves each unlock on their Android phone.
It is **open source by design**: its security must hold when an attacker has all of the following:

- the complete source code, and every binary disassembled;
- control of the relay server and the network in between;
- the Windows password.

This document states exactly what PhoneGate guarantees, how, and what it cannot protect against.

## 1. Guarantees

| # | Guarantee | How it is enforced |
|---|-----------|--------------------|
| G1 | Nothing secret ships in the code | Every key is generated on the owner's devices at pairing time. The repository contains only public data: protocol test vectors made with throwaway keys, and Google's public attestation root certificates. CI runs `tools/scan-secrets.mjs`. |
| G2 | The relay cannot approve a sign-in | The PC accepts an approval only if it is signed by the phone's **approve key**, which the PC pinned at pairing. The relay holds no key material. See `ApprovalResponse::verify_decision` and `Engine::apply_response`. |
| G3 | The relay cannot read requests | Every request and response is encrypted end to end with AES-256-GCM, under keys derived from `k_pair`. Only the two paired devices know `k_pair`. |
| G4 | No replay | Each request has a random 16-byte id and a 32-byte nonce, and expires in 60 s or less. An approval is bound to the SHA-256 of the exact request and is consumed once. Envelope message ids are remembered for 24 h. |
| G5 | No key substitution at pairing | The QR code on the PC screen is the out-of-band channel. It carries a one-time 256-bit secret and the hash of the PC key. Both screens also show a 6-digit code derived from the key exchange, which the owner confirms. |
| G6 | Approvals need the owner's finger | The approve key lives in Android Keystore (StrongBox when available). It requires strong biometric or device-credential authentication for **every** use, and is destroyed when new fingerprints are enrolled. The PC checks this with **hardware key attestation** at pairing. |
| G7 | Push fatigue resistance | The owner must **type** the 2-digit number shown on the PC. There is no pick-list, and a wrong number counts as suspicious. After 3 unanswered or denied requests, the PC waits before sending more (escalating cool-down). |
| G8 | The PC's key cannot be copied | The PC identity key is a non-exportable **TPM** key (Microsoft Platform Crypto Provider). Local secrets are wrapped with a TPM RSA key. A copied `state.json` is useless on another machine. |
| G9 | Fail-secure | A timeout, network error, relay outage, malformed message, bad signature, corrupt state file or unpaired PC always means **no unlock**. The only way in is then an offline method from §3. There is no debug flag and no master key. |
| G10 | The gate runs where users cannot kill it | The gate is a Credential Provider running in `LogonUI.exe` as SYSTEM on the secure desktop, before any user session exists. A filter hides every other tile (PIN, Hello, smart card) while protection is on. It is not an overlay. |

All of these are covered by automated tests, including a hostile-relay suite
(`tests/e2e/tests/malicious_relay.rs`). That suite flips bits, forges senders, replays messages,
mints approvals with attacker keys (even knowing `k_pair`), and substitutes pairing messages.
Mutation testing confirmed the suite fails if the acceptance rule is weakened.

## 2. Cryptography

- **Algorithms**: P-256 ECDSA (SHA-256) and P-256 ECDH, HKDF-SHA256, AES-256-GCM and HMAC-SHA256.
  These are the algorithms both TPMs and Android Keystore support natively.
- **Libraries**: RustCrypto in Rust, and JCA/Keystore in Kotlin. There are no hand-rolled primitives.
- **Wire format**: signed and hashed data uses a canonical length-prefixed encoding with a unique
  label per structure, which gives domain separation. JSON is never signed. The full specification
  is in `docs/specs/001-phone-approved-unlock/contracts/protocol.md`.
- **Cross-checks**: shared test vectors (`protocol/vectors/v1.json`) keep the Rust and Kotlin
  implementations byte-identical.

## 3. Never locked out

| Situation | Way back in |
|-----------|-------------|
| Phone offline or relay down | **Offline approval**: the lock screen shows a PC-signed QR code, and the phone answers with a 10-digit code after a biometric check. No network is used. |
| Phone lost, reset or dead | **Recovery codes**: 10 single-use codes of 128 bits each, shown once at setup. One must be typed back before protection can be turned on. The PC stores them only as salted hashes, and a lockout escalates after 5 wrong tries. |
| Agent service not running | The credential provider verifies recovery codes directly from the SYSTEM-only file. |
| Credential provider broken | Boot into Safe Mode, where third-party providers do not load, and uninstall. See §4, which is also why you should test in a VM first. |

## 4. Tamper alarm and hardening (feature 002)

PhoneGate cannot stop an administrator of the PC from removing it. No third-party, open-source
Windows service can: Protected Process Light requires a Microsoft-signed antimalware driver.
What PhoneGate guarantees instead is that **removal or tampering cannot happen silently**.

| Mechanism | What it does | Limit |
|-----------|--------------|-------|
| **Status reports** | Every 5 minutes, and immediately on any change, the PC sends the phone an end-to-end signed and encrypted report. It covers protection on/off, sign-in tile and filter registration, program files matching their install-time fingerprints, watchdog present, drive encryption, network sign-in block, and Safe Mode. A strictly increasing sequence number defeats replay. | A report can only be *withheld*, which triggers the alarm, never forged. |
| **Silence alarm** | The phone alerts if no report arrives for 20 minutes, unless the PC last said it was shutting down or going to sleep. It is measured on the **phone's** clock. | A PC that is simply offline also alarms ("may be offline"). |
| **Lifecycle notices** | Service stopped (alarm), shutdown, sleep, resume, started, repaired (alarm), Safe Mode boot (alarm), setting changed. | A killed process sends nothing; the silence alarm covers it. |
| **Protection-off check** | The phone alarms when a report shows protection turned off unless a `protection-disabled` notice (sent only after phone approval or a recovery code) arrived within 10 minutes. This catches someone editing `state.json`. | — |
| **Watchdog** | A SYSTEM scheduled task runs at startup and every 5 minutes. It restores the service, the tile and filter registration, Safe Mode registration and the program files from a protected copy. It restores **only** if the copy still matches the install-time SHA-256 manifest. Each repair is reported. | An administrator can delete the task too; the next report (or the silence) reveals it. |
| **Safe Mode** | The agent is registered to start in Safe Mode and raises a Safe Mode alarm: immediately with networking, otherwise queued until the next normal start. | Windows does not load third-party sign-in tiles in Safe Mode, so the phone step is skipped there. The password is still required. |
| **BitLocker + PIN helper** | The companion turns on drive encryption with a startup PIN, or upgrades TPM-only to TPM+PIN. The recovery key is shown once and the owner must type its last 6 digits back. The PIN is passed over stdin, never stored or logged. | Needs a Windows edition with BitLocker (Pro/Enterprise/Education). |
| **Network sign-in block** | Optional `SeDenyNetworkLogonRight` for NT AUTHORITY\Local account (S-1-5-113). The password alone no longer works over SMB, WinRM or RDP-with-NLA. Unblocking while protection is on needs the phone or a recovery code. | Breaks inbound file sharing, remote PowerShell and Remote Desktop for local accounts, by design. |

## 5. Residual risks (software cannot close these)

Be honest with yourself about these. They are listed in the companion app too.

1. **Physical access without full-disk encryption.** An attacker can boot another OS, edit the
   registry, delete the provider, or use the `utilman.exe`/`sethc.exe` trick. **Mitigation:** turn
   on BitLocker **with a startup PIN** (TPM+PIN), Secure Boot, a firmware password, and Kernel DMA
   Protection. The installer warns when BitLocker is off.
2. **Safe Mode / WinRE.** Windows loads only its built-in providers in Safe Mode, so the phone
   step is skipped there. The Windows password is still needed. **Mitigation:** BitLocker TPM+PIN,
   plus a firmware password to stop unattended boot changes.
3. **An administrator who is already signed in** can uninstall PhoneGate or edit its files.
   PhoneGate protects the *lock screen*, not a machine that is already compromised. Turning
   protection off through the app requires the phone or a recovery code. A local admin with a
   shell can still remove the software.
4. **Network logons.** SMB, WinRM and `runas` accept the Windows password without the phone.
   **Mitigation:** deny "Access this computer from the network" to interactive accounts, and keep
   RDP off unless needed (RDP sign-in itself *is* gated).
5. **Compromised phone OS or TEE extraction.** Attestation checks the chain up to Google's pinned roots and checks intermediate certificate validity. It does not yet consult Google's attestation revocation list, so a device whose attestation keys were leaked would still pass. Tracked as future work.
   In addition, a rooted phone or unlocked bootloader could show
   fake details. Attestation rejects unlocked bootloaders at pairing. It cannot detect a
   compromise that happens later.
6. **Social engineering.** Someone reading the number to you over the phone. Only approve
   requests you started.
7. **Relay availability.** Whoever runs the relay can block requests, which is denial of service.
   They can never approve. Offline approval and recovery codes still work.
8. **Supply chain.** A malicious PhoneGate build is outside this model. Build from source, or
   verify release hashes and signatures.
9. **Firmware TPM attacks** (for example faulTPM on some AMD fTPMs) can extract TPM keys with
   physical access. BitLocker TPM+PIN still protects the disk.

## 6. Reporting vulnerabilities

Please open a private security advisory on the repository (GitHub → Security → Report a
vulnerability). Do not file public issues for security problems. We aim to respond within 7 days.

# Product

<!-- impeccable:product-schema 1 -->

## Platform

adaptive

Two surfaces with their own native expectations:

- **Android app**: native Jetpack Compose / Material 3 (API 30+).
- **Windows companion app**: a Tauri desktop app with a web UI, running elevated on Windows 10/11.

## Stack

- Android: Kotlin + Jetpack Compose (Material 3), CameraX + ZXing, OkHttp. Chosen in plan.md.
- Companion: Tauri 2 (Rust backend) + TypeScript/Vite web UI with no heavy framework. Delegated to
  the implementer: small, auditable dependencies, per Constitution VII.

## Users

Tech-savvy owners who self-host a small relay server (Docker on a VPS) and want their Windows PC
to stay locked until they approve each unlock from their Android phone. They understand terms like
"relay server", "TPM", and "BitLocker", but expect each one to be explained in plain words when it
matters. One owner, 1–10 PCs, one phone.

## Product Purpose

PhoneGate adds a mandatory phone approval to every Windows unlock, sign-in, and remote-desktop
sign-in. Success means that:

- The owner gets in within 15 s with a single typed number and a fingerprint.
- Nobody else gets in, even with the password, the full source code, or control of the server.
- The owner is never permanently locked out, because offline recovery codes always work.

## Positioning

- It is open source and self-hosted, with security that survives full disclosure. Approvals are
  signed by a biometric-bound hardware key on the phone and checked against a key the PC pinned at
  pairing.
- The relay server is untrusted by design. Unlike Duo-style products, there is no vendor cloud
  that could approve logins.

## Operating Context

- **Approval moment (hero)**: the owner sits at a locked PC. Their phone buzzes with a heads-up
  notification, and they must type the 2-digit number shown on the PC screen and then use their
  fingerprint. It happens many times a day, in seconds, often one-handed. An unexpected request
  means someone else is trying to get in.
- **Setup moment**: a one-time, deliberate session at the desk. The owner opens the companion on
  the PC, scans a QR code, compares a 6-digit code on both screens, saves 10 recovery codes, and
  types one back.
- **Emergency moment**: the phone is lost or offline. The owner uses a recovery code or the offline
  QR code from the lock screen.

## Capabilities and Constraints

- Pair via QR with SAS confirmation, and verify the phone's hardware key attestation.
- Approve / deny / "This wasn't me" with typed number matching.
- Requests expire after 60 s.
- 10 single-use recovery codes, and an offline QR challenge/response.
- History of attempts (90 days) on both devices.
- Multiple PCs per phone.
- Turning protection off requires a phone approval or a recovery code.
- The phone keeps a persistent connection to the relay, shown as an ongoing notification.
- Honest security warnings: no TPM, BitLocker off, RDP on, Safe Mode limits.

## Brand Commitments

The name **PhoneGate** is confirmed. There is no existing logo, palette, or style: the visual
identity is to be created fresh.

## Evidence on Hand

- Specs: `specs/001-phone-approved-unlock/`. Security research is in `research.md`.
- There are no users, testimonials, press, or benchmarks. Never invent any.

## Product Principles

1. **Unambiguous at a glance.** Who is asking, from which PC, for which account, and when must be
   readable in one second.
2. **Deny is never harder than approve.** Refusing must be at least as easy as accepting.
3. **Honest about limits.** Say plainly what PhoneGate cannot protect against. Never overclaim.
4. **Calm under pressure.** An unexpected request is alarming. The UI stays steady and gives one
   clear next step.
5. **Never a dead end.** Every failure state names the way back in: retry, offline code, or
   recovery code.

## Accessibility & Inclusion

WCAG 2.2 AA on both surfaces:

- screen-reader labels, and system font scaling up to 200%;
- touch targets ≥ 48dp;
- light and dark themes;
- color never the only signal (outcome states carry an icon and text);
- reduced-motion respected.

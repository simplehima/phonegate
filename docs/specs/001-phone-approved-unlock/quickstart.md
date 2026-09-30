# Quickstart & Validation Guide

> **Safety first**: never test the Credential Provider on a machine you can't afford to lose access
> to. Use a Windows VM with a snapshot, and keep your recovery codes.

## Prerequisites

- Rust stable (MSVC) · Visual Studio Build Tools (C++ workload, Windows SDK)
- Android SDK 36, JDK 17 · Node 20+ (companion UI) · Docker (relay)

## 1. Automated validation (any dev machine)

```powershell
cargo test --workspace                 # protocol, crypto, recovery, relay, E2E simulation
cargo clippy --workspace -- -D warnings
cd android; .\gradlew.bat testDebugUnitTest lintDebug   # includes shared protocol vectors
```

These must pass:

- `pg-core` vectors: encoding, HKDF, SAS, envelope, decision signatures, offline codes, recovery.
- `e2e_pairing_and_approval`: simulated PC + simulated phone + real relay. Pair, then approve.
- `e2e_malicious_relay`: a relay that tampers, replays, and substitutes keys. Nothing is ever
  accepted.
- `e2e_replay_and_expiry`: a replayed response, a response after expiry, the wrong key for approve,
  and a wrong typed number are all rejected.
- Android `ProtocolVectorsTest` consumes `protocol/vectors/*.json`.

## 2. Relay

```bash
cd deploy
cp .env.example .env        # set PG_DOMAIN=relay.example.com
docker compose up -d        # Caddy obtains a TLS cert automatically
curl https://relay.example.com/healthz   # → ok
```

## 3. Windows (in a VM)

```powershell
.\windows\scripts\build.ps1            # builds agent, CP DLL, companion
.\windows\scripts\install.ps1          # admin: installs the service, registers the CP (enforcement OFF)
```

1. Open **PhoneGate** (the companion). Set the relay URL and choose **Pair phone**. A QR code
   appears.
2. On the phone, open the PhoneGate app, tap **Add PC**, and scan the QR. Confirm with your
   fingerprint. Both screens show the same 6-digit code. Confirm on both.
3. Save the 10 recovery codes and type one back. Then choose **Turn on protection**.
4. Press Win+L and sign in with your password. The PC shows "Approve on your phone · 42". Type 42
   on the phone and use your fingerprint. The desktop appears. ✔ Story 1
5. Lock the PC again and tap **Deny** → the PC stays locked. ✔
6. Disconnect the VM network, lock, and sign in with a recovery code → unlocked; the same code now
   fails. ✔ Story 3
7. Use **Offline code** on the lock screen, scan the QR with the phone, and type the 10-digit
   code → unlocked. ✔ FR-026a
8. Tap **This wasn't me** on a request → it appears as suspicious in both histories. ✔ Story 4
9. Bypass checks (SC-005): the PIN, fingerprint, and "Other user" tiles are hidden; a restart then
   sign-in is gated; RDP sign-in is gated when RDP is enabled.

## 4. Uninstall

`.\windows\scripts\uninstall.ps1` (admin). It needs phone approval or a recovery code if protection
is on.

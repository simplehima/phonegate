# Implementation Plan: Tamper Alarm & Hardening

**Branch**: `002-tamper-hardening` | **Date**: 2026-09-27 | **Spec**: [spec.md](./spec.md)

## Summary

This feature adds four things:

- **Tamper alarm.** The PC sends a sealed `status` report with a monotonic sequence number and
  lifecycle notices (stopped, shutdown, sleep, repaired, Safe Mode). The phone evaluates alerts,
  including a silence alarm that the attacker cannot suppress.
- **Watchdog.** A SYSTEM scheduled task restores the service, the provider registration and the
  program files from a manifest-verified protected copy, and reports each repair.
- **BitLocker + PIN helper.** It adds the startup-PIN protector, and shows a recovery password once,
  which the owner must confirm.
- **Network sign-in block.** An opt-in LSA user right (`SeDenyNetworkLogonRight` on
  `S-1-5-113`). Unblocking needs phone approval.

Decisions are in [research.md](./research.md). Contracts:

- [protocol-v1-additions.md](./contracts/protocol-v1-additions.md)
- [agent-control-additions.md](./contracts/agent-control-additions.md)

## Technical Context

Same stack as feature 001: Rust (pg-core, agent), Kotlin/Compose (Android), and Tauri/TypeScript
(companion). New Windows APIs:

- LSA account rights (`Win32_Security_Authentication_Identity`);
- service power events;
- `GetSystemMetrics(SM_CLEANBOOT)`.

New tooling is the scheduled task (PowerShell, in the installer) and the BitLocker PowerShell
module, driven by the agent over stdin.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Kerckhoffs | ✅ | No new secrets. Reports are sealed with the existing pairing keys. |
| II. Untrusted relay | ✅ | The monotonic `seq` stops replay. A withheld report causes a false alarm, never false reassurance. |
| III. Hardware keys | ✅ | Unchanged. The BitLocker PIN is never stored. |
| IV. Fail-secure / honest recovery | ✅ | The watchdog never weakens protection. The BitLocker recovery password is confirmed before encryption starts. |
| V. Honest limits | ✅ | "Detection, not prevention" is stated in the UI and SECURITY.md. The Safe Mode limit is stated. |
| VI. Test-first | ✅ | Tests cover status vectors, seq/replay, the alert rule, watchdog `plan()`, the BitLocker script builders and parsers, and E2E notices. |
| VII. Memory-safe | ✅ | Rust and Kotlin only. PowerShell is limited to BitLocker cmdlets with no string interpolation of secrets. |
| VIII. Calm UX | ✅ | One alert per episode, with specific wording, and no alarms for normal sleep or shutdown. |

## Project Structure (changes)

```text
crates/pg-core/src/messages.rs        # Kind::Status, Status struct, NoticeKind additions, Scenario::ChangeSetting
crates/pg-core/src/health.rs          # shared alert-rule evaluator (reference for Android)
crates/pg-core/tests/vectors.rs       # + status vectors
windows/agent/src/engine.rs           # seq persistence, status send loop, lifecycle notices, netlogon approval
windows/agent/src/probe.rs            # StatusProbe trait (+ test impl)
windows/agent/src/watchdog.rs         # pure plan() + unit tests
windows/agent/src/win/{probe,watchdog_exec,bitlocker,netlogon,power}.rs
windows/agent/src/main.rs             # --watchdog, service power/shutdown events, safe-mode detection
windows/scripts/install.ps1           # protected copy + manifest, watchdog task, SafeBoot keys
windows/scripts/uninstall.ps1         # remove watchdog task first
tests/e2e/tests/tamper.rs             # status + notices through the real relay; forged/replayed status
crates/pg-sim/src/lib.rs              # phone-side status/health handling
android/…                             # status handling, health model, alerts, PC card states, change-setting
windows/companion/ui/…                # Hardening section: BitLocker wizard, network block, watchdog/alarm status
```

## Complexity Tracking

| Addition | Why needed | Simpler alternative rejected |
|----------|------------|------------------------------|
| A second process (watchdog task) | It must run when the service is gone | Service self-recovery alone cannot bring back a deleted service |
| PowerShell for BitLocker | The BitLocker WMI/COM surface is huge; the cmdlets are the supported interface | Hand-driving WMI methods adds more risk and more code |

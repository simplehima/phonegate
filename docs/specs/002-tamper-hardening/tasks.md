# Tasks: Tamper Alarm & Hardening

**Tests**: required (Constitution VI).

## Phase 1: Foundational (protocol)

- [X] T101 Add `Kind::Status`, a `Status` struct with strict decode (flags 0/1 only, bitlocker enum), `NoticeKind` additions (agent-started, agent-stopped, shutdown, sleep, resume, repaired, safe-mode-boot, setting-changed) and `Scenario::ChangeSetting` in `crates/pg-core/src/messages.rs`, with unit tests
- [X] T102 Add the shared alert-rule evaluator `crates/pg-core/src/health.rs` (contract §4: per-PC state, seq check, silence window, protection-off-without-notice, integrity, one alert per episode), with unit tests for every rule and for no alarm on sleep/shutdown
- [X] T103 Extend `crates/pg-core/tests/vectors.rs` with the status vectors and regenerate `protocol/vectors/v1.json` (existing entries unchanged)

## Phase 2: US1 Tamper alarm (P1)

- [X] T104 [US1] Add the `StatusProbe` trait and a test probe in `windows/agent/src/probe.rs`; Windows probe `windows/agent/src/win/probe.rs` (registry for CP/filter, file hashes vs manifest, watchdog task present, BitLocker, netlogon, SM_CLEANBOOT)
- [X] T105 [US1] Engine: persisted monotonic `status_seq`, status on connect + every 300 s + on change, lifecycle notices API (`lifecycle(kind, detail)`), agent-started / safe-mode-boot at start, in `windows/agent/src/engine.rs`
- [X] T106 [US1] Service: accept SHUTDOWN/PRESHUTDOWN/POWEREVENT; map STOP→agent-stopped, SHUTDOWN→shutdown, suspend→sleep, resume→resume; flush best-effort within 3 s, in `windows/agent/src/main.rs`
- [X] T107 [US1] pg-sim: phone-side status handling via `pg_core::health`
- [X] T108 [US1] E2E `tests/e2e/tests/tamper.rs`: status delivered and verified; seq replay rejected; forged/tampered status rejected; agent-stopped raises an alert; sleep then silence does not; protection off without notice alerts, with notice does not
- [X] T109 [P] [US1] Android: `Status` + notice kinds + `ChangeSetting` in protocol/, vectors test, health model mirroring pg-core health, 1-minute silence ticker, high-priority tamper notifications, PC card states (OK / Asleep / Off / Stopped reporting / Tamper alert) and drive-encryption / network warnings

## Phase 3: US2 Watchdog (P1)

- [X] T110 [US2] Pure `plan(observed) -> Vec<Action>` with rate limiting in `windows/agent/src/watchdog.rs`, with unit tests (service missing/stopped, registry missing/wrong path, file missing/altered, backup altered → report only, rate limit, SafeBoot keys)
- [X] T111 [US2] Windows executor `windows/agent/src/win/watchdog_exec.rs` (sc/registry/file restore with rename-in-use, pending repair notices) and `--watchdog` entry
- [X] T112 [US2] Installer: protected copy + `manifest.json` (SHA-256), SYSTEM scheduled task (startup + every 5 min), SafeBoot keys; uninstaller removes the task first

## Phase 4: US3 BitLocker helper (P2)

- [X] T113 [US3] `windows/agent/src/win/bitlocker.rs`: status parser, FVE policy writer, prepare (recovery protector), enable/upgrade with PIN over stdin; pure script builders/parsers unit-tested in `windows/agent/src/bitlocker_logic.rs`
- [X] T114 [US3] Control ops `bitlocker_status/prepare/enable` in `windows/agent/src/api.rs` + engine session holding the pending protector id and recovery-password check

## Phase 5: US4 Network sign-in block (P3)

- [X] T115 [US4] `windows/agent/src/win/netlogon.rs` LSA add/remove/query of `SeDenyNetworkLogonRight` for S-1-5-113; control ops `netlogon_status/set/unblock_begin/unblock_wait/unblock_recovery` with approval required to unblock while enforcing, and E2E test of the approval gate using a test netlogon backend

## Phase 6: UI & polish

- [X] T116 [P] Companion: Hardening section (tamper-alarm status + last report, watchdog status and repairs, BitLocker wizard with PIN twice → recovery key once → type last 6 → restart notice, network sign-in block toggle with side-effect warning and approval flow), visitor-log design, recaptures
- [X] T117 Update `docs/SECURITY.md` (detection vs prevention, Safe Mode, what each hardening does), README
- [X] T118 Final validation: all gates green, clippy, Android tests/lint, companion build, secret scan

# Quickstart & Validation: Tamper Alarm & Hardening

## Automated

```powershell
cargo test --workspace            # status vectors, seq/replay, alert rule, watchdog plan, bitlocker/netlogon builders, E2E tamper
cd android; .\gradlew.bat testDebugUnitTest   # status vectors + health/alert rule tests
cd windows\companion; npm run build
```

## In a Windows VM (with a vTPM) and a paired phone

1. `sc stop PhoneGateAgent`. The phone alerts "PhoneGate on <PC> was stopped" within 1 minute. The
   watchdog restarts the service within 5 minutes, and the phone logs "Repaired: service".
2. Sleep and wake the VM, then shut it down and start it. No alerts.
3. `taskkill /f /im phonegate-agent.exe`, then delete the Scheduled Task. After about 20 minutes the
   phone says "Stopped reporting".
4. Delete `HKLM\...\Credential Providers\{c8ee462b-…}`. Within 5 minutes it is restored and
   reported.
5. Boot into Safe Mode with Networking. The phone shows a Safe Mode alert.
6. Companion → Hardening → Turn on BitLocker with a PIN. Save the recovery key, type its last 6
   digits and restart. The PIN prompt appears at boot.
7. Companion → Block network sign-ins. From another machine, `net use \\VM\c$ /user:VM\owner`
   is denied. Unblocking asks for phone approval.

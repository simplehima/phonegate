# Contract: Protocol v1 additions (feature 002)

This is normative for `crates/pg-core` and the Android `protocol/` module. Everything in
`docs/specs/001-phone-approved-unlock/contracts/protocol.md` still holds. These additions are
backward-compatible: a receiver that does not know a new kind drops it.

## 1. New sealed wire kind: `status` (PC → phone)

```
plaintext = enc("phonegate/v1/status",
                seq, at,                       // u64, u64 (ms)
                enforce,                       // u64: 0 | 1
                cp_registered, filter_registered, files_intact, watchdog_present,   // u64 0|1 each
                bitlocker,                     // string: "off" | "on-no-pin" | "on-pin" | "unknown"
                netlogon_blocked,              // u64 0|1
                safe_mode)                     // u64 0|1 (this boot is Safe Mode)
```

- The kind is `status`. It is added to §5, and `is_sealed()` returns true for it.
- `seq` MUST increase strictly across reports from one PC, including across agent restarts. The
  phone MUST drop any report with `seq ≤ last_seq` for that PC.
- The PC sends a report:
  - when the relay connection comes up;
  - every 300 s;
  - within 5 s of any integrity or setting change.
  The relay TTL is 300 s.
- Decoding MUST reject any u64 flag that is not 0 or 1, and any unknown `bitlocker` value.

## 2. New notice kinds (`notice.notice_kind`)

| kind | Sent when | Phone alerts? |
|------|-----------|---------------|
| `agent-started` | the agent starts (detail: `boot` \| `restart`) | no (history only) |
| `agent-stopped` | a service STOP control is received | **yes** |
| `shutdown` | a SHUTDOWN/PRESHUTDOWN control is received | no; suppresses the silence alarm |
| `sleep` | suspend power event | no; suppresses the silence alarm |
| `resume` | resume power event | no |
| `repaired` | the watchdog repaired something (detail: item list) | **yes** |
| `safe-mode-boot` | the agent started in Safe Mode (detail: boot time) | **yes** |
| `setting-changed` | network sign-in block or BitLocker protector changed (detail: which) | history only |

Existing kinds are unchanged: `recovery-code-used`, `offline-code-used`, `protection-enabled`,
`protection-disabled`, `cooldown`.

## 3. New scenario: `change-setting`

Used by an `approval-request` when weakening a security setting while protection is on (FR-116).
The `account` field carries a human-readable setting description, for example
`Allow network sign-ins`. The phone shows the title "Change a security setting".

## 4. Phone alert rule (normative)

For each paired PC, the phone raises exactly one alert per episode when any of these holds:

1. It receives the notice `agent-stopped`, `repaired` or `safe-mode-boot`.
2. A `status` arrives with `enforce = 1` and any of `cp_registered`, `filter_registered` or
   `files_intact` equal to 0.
3. A `status` arrives with `enforce = 0` while the previous accepted status had `enforce = 1`, and
   no `protection-disabled` notice arrived in the preceding 10 minutes of phone time.
4. No `status` has arrived for 20 minutes of phone time, and the last lifecycle notice is not
   `shutdown` or `sleep`.

An episode ends when a `status` arrives with all integrity fields healthy.

## 5. Test vectors

`protocol/vectors/v1.json` gains a `status` section with:

- `plain`, a sealed `envelope`, and the `wire` form, for fixed values;
- a `notice_agent_stopped` plaintext;
- a `request_change_setting` plaintext.

Existing entries are unchanged.

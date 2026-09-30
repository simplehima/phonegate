# Data Model: Phone-Approved Windows Unlock

## PC side (`C:\ProgramData\PhoneGate\`, ACL: SYSTEM + Administrators only)

### `state.json`: PcState (written only by the agent; atomic write via temp + rename, under a file lock)

| Field | Type | Rule |
|-------|------|------|
| `version` | u32 | `1` |
| `pc_name` | string | 1–64 chars; default is the computer name |
| `relay_url` | string | `https://` URL. `http://` only to `localhost`/`127.0.0.1` for development |
| `key_backend` | `"tpm"` \| `"software"` | chosen at first start; `software` needs `software_ack = true` |
| `pc_pub` | b64 PUB | public half of the TPM/software identity key |
| `software_ack` | bool | owner acknowledged software-only key protection (no TPM) |
| `pairing` | Pairing? | at most one |
| `enforce` | bool | may become true only if `pairing` exists and `recovery.confirmed` |
| `history` | AttemptRecord[] | ring buffer, entries older than 90 days pruned |

### Pairing

| Field | Type | Rule |
|-------|------|------|
| `phone_id` | b64(32) | `ID(phone_device_pub)` |
| `phone_name` | string | ≤ 64 chars |
| `phone_device_pub` | b64 PUB | pinned |
| `phone_approve_pub` | b64 PUB | pinned; the only key accepted for `approve` |
| `attestation` | `{verified: bool, reason?: string}` | from protocol §3.4 |
| `accepted_unverified` | bool | true when the owner accepted an unverified attestation |
| `k_pair_wrapped` | b64 | `k_pair` wrapped with the TPM RSA key (OAEP) or with DPAPI machine scope |
| `paired_at` | u64 ms | |

### `identity-software.bin` (only without TPM)

DPAPI machine-scope blob holding the software P-256 identity scalar.

### `recovery.json`: RecoverySet (written by the agent or the CP under the same file lock)

| Field | Type | Rule |
|-------|------|------|
| `salt` | b64(32) | random per set |
| `codes` | `{hash: b64(32), used_at: u64?}[10]` | hash per protocol §7 |
| `confirmed` | bool | true once the owner typed one code back (FR-023) |
| `failures` | u32 | consecutive failures; reset on success |
| `lockouts` | u32 | lockouts applied so far (exponent for backoff) |
| `locked_until` | u64 ms | 0 = not locked |
| `pending_notices` | Notice[] | e.g. recovery-code-used, reported to the phone later |

### Runtime only (agent memory, never persisted)

- **OutstandingRequest**: `req_id`, `nonce`, `digest`, `match_number`, `expires_at`, `scenario`,
  `account`, `state` (pending → approved | denied | not_me | expired), `consumed` bool.
- **PairingSession**: `pairing_id`, `psk`, `pc_eph` (priv), `expires_at`, `state` (waiting →
  confirm → completed | failed), plus the phone's join data and `k_pair` in memory until
  completion. It is zeroized on drop.
- **OfflineChallenge**: `chal_id`, `body`, `expires_at`, `attempts_left`.
- **Cooldown**: timestamps of recent denied/expired requests, plus `cooldown_until`.

### State transitions

```
Unpaired ──pair_start──▶ PairingSession(waiting) ──pair-join ok──▶ confirm
confirm ──phone pair-confirm + owner accept──▶ Paired(recovery unconfirmed)
Paired ──recovery_confirm ok──▶ Paired(recovery confirmed) ──enable──▶ Enforcing
Enforcing ──disable (phone approve | recovery code)──▶ Paired
Paired (not enforcing) ──unpair──▶ Unpaired
Any failure in PairingSession ──▶ failed (pairing_id burned)
```

## Phone side (app-private storage; the JSON blob is encrypted with the Keystore `wrap` key)

### PhoneState

| Field | Type | Rule |
|-------|------|------|
| `device_name` | string | default `Build.MODEL` |
| `device_key_alias` | string | Keystore alias of the `device` key |
| `approve_key_alias` | string | Keystore alias of the `approve` key; re-pairing needed if invalidated |
| `pcs` | PairedPc[] | 0..n |
| `history` | AttemptRecord[] | 90-day retention |
| `seen_msg_ids` | map<b64, u64> | 24 h replay window |

### PairedPc

| Field | Type | Rule |
|-------|------|------|
| `pc_id` | b64(32) | `ID(pc_pub)` |
| `pc_pub` | b64 PUB | pinned from the QR hash plus the offer |
| `pc_name` | string | editable label (local rename) |
| `relay_url` | string | from the QR |
| `k_pair` | b64(32) | inside the encrypted blob |
| `k_offline_wrapped` | b64 | encrypted with the `offline-wrap` key (biometric per use) |
| `paired_at` | u64 | |

## Shared: AttemptRecord

| Field | Type | Values |
|-------|------|--------|
| `at` | u64 ms | |
| `pc_name` | string | |
| `account` | string | |
| `scenario` | string | unlock, logon, remote, disable-protection |
| `outcome` | string | approved, denied, not_me, expired, recovery_code, offline_code, wrong_number, error |
| `req_id` | b64? | |

## Relay (memory only)

- **Mailbox**: `id → VecDeque<{from, body, expires_at}>`, capped at `PG_MAX_QUEUE`.
- **Connections**: `id → Vec<Sender>`; `slot → Vec<(Sender, expires_at)>`.
- **Rate limiters**: token buckets per IP and per connection.

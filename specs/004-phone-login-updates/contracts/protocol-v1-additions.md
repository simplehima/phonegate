# Contract: Protocol v1 additions (feature 004)

Builds on 001/002 contracts, backward-compatible (unknown kinds are dropped). Normative for
`pg-core` and the Android `protocol/` module.

## 1. New sealed wire kind: `command` (phone → PC)

```
auth    = enc("phonegate/v1/command-auth", cmd_id16, nonce32, command, issued_at, expires_at)
approve_sig = SIGN_approve(auth)          // the phone's biometric-bound approve key
plaintext = enc("phonegate/v1/command",
                cmd_id16, nonce32, pc_id, phone_id, issued_at, expires_at, command, approve_sig)
```

- Wrapped in the standard sealed envelope (§4 of the 001 protocol), signed by the phone **device**
  key like all phone→PC traffic.
- `command` ∈ { `disable-protection` } (room for more later).
- `expires_at − issued_at ≤ 120000` ms.
- Acceptance on the PC (all required; any failure = ignore):
  1. envelope valid, `from` = paired phone, `to` = this PC, `msg_id` unseen (24 h);
  2. `pc_id`/`phone_id` match the pairing;
  3. `approve_sig` verifies against the pinned **approve** public key over `auth`;
  4. PC clock < `expires_at` and `issued_at ≤ now + 300000` (skew);
  5. `cmd_id` unseen (single-use).
  Only then is the command executed. `disable-protection` turns enforcement off and is a no-op if
  already off.

## 2. Vectors

`protocol/vectors/v1.json` gains a `command` section: `auth` bytes, `plain`, sealed `envelope`,
`wire`, with the fixed keys already in the file. Existing entries unchanged.

## 3. Update feed (not wire protocol; shared parse)

`pg-core::update` provides:
- `parse_latest_tag(json: &str) -> Option<String>` — reads `tag_name` from the GitHub
  "latest release" JSON.
- `is_newer(current: &str, latest: &str) -> bool` — semver-ish compare of `vX.Y.Z` / `X.Y.Z`
  (numeric dotted; missing parts = 0; non-numeric suffix ignored). Returns true only when `latest`
  is strictly greater.
Both are pure and covered by shared test vectors so the Kotlin and Rust/TS sides agree.

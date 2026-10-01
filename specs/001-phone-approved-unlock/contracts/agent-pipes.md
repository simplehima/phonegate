# Contract: Agent Local IPC (named pipes)

- **Framing**: each message is a `u32` little-endian length followed by that many bytes of UTF-8
  JSON. Max 64 KiB. One request gets one response.
- **Server**: `phonegate-agent` (LocalSystem). It creates each pipe with `FILE_FLAG_FIRST_PIPE_INSTANCE`
  and a DACL: `D:P(A;;GA;;;SY)(A;;GA;;;BA)`.
- **Clients**: MUST verify that the server process runs as SYSTEM (`GetNamedPipeServerProcessId`
  → process token user SID `S-1-5-18`) before sending anything.
- **Errors**: always `{"ok":false,"err":"<code>","detail":"..."}`.

## `\\.\pipe\phonegate.gate` (Credential Provider ↔ agent)

| op | request | response |
|----|---------|----------|
| `status` | `{}` | `{"ok":true,"enforce":bool,"paired":bool,"relay":"up"\|"down","cooldown_s":u32}` |
| `begin` | `{"scenario":"unlock"\|"logon"\|"remote","account":str,"remote":str}` | `{"ok":true,"req":b64,"number":u8,"expires_in_s":u32}` / err `not_paired`, `cooldown` (+`retry_s`), `relay_down` |
| `wait` | `{"req":b64,"timeout_ms":u32≤2000}` | `{"ok":true,"state":"pending"\|"approved"\|"denied"\|"not_me"\|"expired"\|"error"}` |
| `cancel` | `{"req":b64}` | `{"ok":true}` |
| `offline_begin` | `{"scenario":str,"account":str}` | `{"ok":true,"chal":b64,"qr":"PGO1:…","expires_in_s":60}` |
| `offline_verify` | `{"chal":b64,"code":str}` | `{"ok":true,"valid":bool,"attempts_left":u8,"locked_s":u32}` |
| `recovery_verify` | `{"code":str,"account":str}` | `{"ok":true,"valid":bool,"remaining":u8,"locked_s":u32}` |

An `approved` state is returned **once**. Every later `wait` for that id returns `expired`.

If the agent is unreachable, the CP verifies recovery codes directly against `recovery.json`,
using the same `pg-core` code and the same file lock.

## `\\.\pipe\phonegate.control` (Companion ↔ agent; Administrators only)

| op | request | response |
|----|---------|----------|
| `status` | `{}` | `Status` object (see data-model.md) |
| `settings_set` | `{"relay_url"?:str,"pc_name"?:str}` | `{"ok":true}`. Rejected while enforcing, unless re-paired. |
| `pair_start` | `{}` | `{"ok":true,"qr":str,"expires_at":u64}` |
| `pair_poll` | `{}` | `{"ok":true,"state":"waiting"\|"confirm"\|"completed"\|"failed","sas"?:str,"phone_name"?:str,"attestation"?:{"verified":bool,"reason"?:str},"error"?:str}` |
| `pair_decide` | `{"accept":bool,"accept_unverified":bool}` | `{"ok":true}` |
| `recovery_generate` | `{}` | `{"ok":true,"codes":[str;10]}`. Allowed right after pairing, or while not enforcing, or with a fresh approval token. |
| `recovery_confirm` | `{"code":str}` | `{"ok":true,"valid":bool}` |
| `enable` | `{}` | `{"ok":true}` / err `not_paired`, `recovery_unconfirmed` |
| `disable_begin` | `{}` | `{"ok":true,"req":b64,"number":u8}`, a phone approval with scenario `disable-protection` |
| `disable_wait` | `{"req":b64}` | `{"ok":true,"state":…}`; on `approved`, enforcement turns off |
| `disable_recovery` | `{"code":str}` | `{"ok":true,"valid":bool}`; on valid, enforcement turns off (the code is consumed) |
| `unpair` | `{}` | Only while not enforcing. It sends `unpair` to the phone and wipes the pairing. |
| `history` | `{"limit":u16}` | `{"ok":true,"items":[AttemptRecord]}` |
| `security_check` | `{}` | `{"ok":true,"tpm":bool,"bitlocker":"on"\|"off"\|"unknown","secure_boot":bool\|null,"rdp_enabled":bool,"passwordless_only":bool}` |

# Contract: Pipe additions (feature 004)

## Control pipe `\\.\pipe\phonegate.control` (Administrators + SYSTEM)

| op | request | response |
|----|---------|----------|
| `passwordless_status` | `{}` | `{"ok":true,"on":bool,"account":str?}` |
| `passwordless_enable` | `{"account":str,"password":str}` | `{"ok":true,"req":b64,"number":u8}` — stores the password TPM-wrapped *pending*, and starts a phone approval (scenario `change-setting`, account text "Turn on phone sign-in"). The password is never echoed back or logged. |
| `passwordless_enable_wait` | `{"req":b64,"timeout_ms":u32}` | `{"ok":true,"state":…}`; on `approved` passwordless is armed; on anything else the pending password is wiped. |
| `passwordless_disable` | `{}` | `{"ok":true}` — wipes the stored password and disarms (no approval needed; it only makes sign-in stricter). |
| `passwordless_update_password` | `{"password":str}` | `{"ok":true}` / err `not_armed` — replaces the stored password (after a Windows password change). |
| `update_check` | `{}` | `{"ok":true,"current":str,"latest":str?,"newer":bool}` — the agent performs the GitHub GET (companion may also do it directly). |

The password only ever travels companion→agent over the SYSTEM/Admin-only pipe, in a single field,
and is wiped from the request buffer after wrapping.

## Gate pipe `\\.\pipe\phonegate.gate` (SYSTEM / LogonUI)

| op | request | response |
|----|---------|----------|
| `release` | `{"req":b64}` | `{"ok":true,"serialization":b64,"package":u32,"clsid":b64}` / err `not_passwordless`, `not_approved`, `expired` |

`release` returns a packed `KERB_INTERACTIVE_LOGON` serialization for the stored account+password
**only** when: passwordless is on, `req` names a request this agent issued, that request reached
`approved`, and it has not been released before (one-shot, same consumption as `poll`). Otherwise an
error. The credential provider submits the returned serialization to LogonUI; LSA still performs the
real password check.

`status` gains `"passwordless":bool` so the tile knows whether to expect `release`.

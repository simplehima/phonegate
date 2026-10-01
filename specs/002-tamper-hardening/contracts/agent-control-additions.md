# Contract: Control-pipe additions (feature 002)

These ops are added to `\\.\pipe\phonegate.control` (Administrators and SYSTEM only). They use
the same framing and error shape as `specs/001-phone-approved-unlock/contracts/agent-pipes.md`.

| op | request | response |
|----|---------|----------|
| `health` | `{}` | `{"ok":true,"status":{…fields of the status plaintext…},"last_sent_at":u64,"watchdog":{"present":bool,"last_run_at":u64?,"last_repairs":[{"at":u64,"item":str}]}}` |
| `bitlocker_status` | `{}` | `{"ok":true,"supported":bool,"state":"off"\|"on-no-pin"\|"on-pin"\|"encrypting"\|"unknown","percent":u8?,"reason"?:str}` |
| `bitlocker_prepare` | `{}` | `{"ok":true,"recovery_password":str,"protector_id":str}`. It ensures the startup-PIN policy exists and adds a recovery-password protector. The password is shown once and is **not** stored by the agent. |
| `bitlocker_enable` | `{"pin":str,"recovery_last6":str}` | `{"ok":true,"restart_required":bool}` / err `bad_pin` (must be 6–20 digits), `recovery_mismatch`, `not_prepared`, `unsupported`, `failed` (+detail) |
| `netlogon_status` | `{}` | `{"ok":true,"blocked":bool}` |
| `netlogon_set` | `{"block":bool}` | `{"ok":true}`. Refused with `approval_required` when `block=false` while enforcing. |
| `netlogon_unblock_begin` | `{}` | `{"ok":true,"req":b64,"number":u8}`: an approval with scenario `change-setting` |
| `netlogon_unblock_wait` | `{"req":b64,"timeout_ms":u32≤2000}` | `{"ok":true,"state":…}`. On `approved` the block is removed. |
| `netlogon_unblock_recovery` | `{"code":str}` | `{"ok":true,"valid":bool,"locked_s":u32}`. On valid the block is removed, and the code is consumed. |

`security_check` gains `"netlogon_blocked":bool`, `"watchdog_present":bool` and
`"safe_mode_registered":bool`.

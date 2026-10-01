//! Client for the agent's gate pipe, plus the recovery-code fallback used when the agent is not
//! running (same file, same lock, same lockout as the agent).

use pg_core::ipc::GATE_PIPE;
use pg_core::recovery::{RecoverySet, VerifyOutcome};
use serde_json::{json, Value};

use crate::policy;

pub enum Begin {
    Started { req: String, number: u64, expires_in_s: u64 },
    Refused { code: String, retry_s: u64 },
}

pub struct CodeResult {
    pub valid: bool,
    pub remaining: u64,
    pub locked_s: u64,
}

#[cfg(windows)]
fn call(req: &Value) -> Result<Value, String> {
    let bytes = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    let resp = pg_core::ipc::client::call(GATE_PIPE, &bytes, 2_000).map_err(|e| e.to_string())?;
    serde_json::from_slice(&resp).map_err(|e| e.to_string())
}

#[cfg(not(windows))]
fn call(_req: &Value) -> Result<Value, String> {
    Err(format!("{GATE_PIPE} unavailable"))
}

pub fn begin(scenario: &str, account: &str, remote: &str) -> Begin {
    match call(&json!({"op":"begin","scenario":scenario,"account":account,"remote":remote})) {
        Ok(v) if v["ok"] == true => Begin::Started {
            req: v["req"].as_str().unwrap_or_default().to_string(),
            number: v["number"].as_u64().unwrap_or(0),
            expires_in_s: v["expires_in_s"].as_u64().unwrap_or(60),
        },
        Ok(v) => Begin::Refused { code: v["err"].as_str().unwrap_or("internal").to_string(), retry_s: v["retry_s"].as_u64().unwrap_or(0) },
        Err(_) => Begin::Refused { code: "agent_unavailable".into(), retry_s: 0 },
    }
}

/// One poll step: returns the request state, or `None` when the agent could not be reached.
pub fn wait(req: &str, timeout_ms: u64) -> Option<String> {
    call(&json!({"op":"wait","req":req,"timeout_ms":timeout_ms})).ok().and_then(|v| v["state"].as_str().map(str::to_string))
}

/// Passwordless (004): is phone-only sign-in armed for this PC? Read from the agent's gate status.
pub fn passwordless_on() -> bool {
    call(&json!({"op":"status"})).ok().and_then(|v| v["passwordless"].as_bool()).unwrap_or(false)
}

/// Releases the stored credential for an approved request (one-shot). Returns the packed logon
/// serialization bytes, or None if the agent declines (then the tile falls back to the password).
pub fn release(req: &str) -> Option<Vec<u8>> {
    let v = call(&json!({"op":"release","req":req})).ok()?;
    if v["ok"] != true {
        return None;
    }
    pg_core::crypto::b64::decode(v["serialization"].as_str()?).ok()
}

pub fn cancel(req: &str) {
    let _ = call(&json!({"op":"cancel","req":req}));
}

pub fn offline_begin(scenario: &str, account: &str) -> Result<(String, String), String> {
    let v = call(&json!({"op":"offline_begin","scenario":scenario,"account":account}))?;
    if v["ok"] != true {
        return Err(v["detail"].as_str().unwrap_or("offline approval unavailable").to_string());
    }
    Ok((v["chal"].as_str().unwrap_or_default().to_string(), v["qr"].as_str().unwrap_or_default().to_string()))
}

pub fn offline_verify(chal: &str, code: &str) -> CodeResult {
    match call(&json!({"op":"offline_verify","chal":chal,"code":code})) {
        Ok(v) if v["ok"] == true => CodeResult { valid: v["valid"] == true, remaining: v["attempts_left"].as_u64().unwrap_or(0), locked_s: v["locked_s"].as_u64().unwrap_or(0) },
        _ => CodeResult { valid: false, remaining: 0, locked_s: 0 },
    }
}

/// Recovery code check through the agent, or directly from `recovery.json` when the agent is down.
pub fn recovery_verify(code: &str, account: &str) -> CodeResult {
    if let Ok(v) = call(&json!({"op":"recovery_verify","code":code,"account":account})) {
        if v["ok"] == true {
            return CodeResult { valid: v["valid"] == true, remaining: v["remaining"].as_u64().unwrap_or(0), locked_s: v["locked_s"].as_u64().unwrap_or(0) };
        }
    }
    recovery_verify_file(&policy::recovery_path_for(&policy::state_path()), code)
}

pub fn recovery_verify_file(path: &std::path::Path, code: &str) -> CodeResult {
    let now = pg_core::now_ms();
    let r = pg_core::store::update_json::<RecoverySet, _>(path, |s| match s.as_mut() {
        Some(set) => set.verify_and_consume(code, now).map(Some),
        None => Ok(None),
    });
    match r {
        Ok(Some(VerifyOutcome::Valid { remaining })) => CodeResult { valid: true, remaining: remaining as u64, locked_s: 0 },
        Ok(Some(VerifyOutcome::Invalid { locked_ms })) => CodeResult { valid: false, remaining: 0, locked_s: locked_ms.div_ceil(1000) },
        Ok(Some(VerifyOutcome::Locked { remaining_ms })) => CodeResult { valid: false, remaining: 0, locked_s: remaining_ms.div_ceil(1000) },
        _ => CodeResult { valid: false, remaining: 0, locked_s: 0 },
    }
}

pub fn code_error_message(r: &CodeResult, what: &str) -> String {
    if r.locked_s > 0 {
        format!("Too many wrong codes. Try again in {} s.", r.locked_s)
    } else {
        format!("That {what} didn't work. Check it and try again.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_fallback_consumes_codes_and_locks() {
        let dir = std::env::temp_dir().join(format!("pg-cp-rec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("recovery.json");
        let (set, codes) = RecoverySet::generate().unwrap();
        pg_core::store::write_json_atomic(&p, &set).unwrap();
        assert!(recovery_verify_file(&p, &codes[0]).valid);
        assert!(!recovery_verify_file(&p, &codes[0]).valid, "single use (counts as failure 1)");
        for _ in 0..3 {
            assert_eq!(recovery_verify_file(&p, "nope").locked_s, 0);
        }
        let r = recovery_verify_file(&p, "nope");
        assert!(r.locked_s > 0);
        assert!(code_error_message(&r, "recovery code").contains("Try again in"));
        assert!(!recovery_verify_file(&p, &codes[1]).valid, "locked even for a valid code");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!recovery_verify_file(&dir.join("missing.json"), &codes[2]).valid);
    }
}

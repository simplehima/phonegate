//! JSON request dispatch for the two local pipes (contracts/agent-pipes.md).

use std::time::Duration;

use pg_core::crypto::b64;
use pg_core::messages::Scenario;
use pg_core::Error;
use serde_json::{json, Value};

use crate::engine::{Engine, GateError};

fn fail(code: &str, detail: impl std::fmt::Display) -> Value {
    json!({"ok": false, "err": code, "detail": detail.to_string()})
}

fn req_id(v: &Value, key: &str) -> Option<[u8; 16]> {
    v[key].as_str().and_then(|s| b64::decode_fixed::<16>(s).ok())
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("")
}

fn gate_err(e: GateError) -> Value {
    match e {
        GateError::Cooldown { retry_s } => json!({"ok": false, "err": "cooldown", "retry_s": retry_s}),
        GateError::Internal(d) => fail("internal", d),
        other => fail(other.code(), ""),
    }
}

/// `\\.\pipe\phonegate.gate` — used by the credential provider inside LogonUI.
pub async fn handle_gate(engine: &Engine, raw: &[u8]) -> Value {
    let Ok(v) = serde_json::from_slice::<Value>(raw) else {
        return fail("bad_request", "invalid json");
    };
    match v["op"].as_str().unwrap_or("") {
        "status" => {
            let s = engine.gate_status();
            json!({"ok": true, "enforce": s.enforce, "paired": s.paired, "relay": s.relay, "cooldown_s": s.cooldown_s, "passwordless": s.passwordless})
        }
        "release" => {
            let Some(id) = req_id(&v, "req") else { return fail("bad_request", "req") };
            match engine.release(&id) {
                Ok(ser) => json!({"ok": true, "serialization": pg_core::crypto::b64::encode(&ser)}),
                Err(code) => fail(code, ""),
            }
        }
        "begin" => {
            let scenario = match Scenario::parse(str_field(&v, "scenario")) {
                Ok(s @ (Scenario::Unlock | Scenario::Logon | Scenario::Remote)) => s,
                _ => return fail("bad_request", "scenario"),
            };
            match engine.begin(scenario, str_field(&v, "account"), str_field(&v, "remote")) {
                Ok(b) => json!({"ok": true, "req": b.req, "number": b.number, "expires_in_s": b.expires_in_s}),
                Err(e) => gate_err(e),
            }
        }
        "wait" => {
            let Some(id) = req_id(&v, "req") else { return fail("bad_request", "req") };
            let t = v["timeout_ms"].as_u64().unwrap_or(1000).min(2000);
            let s = engine.wait(&id, Duration::from_millis(t)).await;
            json!({"ok": true, "state": s.as_str()})
        }
        "cancel" => {
            let Some(id) = req_id(&v, "req") else { return fail("bad_request", "req") };
            engine.cancel(&id);
            json!({"ok": true})
        }
        "offline_begin" => {
            let scenario = Scenario::parse(str_field(&v, "scenario")).unwrap_or(Scenario::Unlock);
            match engine.offline_begin(scenario, str_field(&v, "account")) {
                Ok((chal, qr, exp)) => json!({"ok": true, "chal": chal, "qr": qr, "expires_in_s": exp}),
                Err(e) => fail("offline_unavailable", e),
            }
        }
        "offline_verify" => {
            let Some(id) = req_id(&v, "chal") else { return fail("bad_request", "chal") };
            match engine.offline_verify(&id, str_field(&v, "code")) {
                Ok(c) => json!({"ok": true, "valid": c.valid, "attempts_left": c.attempts_left, "locked_s": c.locked_s}),
                Err(e) => fail("internal", e),
            }
        }
        "recovery_verify" => match engine.recovery_verify(str_field(&v, "code"), str_field(&v, "account")) {
            Ok(c) => json!({"ok": true, "valid": c.valid, "remaining": c.remaining, "locked_s": c.locked_s}),
            Err(e) => fail("internal", e),
        },
        _ => fail("bad_request", "unknown op"),
    }
}

/// `\\.\pipe\phonegate.control` — used by the elevated companion app.
pub async fn handle_control(engine: &Engine, raw: &[u8], security: impl Fn() -> Value, watchdog: impl Fn() -> Value) -> Value {
    let Ok(v) = serde_json::from_slice::<Value>(raw) else {
        return fail("bad_request", "invalid json");
    };
    let ok = |r: pg_core::Result<()>| match r {
        Ok(()) => json!({"ok": true}),
        Err(e) => fail("refused", e),
    };
    match v["op"].as_str().unwrap_or("") {
        "status" => {
            let mut s = engine.status_json();
            s["ok"] = json!(true);
            s
        }
        "settings_set" => ok(engine.settings_set(v["relay_url"].as_str(), v["pc_name"].as_str(), v["software_ack"].as_bool())),
        "pair_start" => match engine.pair_start() {
            Ok((qr, exp)) => json!({"ok": true, "qr": qr, "expires_at": exp}),
            Err(e) => fail("refused", e),
        },
        "pair_poll" => {
            let mut p = serde_json::to_value(engine.pair_poll()).unwrap_or(Value::Null);
            p["ok"] = json!(true);
            p
        }
        "pair_decide" => ok(engine.pair_decide(v["accept"].as_bool().unwrap_or(false), v["accept_unverified"].as_bool().unwrap_or(false))),
        "recovery_generate" => match engine.recovery_generate() {
            Ok(codes) => json!({"ok": true, "codes": codes}),
            Err(e) => fail("refused", e),
        },
        "recovery_confirm" => match engine.recovery_confirm(str_field(&v, "code")) {
            Ok(valid) => json!({"ok": true, "valid": valid}),
            Err(e) => fail("internal", e),
        },
        "enable" => ok(engine.enable()),
        "disable_begin" => match engine.disable_begin() {
            Ok(Some(b)) => json!({"ok": true, "req": b.req, "number": b.number, "expires_in_s": b.expires_in_s}),
            Ok(None) => json!({"ok": true, "already_off": true}),
            Err(e) => gate_err(e),
        },
        "disable_wait" => {
            let Some(id) = req_id(&v, "req") else { return fail("bad_request", "req") };
            let t = v["timeout_ms"].as_u64().unwrap_or(1000).min(2000);
            match engine.disable_wait(&id, Duration::from_millis(t)).await {
                Ok(s) => json!({"ok": true, "state": s.as_str()}),
                Err(e) => fail("internal", e),
            }
        }
        "disable_recovery" => match engine.disable_recovery(str_field(&v, "code")) {
            Ok(c) => json!({"ok": true, "valid": c.valid, "remaining": c.remaining, "locked_s": c.locked_s}),
            Err(e) => fail("internal", e),
        },
        "unpair" => ok(engine.unpair()),
        "history" => {
            let limit = v["limit"].as_u64().unwrap_or(100).min(1000) as usize;
            json!({"ok": true, "items": engine.history_items(limit)})
        }
        "security_check" => {
            let mut s = security();
            s["ok"] = json!(true);
            s
        }
        // ---- feature 004: passwordless + update check ----
        "passwordless_status" => {
            let (on, account) = engine.passwordless_status();
            json!({"ok": true, "on": on, "account": account})
        }
        "passwordless_enable" => {
            let (account, password) = (str_field(&v, "account"), str_field(&v, "password"));
            if account.is_empty() || password.is_empty() {
                return fail("bad_request", "account and password are required");
            }
            match engine.passwordless_enable(account, password) {
                Ok(b) => json!({"ok": true, "req": b.req, "number": b.number, "expires_in_s": b.expires_in_s}),
                Err(e) => gate_err(e),
            }
        }
        "passwordless_enable_wait" => {
            let Some(id) = req_id(&v, "req") else { return fail("bad_request", "req") };
            let t = v["timeout_ms"].as_u64().unwrap_or(1000).min(2000);
            match engine.passwordless_enable_wait(&id, Duration::from_millis(t)).await {
                Ok(s) => json!({"ok": true, "state": s.as_str()}),
                Err(e) => fail("internal", e),
            }
        }
        "passwordless_disable" => match engine.passwordless_disable() {
            Ok(()) => json!({"ok": true}),
            Err(e) => fail("internal", e),
        },
        "passwordless_update_password" => match engine.passwordless_update_password(str_field(&v, "password")) {
            Ok(()) => json!({"ok": true}),
            Err(Error::State("not_armed")) => fail("not_armed", ""),
            Err(e) => fail("internal", e),
        },
        // ---- feature 002 ----
        "health" => {
            let mut h = engine.health_json(watchdog());
            h["ok"] = json!(true);
            h
        }
        "bitlocker_status" => match engine.bitlocker_status() {
            Ok(i) => json!({"ok": true, "supported": i.supported, "state": i.state, "percent": i.percent}),
            Err(e) => fail("failed", e),
        },
        "bitlocker_prepare" => match engine.bitlocker_prepare() {
            Ok((pw, id)) => json!({"ok": true, "recovery_password": pw, "protector_id": id}),
            Err(Error::State("unsupported")) => fail("unsupported", "this edition of Windows has no BitLocker"),
            Err(e) => fail("failed", e),
        },
        "bitlocker_enable" => match engine.bitlocker_enable(str_field(&v, "pin"), str_field(&v, "recovery_last6")) {
            Ok(restart) => json!({"ok": true, "restart_required": restart}),
            Err(Error::State(code @ ("bad_pin" | "recovery_mismatch" | "not_prepared"))) => fail(code, ""),
            Err(e) => fail("failed", e),
        },
        "netlogon_status" => match engine.netlogon_status() {
            Ok(b) => json!({"ok": true, "blocked": b}),
            Err(e) => fail("failed", e),
        },
        "netlogon_set" => match v["block"].as_bool() {
            None => fail("bad_request", "block"),
            Some(block) => match engine.netlogon_set(block) {
                Ok(()) => json!({"ok": true}),
                Err(Error::State("approval_required")) => fail("approval_required", "turning this off while protection is on needs your phone"),
                Err(e) => fail("failed", e),
            },
        },
        "netlogon_unblock_begin" => match engine.netlogon_unblock_begin() {
            Ok(b) => json!({"ok": true, "req": b.req, "number": b.number, "expires_in_s": b.expires_in_s}),
            Err(e) => gate_err(e),
        },
        "netlogon_unblock_wait" => {
            let Some(id) = req_id(&v, "req") else { return fail("bad_request", "req") };
            let t = v["timeout_ms"].as_u64().unwrap_or(1000).min(2000);
            match engine.netlogon_unblock_wait(&id, Duration::from_millis(t)).await {
                Ok(s) => json!({"ok": true, "state": s.as_str()}),
                Err(e) => fail("internal", e),
            }
        }
        "netlogon_unblock_recovery" => match engine.netlogon_unblock_recovery(str_field(&v, "code")) {
            Ok(c) => json!({"ok": true, "valid": c.valid, "locked_s": c.locked_s}),
            Err(e) => fail("internal", e),
        },
        _ => fail("bad_request", "unknown op"),
    }
}

//! PhoneGate companion backend.
//!
//! The web UI can reach exactly two commands:
//! - `agent`: forwards one allowlisted request to the agent's control pipe
//!   (`\\.\pipe\phonegate.control`, contracts/agent-pipes.md) and returns the agent's JSON reply.
//! - `qr_svg`: renders a QR code as SVG so the UI needs no JavaScript QR library.
//!
//! Everything else (the pairing state machine, recovery codes, enforcement) lives in the
//! LocalSystem agent. This process only relays requests it can name.

// A release build without `custom-protocol` would load the dev server (localhost:5173) instead of
// the bundled UI: "localhost refused to connect". Refuse to build that binary at all.
#[cfg(all(not(debug_assertions), not(feature = "custom-protocol")))]
compile_error!("release builds must enable the `custom-protocol` feature (cargo build --release --features custom-protocol)");

use serde_json::{Map, Value};

pub mod apk;

/// Connect timeout for the control pipe. The pipe server answers in milliseconds when it runs;
/// this only bounds how long we wait for a free pipe instance.
pub const CONNECT_TIMEOUT_MS: u32 = 3000;

/// Longest string field we forward. The agent enforces its own limits; this keeps a confused
/// UI from sending megabytes into a 64 KiB framed channel.
const MAX_STRING: usize = 512;

/// Largest text we render as a QR code (a pairing URI is ~200 bytes).
const MAX_QR_TEXT: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FieldKind {
    Str,
    Bool,
    Uint,
}

/// The control-pipe operations the companion may send, with the fields each accepts.
/// Anything not listed here never reaches the pipe.
const OPS: &[(&str, &[(&str, FieldKind)])] = &[
    ("status", &[]),
    (
        "settings_set",
        &[("relay_url", FieldKind::Str), ("pc_name", FieldKind::Str), ("software_ack", FieldKind::Bool)],
    ),
    ("pair_start", &[]),
    ("pair_poll", &[]),
    ("pair_decide", &[("accept", FieldKind::Bool), ("accept_unverified", FieldKind::Bool)]),
    ("recovery_generate", &[]),
    ("recovery_confirm", &[("code", FieldKind::Str)]),
    ("enable", &[]),
    ("disable_begin", &[]),
    ("disable_wait", &[("req", FieldKind::Str), ("timeout_ms", FieldKind::Uint)]),
    ("disable_recovery", &[("code", FieldKind::Str)]),
    ("unpair", &[]),
    ("history", &[("limit", FieldKind::Uint)]),
    ("security_check", &[]),
    // feature 002 (docs/specs/002-tamper-hardening/contracts/agent-control-additions.md)
    ("health", &[]),
    ("bitlocker_status", &[]),
    ("bitlocker_prepare", &[]),
    ("bitlocker_enable", &[("pin", FieldKind::Str), ("recovery_last6", FieldKind::Str)]),
    ("netlogon_status", &[]),
    ("netlogon_set", &[("block", FieldKind::Bool)]),
    ("netlogon_unblock_begin", &[]),
    ("netlogon_unblock_wait", &[("req", FieldKind::Str), ("timeout_ms", FieldKind::Uint)]),
    ("netlogon_unblock_recovery", &[("code", FieldKind::Str)]),
];

/// Returns true when `op` is one of the allowlisted control operations.
pub fn is_allowed_op(op: &str) -> bool {
    OPS.iter().any(|(name, _)| *name == op)
}

/// Validates a UI request against the allowlist and rebuilds it with only known, well-typed
/// fields. Errors are short machine codes the UI maps to plain-language messages.
pub fn sanitize(request: &Value) -> Result<Value, String> {
    let obj = request.as_object().ok_or_else(|| "bad_request".to_string())?;
    let op = obj.get("op").and_then(Value::as_str).ok_or_else(|| "bad_request".to_string())?;
    let (_, fields) = OPS.iter().find(|(name, _)| *name == op).ok_or_else(|| "op_not_allowed".to_string())?;
    let mut out = Map::new();
    out.insert("op".into(), Value::String(op.to_string()));
    for (key, value) in obj {
        if key == "op" {
            continue;
        }
        let kind = fields
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, k)| *k)
            .ok_or_else(|| format!("field_not_allowed:{key}"))?;
        let ok = match kind {
            FieldKind::Str => value.as_str().is_some_and(|s| s.len() <= MAX_STRING),
            FieldKind::Bool => value.is_boolean(),
            FieldKind::Uint => value.as_u64().is_some_and(|n| n <= 100_000),
        };
        if !ok {
            return Err(format!("bad_field:{key}"));
        }
        out.insert(key.clone(), value.clone());
    }
    Ok(Value::Object(out))
}

/// Maps a pipe-client failure to a stable code for the UI.
pub fn transport_error(e: &pg_core::Error) -> String {
    match e {
        pg_core::Error::Verify(_) => "agent_untrusted".into(),
        pg_core::Error::Io(m) if m.starts_with("agent unavailable") => "agent_unavailable".into(),
        _ => "agent_io".into(),
    }
}

/// Renders `text` as a QR code SVG (error correction M, 4-module quiet zone). Dark modules are
/// one path so the SVG stays small; colours are fixed dark-on-light because phone cameras scan
/// that most reliably in both UI themes.
pub fn render_qr(text: &str) -> Result<String, String> {
    if text.is_empty() || text.len() > MAX_QR_TEXT {
        return Err("qr_text_length".into());
    }
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)
        .map_err(|_| "qr_encode".to_string())?;
    let width = code.width();
    let quiet = 4usize;
    let size = width + 2 * quiet;
    let colors = code.to_colors();
    let mut d = String::with_capacity(width * width * 4);
    for y in 0..width {
        let mut x = 0;
        while x < width {
            if colors[y * width + x] == qrcode::Color::Dark {
                let start = x;
                while x < width && colors[y * width + x] == qrcode::Color::Dark {
                    x += 1;
                }
                d.push_str(&format!("M{} {}h{}v1h-{}z", start + quiet, y + quiet, x - start, x - start));
            } else {
                x += 1;
            }
        }
    }
    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" shape-rendering=\"crispEdges\" role=\"img\" aria-label=\"Pairing QR code\"><rect width=\"{size}\" height=\"{size}\" fill=\"#ffffff\"/><path fill=\"#10131a\" d=\"{d}\"/></svg>"
    ))
}

#[cfg(windows)]
fn call_agent(request: Vec<u8>) -> Result<Value, String> {
    let reply = pg_core::ipc::client::call(pg_core::ipc::CONTROL_PIPE, &request, CONNECT_TIMEOUT_MS).map_err(|e| transport_error(&e))?;
    serde_json::from_slice(&reply).map_err(|_| "agent_bad_reply".to_string())
}

#[cfg(not(windows))]
fn call_agent(_request: Vec<u8>) -> Result<Value, String> {
    Err("agent_unavailable".into())
}

#[tauri::command]
async fn agent(request: Value) -> Result<Value, String> {
    let clean = sanitize(&request)?;
    let bytes = serde_json::to_vec(&clean).map_err(|_| "bad_request".to_string())?;
    // Pipe I/O is blocking (disable_wait can hold for up to 2 s); keep it off the async runtime.
    tauri::async_runtime::spawn_blocking(move || call_agent(bytes)).await.map_err(|_| "agent_io".to_string())?
}

#[tauri::command]
fn qr_svg(text: String) -> Result<String, String> {
    render_qr(&text)
}

/// Where the bundled phone app is, its fingerprints, and whether the APK still matches the
/// build-time sidecar. Takes no input: the path comes from this executable's own location.
#[tauri::command]
async fn apk_info() -> Value {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return serde_json::json!({"found": false, "verified": false, "reason": "missing"}),
    };
    let Some(apk) = apk::apk_path_for_exe(&exe) else {
        return serde_json::json!({"found": false, "verified": false, "reason": "missing"});
    };
    tauri::async_runtime::spawn_blocking(move || apk::inspect(&apk))
        .await
        .unwrap_or_else(|_| serde_json::json!({"found": false, "verified": false, "reason": "unreadable"}))
}

/// Opens Explorer with `PhoneGate.apk` selected. Takes no input; the path is re-derived and
/// validated here, and Explorer is started from the Windows folder, not from PATH.
#[tauri::command]
fn reveal_apk() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|_| "apk_missing".to_string())?;
    let path = apk::validated_reveal_path(&exe)?;
    open_explorer_select(&path)
}

#[cfg(windows)]
fn open_explorer_select(path: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let windir = std::env::var_os("SystemRoot").map(std::path::PathBuf::from).unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
    // Explorer parses `/select,"<path>"` itself, so the argument is passed raw. The path was
    // validated to contain no quote characters.
    std::process::Command::new(windir.join("explorer.exe"))
        .raw_arg(format!("/select,\"{path}\""))
        .spawn()
        .map(|_| ())
        .map_err(|_| "explorer_failed".to_string())
}

#[cfg(not(windows))]
fn open_explorer_select(_path: &str) -> Result<(), String> {
    Err("explorer_failed".into())
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![agent, qr_svg, apk_info, reveal_apk])
        .run(tauri::generate_context!())
        .expect("error while running PhoneGate");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CONTRACT_OPS: [&str; 23] = [
        "status",
        "settings_set",
        "pair_start",
        "pair_poll",
        "pair_decide",
        "recovery_generate",
        "recovery_confirm",
        "enable",
        "disable_begin",
        "disable_wait",
        "disable_recovery",
        "unpair",
        "history",
        "security_check",
        "health",
        "bitlocker_status",
        "bitlocker_prepare",
        "bitlocker_enable",
        "netlogon_status",
        "netlogon_set",
        "netlogon_unblock_begin",
        "netlogon_unblock_wait",
        "netlogon_unblock_recovery",
    ];

    #[test]
    fn allowlist_is_exactly_the_control_contract() {
        for op in CONTRACT_OPS {
            assert!(is_allowed_op(op), "{op} should be allowed");
        }
        assert_eq!(OPS.len(), CONTRACT_OPS.len());
    }

    #[test]
    fn gate_pipe_and_unknown_ops_are_refused() {
        for op in ["begin", "wait", "cancel", "offline_begin", "offline_verify", "recovery_verify", "", "STATUS", "status "] {
            assert!(!is_allowed_op(op), "{op:?} must not be allowed");
            assert_eq!(sanitize(&json!({"op": op})).unwrap_err(), "op_not_allowed");
        }
    }

    #[test]
    fn malformed_requests_are_refused() {
        assert_eq!(sanitize(&json!("status")).unwrap_err(), "bad_request");
        assert_eq!(sanitize(&json!({})).unwrap_err(), "bad_request");
        assert_eq!(sanitize(&json!({"op": 3})).unwrap_err(), "bad_request");
    }

    #[test]
    fn unknown_or_mistyped_fields_are_refused() {
        assert_eq!(sanitize(&json!({"op": "status", "enforce": false})).unwrap_err(), "field_not_allowed:enforce");
        assert_eq!(sanitize(&json!({"op": "pair_decide", "accept": "yes"})).unwrap_err(), "bad_field:accept");
        assert_eq!(sanitize(&json!({"op": "history", "limit": -1})).unwrap_err(), "bad_field:limit");
        let long = "x".repeat(MAX_STRING + 1);
        assert_eq!(sanitize(&json!({"op": "recovery_confirm", "code": long})).unwrap_err(), "bad_field:code");
    }

    #[test]
    fn valid_requests_pass_through_unchanged() {
        let r = json!({"op": "settings_set", "relay_url": "https://relay.example", "pc_name": "Desk", "software_ack": true});
        assert_eq!(sanitize(&r).unwrap(), r);
        let r = json!({"op": "disable_wait", "req": "AAAAAAAAAAAAAAAAAAAAAA==", "timeout_ms": 1500});
        assert_eq!(sanitize(&r).unwrap(), r);
    }

    #[test]
    fn hardening_ops_enforce_field_types() {
        let r = json!({"op": "bitlocker_enable", "pin": "12345678", "recovery_last6": "123456"});
        assert_eq!(sanitize(&r).unwrap(), r);
        assert_eq!(sanitize(&json!({"op": "bitlocker_enable", "pin": 12345678})).unwrap_err(), "bad_field:pin");
        assert_eq!(sanitize(&json!({"op": "bitlocker_enable", "recovery_last6": 123456})).unwrap_err(), "bad_field:recovery_last6");
        let r = json!({"op": "netlogon_set", "block": true});
        assert_eq!(sanitize(&r).unwrap(), r);
        assert_eq!(sanitize(&json!({"op": "netlogon_set", "block": "false"})).unwrap_err(), "bad_field:block");
        let r = json!({"op": "netlogon_unblock_wait", "req": "AAAAAAAAAAAAAAAAAAAAAA==", "timeout_ms": 1500});
        assert_eq!(sanitize(&r).unwrap(), r);
        assert_eq!(sanitize(&json!({"op": "netlogon_unblock_wait", "timeout_ms": "1500"})).unwrap_err(), "bad_field:timeout_ms");
        let r = json!({"op": "netlogon_unblock_recovery", "code": "ABCD-EFGH"});
        assert_eq!(sanitize(&r).unwrap(), r);
        assert_eq!(sanitize(&json!({"op": "netlogon_unblock_recovery", "code": false})).unwrap_err(), "bad_field:code");
        // The prepared recovery password stays in the agent's reply; nothing may be sent back in.
        assert_eq!(sanitize(&json!({"op": "bitlocker_prepare", "recovery_password": "x"})).unwrap_err(), "field_not_allowed:recovery_password");
        assert_eq!(sanitize(&json!({"op": "health", "status": {}})).unwrap_err(), "field_not_allowed:status");
        assert_eq!(sanitize(&json!({"op": "netlogon_set", "block": false, "force": true})).unwrap_err(), "field_not_allowed:force");
    }

    #[test]
    fn transport_errors_map_to_codes() {
        assert_eq!(transport_error(&pg_core::Error::Io("agent unavailable: not found".into())), "agent_unavailable");
        assert_eq!(transport_error(&pg_core::Error::Verify("pipe server is not LocalSystem")), "agent_untrusted");
        assert_eq!(transport_error(&pg_core::Error::Io("frame too large".into())), "agent_io");
    }

    #[test]
    fn qr_svg_renders_a_square_code() {
        let svg = render_qr("phonegate://pair?v=1&r=https%3A%2F%2Frelay.example&i=abc").unwrap();
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        assert!(svg.contains("<path fill=\"#10131a\" d=\"M"));
        assert!(render_qr("").is_err());
        assert!(render_qr(&"a".repeat(MAX_QR_TEXT + 1)).is_err());
    }
}

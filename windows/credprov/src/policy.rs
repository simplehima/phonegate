//! Pure decision logic (unit-tested): enforcement state, filter decisions, scenario mapping and
//! user-facing messages. No Win32 calls here.

use std::path::{Path, PathBuf};

/// `C:\ProgramData\PhoneGate\state.json` (SYSTEM + Administrators only).
pub fn state_path() -> PathBuf {
    let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("PhoneGate").join("state.json")
}

pub fn recovery_path_for(state: &Path) -> PathBuf {
    state.with_file_name("recovery.json")
}

/// Whether enforcement is on. Missing file = not installed/paired yet = off. A file that exists
/// but cannot be read or parsed means enforcement **on** (fail-secure).
pub fn enforcing(state: &Path) -> bool {
    match std::fs::read(state) {
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(v) => v.get("enforce").and_then(|e| e.as_bool()).unwrap_or(true),
            Err(_) => true,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    Logon,
    Unlock,
    CredUi,
    ChangePassword,
    Other,
}

/// Filter decision: while enforcing, on logon/unlock only PhoneGate's provider is allowed.
/// Every other provider (Password, PIN, fingerprint, face, smart card, third-party) is hidden.
/// CredUI and password change are never filtered (Microsoft requirement; FR-002a).
pub fn filter(usage: Usage, enforce: bool, providers: &[u128], ours: u128, allow: &mut [bool]) {
    if !enforce || !matches!(usage, Usage::Logon | Usage::Unlock) {
        return;
    }
    for (i, p) in providers.iter().enumerate() {
        allow[i] = *p == ours;
    }
}

/// Maps the usage scenario (and whether this is a remote session) to the protocol scenario.
pub fn scenario(usage: Usage, remote: bool) -> Option<&'static str> {
    match (usage, remote) {
        (Usage::Logon | Usage::Unlock, true) => Some("remote"),
        (Usage::Logon, false) => Some("logon"),
        (Usage::Unlock, false) => Some("unlock"),
        _ => None,
    }
}

/// Text shown on the lock screen for an agent error code from `begin`.
pub fn begin_error_message(code: &str, retry_s: u64) -> String {
    match code {
        "not_paired" => "This PC isn't paired with a phone. Use a recovery code to sign in.".into(),
        "relay_down" => "Can't reach the PhoneGate server. Use Offline approval or a recovery code.".into(),
        "cooldown" => format!("Too many unanswered or denied requests. Try again in {retry_s} s, or use a recovery code."),
        "agent_unavailable" => "The PhoneGate service isn't running. Use a recovery code to sign in.".into(),
        _ => "PhoneGate couldn't send the request. Try again, or use a recovery code.".into(),
    }
}

/// Text for a terminal request state.
pub fn outcome_message(state: &str) -> &'static str {
    match state {
        "denied" => "The request was denied on your phone.",
        "not_me" => "The request was reported as not you. This attempt was logged.",
        "expired" => "The request expired. Sign in again to send a new one.",
        _ => "The approval couldn't be verified. Sign in again.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: u128 = 0xA;
    const PW: u128 = 0x60b78e88_ead8_445c_9cfd_0b87f74ea6cd;
    const PIN: u128 = 0xB;

    #[test]
    fn filter_hides_everything_but_us_when_enforcing() {
        let providers = [PW, OURS, PIN];
        for usage in [Usage::Logon, Usage::Unlock] {
            let mut allow = [true; 3];
            filter(usage, true, &providers, OURS, &mut allow);
            assert_eq!(allow, [false, true, false]);
        }
    }

    #[test]
    fn filter_leaves_credui_and_disabled_state_alone() {
        let providers = [PW, OURS, PIN];
        let mut allow = [true; 3];
        filter(Usage::CredUi, true, &providers, OURS, &mut allow);
        assert_eq!(allow, [true; 3]);
        filter(Usage::ChangePassword, true, &providers, OURS, &mut allow);
        assert_eq!(allow, [true; 3]);
        filter(Usage::Logon, false, &providers, OURS, &mut allow);
        assert_eq!(allow, [true; 3]);
    }

    #[test]
    fn enforcement_is_fail_secure() {
        let dir = std::env::temp_dir().join(format!("pg-cp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("state.json");
        let _ = std::fs::remove_file(&p);
        assert!(!enforcing(&p), "missing file: not installed");
        std::fs::write(&p, br#"{"enforce":false}"#).unwrap();
        assert!(!enforcing(&p));
        std::fs::write(&p, br#"{"enforce":true}"#).unwrap();
        assert!(enforcing(&p));
        std::fs::write(&p, b"{corrupt").unwrap();
        assert!(enforcing(&p), "corrupt state must enforce");
        std::fs::write(&p, br#"{"other":1}"#).unwrap();
        assert!(enforcing(&p), "missing field must enforce");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scenario_mapping() {
        assert_eq!(scenario(Usage::Unlock, false), Some("unlock"));
        assert_eq!(scenario(Usage::Logon, false), Some("logon"));
        assert_eq!(scenario(Usage::Logon, true), Some("remote"));
        assert_eq!(scenario(Usage::CredUi, false), None);
    }
}

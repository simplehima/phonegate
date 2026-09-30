//! Install layout shared by the probe, the watchdog and the installer scripts. These values must
//! match `windows/scripts/install.ps1` and `windows/credprov/src/lib.rs`.

use std::path::PathBuf;

pub const SERVICE_NAME: &str = "PhoneGateAgent";
pub const TASK_NAME: &str = "PhoneGate Watchdog";
pub const CLSID_PROVIDER: &str = "{c8ee462b-90e1-4c2f-994d-1d808359162f}";
pub const CLSID_FILTER: &str = "{44d3bbdf-b4a3-4bb0-acf0-114f5587c1e5}";
pub const AUTH_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication";
pub const AGENT_EXE: &str = "phonegate-agent.exe";
pub const CP_DLL: &str = "phonegate_cp.dll";

pub fn install_dir() -> PathBuf {
    let pf = std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    pf.join("PhoneGate")
}

pub fn data_dir() -> PathBuf {
    crate::state::Paths::system_default().dir
}

/// Protected copy of the binaries (SYSTEM + Administrators only) and its manifest.
pub fn backup_dir() -> PathBuf {
    data_dir().join("bin")
}

pub fn manifest_path() -> PathBuf {
    backup_dir().join("manifest.json")
}

pub fn watchdog_memory_path() -> PathBuf {
    data_dir().join("watchdog.json")
}

pub fn task_file() -> PathBuf {
    let win = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    win.join("System32").join("Tasks").join(TASK_NAME)
}

/// `{ "files": { "<name>": "<sha256 hex>" } }` written by the installer.
pub fn read_manifest() -> Option<Vec<(String, [u8; 32])>> {
    let raw = std::fs::read(manifest_path()).ok()?;
    let raw = raw.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&raw);
    let v: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let files = v["files"].as_object()?;
    let mut out = Vec::new();
    for (name, h) in files {
        let hex = h.as_str()?;
        if hex.len() != 64 {
            return None;
        }
        let mut arr = [0u8; 32];
        for (i, b) in arr.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        out.push((name.clone(), arr));
    }
    Some(out)
}

pub fn sha256_file(p: &std::path::Path) -> Option<[u8; 32]> {
    std::fs::read(p).ok().map(|b| pg_core::crypto::sha256(&b))
}

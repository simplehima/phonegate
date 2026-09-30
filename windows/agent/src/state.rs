//! Persistent PC state (data-model.md). Files live in `C:\ProgramData\PhoneGate` with an ACL that
//! only allows SYSTEM and Administrators.

use std::path::{Path, PathBuf};

use pg_core::attestation::AttestationResult;
use serde::{Deserialize, Serialize};

pub const STATE_FILE: &str = "state.json";
pub const RECOVERY_FILE: &str = "recovery.json";
pub const HISTORY_RETENTION_MS: u64 = 90 * 24 * 60 * 60 * 1000;
pub const HISTORY_MAX: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pairing {
    pub phone_id: String,
    pub phone_name: String,
    pub phone_device_pub: String,
    pub phone_approve_pub: String,
    pub attestation: AttestationResult,
    pub accepted_unverified: bool,
    pub k_pair_wrapped: String,
    pub paired_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub at: u64,
    pub pc_name: String,
    pub account: String,
    pub scenario: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub req_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcState {
    pub version: u32,
    pub pc_name: String,
    pub relay_url: String,
    pub key_backend: String,
    #[serde(default)]
    pub software_ack: bool,
    pub pc_pub: String,
    #[serde(default)]
    pub pairing: Option<Pairing>,
    pub enforce: bool,
    #[serde(default)]
    pub history: Vec<AttemptRecord>,
    /// Monotonic status-report sequence (feature 002), persisted so it survives restarts.
    #[serde(default)]
    pub status_seq: u64,
}

impl PcState {
    pub fn push_history(&mut self, rec: AttemptRecord) {
        let cutoff = rec.at.saturating_sub(HISTORY_RETENTION_MS);
        self.history.retain(|h| h.at >= cutoff);
        self.history.push(rec);
        if self.history.len() > HISTORY_MAX {
            let drop = self.history.len() - HISTORY_MAX;
            self.history.drain(..drop);
        }
    }
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub dir: PathBuf,
}

impl Paths {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Paths { dir: dir.as_ref().to_path_buf() }
    }

    /// `%ProgramData%\PhoneGate`.
    pub fn system_default() -> Self {
        let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        Paths { dir: base.join("PhoneGate") }
    }

    pub fn state(&self) -> PathBuf {
        self.dir.join(STATE_FILE)
    }

    pub fn recovery(&self) -> PathBuf {
        self.dir.join(RECOVERY_FILE)
    }

    /// DPAPI-protected software identity key (only on PCs without a TPM).
    pub fn software_key(&self) -> PathBuf {
        self.dir.join("identity-software.bin")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_prunes_by_age_and_count() {
        let mut s = PcState {
            version: 1,
            pc_name: "x".into(),
            relay_url: "https://r".into(),
            key_backend: "software".into(),
            software_ack: true,
            pc_pub: String::new(),
            pairing: None,
            enforce: false,
            history: vec![],
            status_seq: 0,
        };
        let rec = |at| AttemptRecord { at, pc_name: "x".into(), account: "a".into(), scenario: "unlock".into(), outcome: "approved".into(), req_id: None };
        s.push_history(rec(0));
        s.push_history(rec(HISTORY_RETENTION_MS + 10));
        assert_eq!(s.history.len(), 1, "90-day-old entry pruned");
        for i in 0..(HISTORY_MAX + 5) {
            s.push_history(rec(HISTORY_RETENTION_MS + 20 + i as u64));
        }
        assert_eq!(s.history.len(), HISTORY_MAX);
    }
}

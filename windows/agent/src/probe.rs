//! Platform interfaces used by the engine for feature 002. Windows implementations live in
//! `win::{probe, bitlocker, netlogon}`; [`Platform::fake`] backs the tests.

use std::sync::{Arc, Mutex};

use pg_core::messages::BitLocker;
use pg_core::Result;
use serde::Serialize;

/// Live integrity observations (everything in a status report except seq/at/enforce).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub cp_registered: bool,
    pub filter_registered: bool,
    pub files_intact: bool,
    pub watchdog_present: bool,
    pub bitlocker: BitLocker,
    pub netlogon_blocked: bool,
    pub safe_mode: bool,
}

pub trait StatusProbe: Send + Sync {
    fn probe(&self) -> Probe;
}

pub trait NetLogon: Send + Sync {
    fn blocked(&self) -> Result<bool>;
    fn set_blocked(&self, block: bool) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BitLockerInfo {
    pub supported: bool,
    /// `off` | `on-no-pin` | `on-pin` | `encrypting` | `unknown`
    pub state: String,
    pub percent: Option<u8>,
}

pub trait BitLockerOps: Send + Sync {
    fn status(&self) -> Result<BitLockerInfo>;
    /// Ensures the startup-PIN policy and adds a recovery-password protector.
    /// Returns `(recovery_password, protector_id)`.
    fn prepare(&self) -> Result<(String, String)>;
    /// Enables BitLocker with TPM+PIN, or upgrades TPM-only to TPM+PIN. Returns whether a restart
    /// is required.
    fn enable(&self, pin: &str) -> Result<bool>;
}

#[derive(Clone)]
pub struct Platform {
    pub probe: Arc<dyn StatusProbe>,
    pub netlogon: Arc<dyn NetLogon>,
    pub bitlocker: Arc<dyn BitLockerOps>,
}

// ------------------------------------------------------------------------------------------
// Test doubles
// ------------------------------------------------------------------------------------------

pub struct FakeProbe(pub Mutex<Probe>);

impl StatusProbe for FakeProbe {
    fn probe(&self) -> Probe {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

#[derive(Default)]
pub struct FakeNetLogon(pub Mutex<bool>);

impl NetLogon for FakeNetLogon {
    fn blocked(&self) -> Result<bool> {
        Ok(*self.0.lock().unwrap_or_else(|p| p.into_inner()))
    }
    fn set_blocked(&self, block: bool) -> Result<()> {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = block;
        Ok(())
    }
}

#[derive(Default)]
pub struct FakeBitLocker {
    pub state: Mutex<String>,
    pub last_pin: Mutex<Option<String>>,
}

impl BitLockerOps for FakeBitLocker {
    fn status(&self) -> Result<BitLockerInfo> {
        Ok(BitLockerInfo { supported: true, state: self.state.lock().unwrap_or_else(|p| p.into_inner()).clone(), percent: None })
    }
    fn prepare(&self) -> Result<(String, String)> {
        Ok(("111111-222222-333333-444444-555555-666666-777777-123456".into(), "{fake-protector}".into()))
    }
    fn enable(&self, pin: &str) -> Result<bool> {
        *self.last_pin.lock().unwrap_or_else(|p| p.into_inner()) = Some(pin.to_string());
        *self.state.lock().unwrap_or_else(|p| p.into_inner()) = "on-pin".into();
        Ok(true)
    }
}

pub struct Fakes {
    pub probe: Arc<FakeProbe>,
    pub netlogon: Arc<FakeNetLogon>,
    pub bitlocker: Arc<FakeBitLocker>,
}

impl Platform {
    /// Healthy fake platform plus handles to mutate it from tests.
    pub fn fake() -> (Platform, Fakes) {
        let probe = Arc::new(FakeProbe(Mutex::new(Probe {
            cp_registered: true,
            filter_registered: true,
            files_intact: true,
            watchdog_present: true,
            bitlocker: BitLocker::OnPin,
            netlogon_blocked: false,
            safe_mode: false,
        })));
        let netlogon = Arc::new(FakeNetLogon::default());
        let bitlocker = Arc::new(FakeBitLocker { state: Mutex::new("off".into()), last_pin: Mutex::new(None) });
        (
            Platform { probe: probe.clone(), netlogon: netlogon.clone(), bitlocker: bitlocker.clone() },
            Fakes { probe, netlogon, bitlocker },
        )
    }
}

/// Validates a BitLocker startup PIN (FR-112): 6-20 ASCII digits.
pub fn valid_pin(pin: &str) -> bool {
    (6..=20).contains(&pin.len()) && pin.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_rules() {
        assert!(valid_pin("123456"));
        assert!(valid_pin(&"9".repeat(20)));
        assert!(!valid_pin("12345"));
        assert!(!valid_pin(&"9".repeat(21)));
        assert!(!valid_pin("12345a"));
        assert!(!valid_pin("١٢٣٤٥٦"), "non-ASCII digits rejected");
    }
}

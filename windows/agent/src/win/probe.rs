//! Live integrity probe for status reports (feature 002). Every field is observed, never taken
//! from configuration. BitLocker (a PowerShell call) is cached for 10 minutes.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pg_core::messages::BitLocker;
use windows::core::HSTRING;
use windows::Win32::System::Registry::{RegGetValueW, HKEY, HKEY_CLASSES_ROOT, HKEY_LOCAL_MACHINE, RRF_RT_ANY, RRF_RT_REG_SZ};
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CLEANBOOT};

use super::layout;
use crate::bitlocker_logic;
use crate::probe::{BitLockerOps, NetLogon, Probe, StatusProbe};

pub fn key_exists(root: HKEY, sub: &str) -> bool {
    // SAFETY: existence query with no output buffer.
    unsafe { RegGetValueW(root, &HSTRING::from(sub), None, RRF_RT_ANY, None, None, None).is_ok() }
}

pub fn reg_string(root: HKEY, sub: &str, value: Option<&str>) -> Option<String> {
    let mut len = 0u32;
    let v = value.map(HSTRING::from);
    let vp = v.as_ref().map(|h| windows::core::PCWSTR(h.as_ptr())).unwrap_or(windows::core::PCWSTR::null());
    // SAFETY: two-call size pattern into a u16 buffer of the reported size.
    unsafe {
        RegGetValueW(root, &HSTRING::from(sub), vp, RRF_RT_REG_SZ, None, None, Some(&mut len)).ok().ok()?;
        let mut buf = vec![0u16; (len as usize).div_ceil(2)];
        RegGetValueW(root, &HSTRING::from(sub), vp, RRF_RT_REG_SZ, None, Some(buf.as_mut_ptr().cast()), Some(&mut len)).ok().ok()?;
        let s = String::from_utf16_lossy(&buf);
        Some(s.trim_end_matches('\0').to_string())
    }
}

/// Provider/filter registration plus the CLSID pointing at the installed DLL.
pub fn registered(kind: &str, clsid: &str) -> bool {
    let listed = key_exists(HKEY_LOCAL_MACHINE, &format!(r"{}\{kind}\{clsid}", layout::AUTH_KEY));
    let dll = layout::install_dir().join(layout::CP_DLL);
    let server = reg_string(HKEY_CLASSES_ROOT, &format!(r"CLSID\{clsid}\InprocServer32"), None);
    listed && server.is_some_and(|s| Path::new(&s) == dll)
}

pub fn files_intact() -> bool {
    let Some(manifest) = layout::read_manifest() else { return false };
    !manifest.is_empty() && manifest.iter().all(|(name, h)| layout::sha256_file(&layout::install_dir().join(name)) == Some(*h))
}

pub fn safe_mode() -> bool {
    // SAFETY: simple query. 0 = normal boot, 1 = Safe Mode, 2 = Safe Mode with networking.
    unsafe { GetSystemMetrics(SM_CLEANBOOT) != 0 }
}

pub struct WinProbe {
    pub bitlocker: Arc<dyn BitLockerOps>,
    pub netlogon: Arc<dyn NetLogon>,
    cache: Mutex<Option<(Instant, BitLocker)>>,
}

impl WinProbe {
    pub fn new(bitlocker: Arc<dyn BitLockerOps>, netlogon: Arc<dyn NetLogon>) -> Self {
        WinProbe { bitlocker, netlogon, cache: Mutex::new(None) }
    }

    fn bitlocker_state(&self) -> BitLocker {
        let mut c = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((t, v)) = *c {
            if t.elapsed() < Duration::from_secs(600) {
                return v;
            }
        }
        let v = self.bitlocker.status().map(|i| bitlocker_logic::to_report(&i)).unwrap_or(BitLocker::Unknown);
        *c = Some((Instant::now(), v));
        v
    }
}

impl StatusProbe for WinProbe {
    fn probe(&self) -> Probe {
        Probe {
            cp_registered: registered("Credential Providers", layout::CLSID_PROVIDER),
            filter_registered: registered("Credential Provider Filters", layout::CLSID_FILTER),
            files_intact: files_intact(),
            watchdog_present: layout::task_file().exists(),
            bitlocker: self.bitlocker_state(),
            netlogon_blocked: self.netlogon.blocked().unwrap_or(false),
            safe_mode: safe_mode(),
        }
    }
}

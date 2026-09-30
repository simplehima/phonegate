//! Watchdog planner (feature 002, US2). Pure: given what was observed, decide what to repair and
//! what to report. The Windows executor (`win::watchdog_exec`) observes and acts.
//!
//! Invariants:
//! - never restores from a backup that no longer matches the install-time manifest;
//! - restores files before touching registration or the service (the service binary must exist);
//! - never weakens protection (it only puts PhoneGate back);
//! - reports each item at most once per hour.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const REPORT_EVERY_MS: u64 = 60 * 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileObs {
    pub name: String,
    /// SHA-256 recorded in the manifest at install time.
    pub manifest: [u8; 32],
    /// Hash of the installed file, `None` if missing.
    pub installed: Option<[u8; 32]>,
    /// Hash of the protected backup copy, `None` if missing.
    pub backup: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Observed {
    pub service_exists: bool,
    pub service_running: bool,
    pub service_auto_start: bool,
    pub provider_registered: bool,
    pub filter_registered: bool,
    /// Both CLSID InprocServer32 entries point at the installed DLL.
    pub clsids_ok: bool,
    pub safeboot_registered: bool,
    pub files: Vec<FileObs>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    RestoreFile(String),
    RegisterClsids,
    RegisterProvider,
    RegisterFilter,
    RegisterSafeBoot,
    CreateService,
    SetServiceAutoStart,
    StartService,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Memory {
    /// item → last time it was reported (ms).
    pub last_reported: BTreeMap<String, u64>,
    pub last_run_at: u64,
    /// Most recent repairs (newest last, capped at 20) for the companion app.
    pub repairs: Vec<(u64, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    pub actions: Vec<Action>,
    /// `(key, text)` to report to the phone (already rate-limited per key).
    pub reports: Vec<(String, String)>,
    /// Everything repaired this run (for the local repair log, not rate-limited).
    pub repaired: Vec<String>,
}

pub fn plan(o: &Observed, mem: &Memory, now: u64) -> Plan {
    let mut p = Plan::default();
    let due = |key: &str| mem.last_reported.get(key).is_none_or(|t| now.saturating_sub(*t) >= REPORT_EVERY_MS);
    let item = |p: &mut Plan, key: &str, text: String| {
        p.repaired.push(text.clone());
        if due(key) {
            p.reports.push((key.to_string(), text));
        }
    };

    let mut blocked_service = false;
    for f in &o.files {
        let backup_ok = f.backup == Some(f.manifest);
        let installed_ok = f.installed == Some(f.manifest);
        if installed_ok {
            continue;
        }
        if backup_ok {
            p.actions.push(Action::RestoreFile(f.name.clone()));
            let what = if f.installed.is_none() { "was missing" } else { "had been changed" };
            item(&mut p, &format!("file:{}", f.name), format!("{} {what} and was restored", f.name));
        } else {
            // Cannot repair safely: report only. If the agent binary is gone, don't try to start it.
            blocked_service |= f.installed.is_none() && f.name.ends_with(".exe");
            let key = format!("backup:{}", f.name);
            if due(&key) {
                p.reports.push((key, format!("{} is damaged and its protected backup no longer matches; reinstall PhoneGate", f.name)));
            }
        }
    }

    if !o.clsids_ok {
        p.actions.push(Action::RegisterClsids);
        item(&mut p, "clsids", "credential provider COM registration was restored".into());
    }
    if !o.provider_registered {
        p.actions.push(Action::RegisterProvider);
        item(&mut p, "provider", "sign-in tile registration was restored".into());
    }
    if !o.filter_registered {
        p.actions.push(Action::RegisterFilter);
        item(&mut p, "filter", "sign-in tile filter registration was restored".into());
    }
    if !o.safeboot_registered {
        p.actions.push(Action::RegisterSafeBoot);
        item(&mut p, "safeboot", "Safe Mode registration was restored".into());
    }

    if !blocked_service {
        if !o.service_exists {
            p.actions.push(Action::CreateService);
            p.actions.push(Action::StartService);
            item(&mut p, "service", "the PhoneGate service had been deleted and was recreated".into());
        } else {
            if !o.service_auto_start {
                p.actions.push(Action::SetServiceAutoStart);
                item(&mut p, "service-start", "the PhoneGate service start mode was restored".into());
            }
            if !o.service_running {
                p.actions.push(Action::StartService);
                item(&mut p, "service-run", "the PhoneGate service was not running and was restarted".into());
            }
        }
    }
    p
}

/// Records a run's outcome in the watchdog memory.
pub fn remember(mem: &mut Memory, plan: &Plan, now: u64) {
    mem.last_run_at = now;
    for (k, _) in &plan.reports {
        mem.last_reported.insert(k.clone(), now);
    }
    for r in &plan.repaired {
        mem.repairs.push((now, r.clone()));
    }
    let n = mem.repairs.len();
    if n > 20 {
        mem.repairs.drain(..n - 20);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: [u8; 32] = [7; 32];

    fn healthy() -> Observed {
        Observed {
            service_exists: true,
            service_running: true,
            service_auto_start: true,
            provider_registered: true,
            filter_registered: true,
            clsids_ok: true,
            safeboot_registered: true,
            files: vec![
                FileObs { name: "phonegate-agent.exe".into(), manifest: H, installed: Some(H), backup: Some(H) },
                FileObs { name: "phonegate_cp.dll".into(), manifest: H, installed: Some(H), backup: Some(H) },
            ],
        }
    }

    #[test]
    fn healthy_system_needs_nothing() {
        let p = plan(&healthy(), &Memory::default(), 0);
        assert!(p.actions.is_empty() && p.reports.is_empty());
    }

    #[test]
    fn stopped_or_deleted_service_is_brought_back() {
        let mut o = healthy();
        o.service_running = false;
        let p = plan(&o, &Memory::default(), 0);
        assert_eq!(p.actions, vec![Action::StartService]);
        assert_eq!(p.reports.len(), 1);

        let mut o = healthy();
        o.service_exists = false;
        let p = plan(&o, &Memory::default(), 0);
        assert_eq!(p.actions, vec![Action::CreateService, Action::StartService]);

        let mut o = healthy();
        o.service_auto_start = false;
        assert_eq!(plan(&o, &Memory::default(), 0).actions, vec![Action::SetServiceAutoStart]);
    }

    #[test]
    fn missing_registration_restored() {
        let mut o = healthy();
        o.provider_registered = false;
        o.filter_registered = false;
        o.clsids_ok = false;
        o.safeboot_registered = false;
        let p = plan(&o, &Memory::default(), 0);
        assert_eq!(p.actions, vec![Action::RegisterClsids, Action::RegisterProvider, Action::RegisterFilter, Action::RegisterSafeBoot]);
        assert_eq!(p.reports.len(), 4);
    }

    #[test]
    fn files_restored_first_and_only_from_intact_backup() {
        let mut o = healthy();
        o.files[1].installed = Some([9; 32]); // DLL replaced
        o.service_running = false;
        let p = plan(&o, &Memory::default(), 0);
        assert_eq!(p.actions.first(), Some(&Action::RestoreFile("phonegate_cp.dll".into())));
        assert!(p.reports[0].1.contains("changed"));

        let mut o = healthy();
        o.files[1].installed = None;
        o.files[1].backup = Some([8; 32]); // backup tampered
        let p = plan(&o, &Memory::default(), 0);
        assert!(!p.actions.iter().any(|a| matches!(a, Action::RestoreFile(_))), "never restore from an altered backup");
        assert!(p.reports[0].1.contains("backup no longer matches"));
    }

    #[test]
    fn missing_agent_without_backup_does_not_start_service() {
        let mut o = healthy();
        o.files[0].installed = None;
        o.files[0].backup = None;
        o.service_running = false;
        let p = plan(&o, &Memory::default(), 0);
        assert!(!p.actions.contains(&Action::StartService));
    }

    #[test]
    fn reports_rate_limited_per_item() {
        let mut o = healthy();
        o.service_running = false;
        let mut mem = Memory::default();
        let p = plan(&o, &mem, 0);
        assert_eq!(p.reports[0].0, "service-run");
        remember(&mut mem, &p, 0);
        let p2 = plan(&o, &mem, 5 * 60_000);
        assert_eq!(p2.actions, vec![Action::StartService], "still repairs");
        assert!(p2.reports.is_empty(), "but does not report again within the hour");
        let p3 = plan(&o, &mem, REPORT_EVERY_MS);
        assert_eq!(p3.reports.len(), 1);
        assert_eq!(mem.repairs.len(), 1);
    }

    #[test]
    fn repair_log_is_capped() {
        let mut mem = Memory::default();
        let mut o = healthy();
        o.service_running = false;
        for i in 0..30 {
            let p = plan(&o, &mem, i);
            remember(&mut mem, &p, i);
        }
        assert_eq!(mem.repairs.len(), 20);
    }
}

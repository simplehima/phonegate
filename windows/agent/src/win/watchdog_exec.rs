//! Watchdog executor (`phonegate-agent --watchdog`, run by a SYSTEM scheduled task). Observes the
//! installation, applies `watchdog::plan`, and queues repair notices for the phone.

use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;

use pg_core::recovery::{PendingNotice, RecoverySet};
use pg_core::{store, Result};
use windows::core::HSTRING;
use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
use windows::Win32::System::Registry::{HKEY_CLASSES_ROOT, HKEY_LOCAL_MACHINE};
use windows_service::service::{ServiceAccess, ServiceStartType, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::layout;
use super::probe::{key_exists, reg_string, registered};
use crate::watchdog::{self, Action, FileObs, Memory, Observed};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SAFEBOOT: &str = r"SYSTEM\CurrentControlSet\Control\SafeBoot";

fn service_state() -> (bool, bool, bool) {
    let Ok(m) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else { return (false, false, false) };
    let Ok(s) = m.open_service(layout::SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG) else { return (false, false, false) };
    let running = s.query_status().map(|st| st.current_state == ServiceState::Running || st.current_state == ServiceState::StartPending).unwrap_or(false);
    let auto = s.query_config().map(|c| c.start_type == ServiceStartType::AutoStart).unwrap_or(false);
    (true, running, auto)
}

fn clsids_ok() -> bool {
    let dll = layout::install_dir().join(layout::CP_DLL);
    [layout::CLSID_PROVIDER, layout::CLSID_FILTER].iter().all(|c| {
        reg_string(HKEY_CLASSES_ROOT, &format!(r"CLSID\{c}\InprocServer32"), None).is_some_and(|s| Path::new(&s) == dll)
    })
}

pub fn observe() -> Observed {
    let (exists, running, auto) = service_state();
    let listed = |kind: &str, clsid: &str| key_exists(HKEY_LOCAL_MACHINE, &format!(r"{}\{kind}\{clsid}", layout::AUTH_KEY));
    let files = layout::read_manifest()
        .unwrap_or_default()
        .into_iter()
        .map(|(name, manifest)| FileObs {
            installed: layout::sha256_file(&layout::install_dir().join(&name)),
            backup: layout::sha256_file(&layout::backup_dir().join(&name)),
            name,
            manifest,
        })
        .collect();
    Observed {
        service_exists: exists,
        service_running: running,
        service_auto_start: auto,
        provider_registered: listed("Credential Providers", layout::CLSID_PROVIDER),
        filter_registered: listed("Credential Provider Filters", layout::CLSID_FILTER),
        clsids_ok: clsids_ok(),
        safeboot_registered: ["Minimal", "Network"].iter().all(|m| key_exists(HKEY_LOCAL_MACHINE, &format!(r"{SAFEBOOT}\{m}\{}", layout::SERVICE_NAME))),
        files,
    }
}

fn run(program: &str, args: &[&str]) {
    let _ = Command::new(program).args(args).creation_flags(CREATE_NO_WINDOW).output();
}

fn reg_add(key: &str, value: Option<&str>, data: &str) {
    let mut args = vec!["add", key];
    match value {
        Some(v) => args.extend(["/v", v]),
        None => args.push("/ve"),
    }
    args.extend(["/t", "REG_SZ", "/d", data, "/f"]);
    run("reg.exe", &args);
}

fn restore_file(name: &str) -> Result<()> {
    let dst = layout::install_dir().join(name);
    let src = layout::backup_dir().join(name);
    std::fs::create_dir_all(layout::install_dir())?;
    if dst.exists() {
        // In-use files (the DLL loaded by LogonUI) cannot be overwritten but can be renamed.
        let old = dst.with_extension(format!("old-{}", pg_core::now_ms()));
        std::fs::rename(&dst, &old)?;
        // SAFETY: valid wide paths; schedules deletion of the displaced copy at reboot.
        unsafe {
            let _ = MoveFileExW(&HSTRING::from(old.as_os_str()), None, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }
    std::fs::copy(&src, &dst)?;
    Ok(())
}

fn execute(a: &Action) {
    let dll = layout::install_dir().join(layout::CP_DLL).display().to_string();
    let exe = format!("\"{}\"", layout::install_dir().join(layout::AGENT_EXE).display());
    match a {
        Action::RestoreFile(name) => {
            if let Err(e) = restore_file(name) {
                tracing::error!("watchdog: restore {name} failed: {e}");
            }
        }
        Action::RegisterClsids => {
            for (c, n) in [(layout::CLSID_PROVIDER, "PhoneGate Credential Provider"), (layout::CLSID_FILTER, "PhoneGate Credential Provider Filter")] {
                reg_add(&format!(r"HKCR\CLSID\{c}"), None, n);
                reg_add(&format!(r"HKCR\CLSID\{c}\InprocServer32"), None, &dll);
                reg_add(&format!(r"HKCR\CLSID\{c}\InprocServer32"), Some("ThreadingModel"), "Apartment");
            }
        }
        Action::RegisterProvider => reg_add(&format!(r"HKLM\{}\Credential Providers\{}", layout::AUTH_KEY, layout::CLSID_PROVIDER), None, "PhoneGate"),
        Action::RegisterFilter => reg_add(&format!(r"HKLM\{}\Credential Provider Filters\{}", layout::AUTH_KEY, layout::CLSID_FILTER), None, "PhoneGate"),
        Action::RegisterSafeBoot => {
            for m in ["Minimal", "Network"] {
                reg_add(&format!(r"HKLM\{SAFEBOOT}\{m}\{}", layout::SERVICE_NAME), None, "Service");
            }
        }
        Action::CreateService => {
            run("sc.exe", &["create", layout::SERVICE_NAME, "binPath=", &exe, "start=", "auto", "DisplayName=", "PhoneGate Agent"]);
            run("sc.exe", &["failure", layout::SERVICE_NAME, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/30000"]);
        }
        Action::SetServiceAutoStart => run("sc.exe", &["config", layout::SERVICE_NAME, "start=", "auto"]),
        Action::StartService => run("sc.exe", &["start", layout::SERVICE_NAME]),
    }
}

/// One watchdog pass. Returns the number of repairs made.
pub fn run_once() -> Result<usize> {
    let now = pg_core::now_ms();
    let mem_path = layout::watchdog_memory_path();
    let mut mem: Memory = store::read_json(&mem_path).ok().flatten().unwrap_or_default();
    let observed = observe();
    let plan = watchdog::plan(&observed, &mem, now);
    for a in &plan.actions {
        execute(a);
    }
    if !plan.reports.is_empty() {
        // Delivered to the phone by the agent (now running again) via the pending-notice queue.
        let recovery = crate::state::Paths::system_default().recovery();
        let _ = store::update_json::<RecoverySet, _>(&recovery, |s| {
            if let Some(s) = s.as_mut() {
                for (_, text) in &plan.reports {
                    s.pending_notices.push(PendingNotice { kind: "repaired".into(), at: now, detail: text.clone() });
                }
            }
            Ok(())
        });
    }
    watchdog::remember(&mut mem, &plan, now);
    store::write_json_atomic(&mem_path, &mem)?;
    Ok(plan.repaired.len())
}

/// Summary for the companion app's `health` op.
pub fn summary() -> serde_json::Value {
    let mem: Memory = store::read_json(&layout::watchdog_memory_path()).ok().flatten().unwrap_or_default();
    serde_json::json!({
        "present": layout::task_file().exists(),
        "last_run_at": (mem.last_run_at > 0).then_some(mem.last_run_at),
        "last_repairs": mem.repairs.iter().rev().take(10).map(|(at, item)| serde_json::json!({"at": at, "item": item})).collect::<Vec<_>>(),
    })
}

/// Whether the agent is registered to start in Safe Mode (for `security_check`).
pub fn safeboot_registered() -> bool {
    ["Minimal", "Network"].iter().all(|m| key_exists(HKEY_LOCAL_MACHINE, &format!(r"{SAFEBOOT}\{m}\{}", layout::SERVICE_NAME)))
}

pub fn cp_registered() -> bool {
    registered("Credential Providers", layout::CLSID_PROVIDER)
}

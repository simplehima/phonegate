//! `phonegate-agent` — LocalSystem Windows service.
//!
//! Usage:
//!   phonegate-agent                 run under the Service Control Manager (installed service)
//!   phonegate-agent --console       run in the foreground (development; run elevated)
//!   phonegate-agent --selftest-tpm  exercise the TPM code path with throwaway user-scope keys
//!   phonegate-agent --watchdog      one repair pass (run by the SYSTEM scheduled task)

#[cfg(windows)]
mod app {
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::time::Duration;

    use pg_agent::engine::{Engine, EngineConfig};
    use pg_agent::keys::KeyBackend;
    use pg_agent::state::Paths;
    use pg_agent::api;
    use pg_agent::probe::{BitLockerOps, NetLogon, Platform};
    use pg_agent::win::{self, acl, bitlocker::WinBitLocker, dpapi::DpapiBackend, netlogon::WinNetLogon, pipes, probe::WinProbe, syscheck, tpm, watchdog_exec};
    use pg_core::ipc::{CONTROL_PIPE, GATE_PIPE};
    use pg_core::messages::NoticeKind;
    use pg_core::signer::Signer;
    use windows_service::service::{PowerEventParam, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    pub const SERVICE_NAME: &str = "PhoneGateAgent";

    fn choose_backend(paths: &Paths) -> pg_core::Result<Arc<dyn KeyBackend>> {
        match tpm::TpmBackend::open(&tpm::PRODUCTION) {
            Ok(t) => Ok(Arc::new(t)),
            Err(e) => {
                tracing::warn!("TPM unavailable ({e}); using DPAPI software key (weaker, surfaced to the owner)");
                Ok(Arc::new(DpapiBackend::open(&paths.software_key())?))
            }
        }
    }

    fn platform() -> Platform {
        let bitlocker: Arc<dyn BitLockerOps> = Arc::new(WinBitLocker);
        let netlogon: Arc<dyn NetLogon> = Arc::new(WinNetLogon);
        Platform { probe: Arc::new(WinProbe::new(bitlocker.clone(), netlogon.clone())), netlogon, bitlocker }
    }

    /// Starts the engine, the relay loop and both pipe servers (on their own threads) and
    /// announces the start to the phone. Returns the engine for lifecycle events.
    pub fn start(paths: Paths) -> pg_core::Result<Arc<Engine>> {
        std::fs::create_dir_all(&paths.dir)?;
        acl::restrict_dir(&paths.dir)?;
        let keys = choose_backend(&paths)?;
        let backend_kind = keys.kind();
        let pc_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".into());
        let engine = Engine::open(keys, EngineConfig::production(paths, pc_name, platform()))?;

        // Tamper evidence: every start is announced; a Safe Mode start raises an alarm (FR-110).
        // SAFETY: simple query.
        let uptime_ms = unsafe { windows::Win32::System::SystemInformation::GetTickCount64() };
        engine.lifecycle(NoticeKind::AgentStarted, if uptime_ms < 5 * 60_000 { "boot" } else { "restart" });
        if win::probe::safe_mode() {
            engine.lifecycle(NoticeKind::SafeModeBoot, "this start");
        }

        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
        let handle = rt.handle().clone();
        let relay_engine = engine.clone();
        std::thread::spawn(move || rt.block_on(relay_engine.run_relay()));

        let (e1, h1) = (engine.clone(), handle.clone());
        let gate: pipes::Handler = Arc::new(move |req| serde_json::to_vec(&h1.block_on(api::handle_gate(&e1, &req))).unwrap_or_default());
        let (e2, h2) = (engine.clone(), handle);
        let control: pipes::Handler = Arc::new(move |req| {
            let security = || {
                let mut s = syscheck::security_check(backend_kind);
                s["netlogon_blocked"] = serde_json::json!(WinNetLogon.blocked().unwrap_or(false));
                s["watchdog_present"] = serde_json::json!(win::layout::task_file().exists());
                s["safe_mode_registered"] = serde_json::json!(watchdog_exec::safeboot_registered());
                s
            };
            let v = h2.block_on(api::handle_control(&e2, &req, security, watchdog_exec::summary));
            serde_json::to_vec(&v).unwrap_or_default()
        });
        std::thread::spawn(move || {
            if let Err(e) = pipes::serve(GATE_PIPE, pipes::GATE_SDDL, gate) {
                tracing::error!("gate pipe stopped: {e}");
            }
        });
        std::thread::spawn(move || {
            if let Err(e) = pipes::serve(CONTROL_PIPE, pipes::CONTROL_SDDL, control) {
                tracing::error!("control pipe stopped: {e}");
            }
        });
        Ok(engine)
    }

    /// Gives the relay connection a moment to transmit a final notice before we exit.
    fn announce(engine: &Engine, kind: NoticeKind, detail: &str) {
        engine.lifecycle(kind, detail);
        std::thread::sleep(Duration::from_millis(1500));
    }

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = run_service() {
            tracing::error!("service failed: {e}");
        }
    }

    enum Event {
        Stop,
        Shutdown,
        Suspend,
        Resume,
    }

    fn run_service() -> windows_service::Result<()> {
        let (tx, rx) = std::sync::mpsc::channel::<Event>();
        let status = service_control_handler::register(SERVICE_NAME, move |ev| {
            let e = match ev {
                ServiceControl::Stop => Some(Event::Stop),
                ServiceControl::Shutdown | ServiceControl::Preshutdown => Some(Event::Shutdown),
                ServiceControl::PowerEvent(PowerEventParam::Suspend) => Some(Event::Suspend),
                ServiceControl::PowerEvent(PowerEventParam::ResumeAutomatic | PowerEventParam::ResumeSuspend) => Some(Event::Resume),
                ServiceControl::Interrogate => None,
                ServiceControl::PowerEvent(_) => None,
                _ => return ServiceControlHandlerResult::NotImplemented,
            };
            if let Some(e) = e {
                let _ = tx.send(e);
            }
            ServiceControlHandlerResult::NoError
        })?;
        let set = |state: ServiceState, accept: ServiceControlAccept, code: u32| {
            status.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: accept,
                exit_code: ServiceExitCode::Win32(code),
                checkpoint: 0,
                wait_hint: Duration::from_secs(5),
                process_id: None,
            })
        };
        let engine = match start(Paths::system_default()) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("agent failed to start: {e}");
                // Non-zero exit: the SCM recovery policy (and the watchdog) restart us.
                set(ServiceState::Stopped, ServiceControlAccept::empty(), 1)?;
                return Ok(());
            }
        };
        set(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN | ServiceControlAccept::PRESHUTDOWN | ServiceControlAccept::POWER_EVENT,
            0,
        )?;
        loop {
            match rx.recv() {
                // Someone stopped the service: that is tamper evidence (FR-103).
                Ok(Event::Stop) | Err(_) => {
                    announce(&engine, NoticeKind::AgentStopped, "the PhoneGate service was stopped");
                    break;
                }
                Ok(Event::Shutdown) => {
                    announce(&engine, NoticeKind::Shutdown, "");
                    break;
                }
                Ok(Event::Suspend) => engine.lifecycle(NoticeKind::Sleep, ""),
                Ok(Event::Resume) => {
                    engine.lifecycle(NoticeKind::Resume, "");
                    engine.maybe_send_status();
                }
            }
        }
        set(ServiceState::Stopped, ServiceControlAccept::empty(), 0)?;
        Ok(())
    }

    fn selftest_tpm() -> i32 {
        let t = match tpm::TpmBackend::open(&tpm::SELFTEST) {
            Ok(t) => t,
            Err(e) => {
                println!("TPM-SELFTEST: UNAVAILABLE ({e})");
                return 2;
            }
        };
        let msg = b"phonegate tpm self-test";
        let res = (|| -> pg_core::Result<()> {
            let sig = t.sign(msg)?;
            pg_core::crypto::verify(&t.public(), msg, &sig)?;
            if pg_core::crypto::verify(&t.public(), b"other", &sig).is_ok() {
                return Err(pg_core::Error::Verify("signature verified for the wrong message"));
            }
            let blob = t.wrap(&[7u8; 32])?;
            if t.unwrap(&blob)?.as_slice() != [7u8; 32] {
                return Err(pg_core::Error::Verify("unwrap mismatch"));
            }
            Ok(())
        })();
        let del = t.delete();
        match (res, del) {
            (Ok(()), Ok(())) => {
                println!("TPM-SELFTEST: OK (ECDSA P-256 sign/verify + RSA-OAEP wrap/unwrap)");
                0
            }
            (Err(e), _) | (_, Err(e)) => {
                println!("TPM-SELFTEST: FAILED ({e})");
                1
            }
        }
    }

    pub fn main() {
        tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--selftest-tpm") {
            std::process::exit(selftest_tpm());
        }
        if args.iter().any(|a| a == "--watchdog") {
            // Run by the "PhoneGate Watchdog" SYSTEM scheduled task (feature 002, US2).
            match watchdog_exec::run_once() {
                Ok(n) => {
                    println!("WATCHDOG: {n} repair(s)");
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("WATCHDOG: failed ({e})");
                    std::process::exit(1);
                }
            }
        }
        if args.iter().any(|a| a == "--console") {
            match start(Paths::system_default()) {
                Ok(_engine) => loop {
                    std::thread::park();
                },
                Err(e) => {
                    eprintln!("phonegate-agent: {e}");
                    std::process::exit(1);
                }
            }
        }
        if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            eprintln!("phonegate-agent must run as a Windows service (or pass --console): {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(windows)]
fn main() {
    app::main();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("phonegate-agent only runs on Windows");
    std::process::exit(1);
}

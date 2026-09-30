//! Test harness: a real relay on loopback, the real agent [`Engine`] with an in-memory key
//! backend and an adjustable clock, and a [`SimPhone`] connected through the relay.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pg_agent::engine::{Engine, EngineConfig};
use pg_agent::keys::MemoryBackend;
use pg_agent::probe::{Fakes, Platform};
use pg_agent::state::Paths;
use pg_core::crypto::Id;
use pg_core::messages::{self, Kind};
use pg_core::relay_client::{self, Incoming, RelaySender};
use pg_core::signer::SoftSigner;
use pg_sim::SimPhone;
use tokio::sync::mpsc::UnboundedReceiver;

pub const T0: u64 = 1_800_000_000_000;

pub struct Harness {
    pub relay_url: String,
    pub engine: Arc<Engine>,
    pub clock: Arc<AtomicU64>,
    pub phone: SimPhone,
    pub phone_tx: RelaySender,
    pub phone_rx: UnboundedReceiver<Incoming>,
    pub dir: PathBuf,
    /// Kept so the engine can be restarted with the same identity (feature 002 tests).
    pub keys: Arc<MemoryBackend>,
    pub fakes: Fakes,
    relay_task: tokio::task::JoinHandle<()>,
}

pub async fn start_relay() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(phonegate_relay::serve(l, phonegate_relay::Config::default()));
    format!("http://{addr}")
}

/// TCP proxy in front of the relay that can be cut to simulate an outage. Returns the proxy URL
/// and a switch; sending `true` drops every proxied connection and refuses new ones.
pub async fn start_cuttable_proxy(upstream: &str) -> (String, tokio::sync::watch::Sender<bool>) {
    let up = upstream.trim_start_matches("http://").to_string();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = l.accept().await else { return };
            let mut cut = rx.clone();
            if *cut.borrow() {
                continue;
            }
            let up = up.clone();
            tokio::spawn(async move {
                let Ok(mut outbound) = tokio::net::TcpStream::connect(&up).await else { return };
                tokio::select! {
                    _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => {}
                    _ = cut.wait_for(|c| *c) => {}
                }
            });
        }
    });
    (format!("http://{addr}"), tx)
}

fn temp_dir(tag: &str) -> PathBuf {
    let n: u64 = u64::from_be_bytes(pg_core::crypto::random::<8>().unwrap());
    let d = std::env::temp_dir().join(format!("pg-e2e-{tag}-{n:x}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

impl Harness {
    /// Relay + engine connected, phone connected, not yet paired.
    pub async fn new(tag: &str) -> Harness {
        let relay_url = start_relay().await;
        let phone = SimPhone::new("Pixel Test");
        Self::with_phone(tag, relay_url, phone).await
    }

    pub async fn with_phone(tag: &str, relay_url: String, phone: SimPhone) -> Harness {
        let dir = temp_dir(tag);
        let clock = Arc::new(AtomicU64::new(T0));
        let c2 = clock.clone();
        let keys = Arc::new(MemoryBackend::generate().unwrap());
        let (platform, fakes) = Platform::fake();
        let cfg = Self::config(&dir, &phone.test_root(), c2, platform);
        let engine = Engine::open(keys.clone(), cfg).unwrap();
        engine.settings_set(Some(&relay_url), None, None).unwrap();
        let relay_task = tokio::spawn(engine.clone().run_relay());
        let dev = Arc::new(SoftSigner::from_bytes(&phone.device.to_bytes()).unwrap());
        let (phone_tx, phone_rx, _) = relay_client::connect(&relay_url, dev).await.unwrap();
        let h = Harness { relay_url, engine, clock, phone, phone_tx, phone_rx, dir, keys, fakes, relay_task };
        h.wait_relay_up().await;
        h
    }

    fn config(dir: &std::path::Path, root: &[u8], clock: Arc<AtomicU64>, platform: Platform) -> EngineConfig {
        EngineConfig {
            paths: Paths::new(dir),
            attestation_roots: vec![root.to_vec()],
            default_pc_name: "Test PC".into(),
            clock: Arc::new(move || clock.load(Ordering::SeqCst)),
            platform,
            // Tests trigger reports explicitly; keep the periodic ones out of the way.
            status_interval: Duration::from_secs(3600),
            probe_interval: Duration::from_secs(3600),
        }
    }

    /// Stops the engine and opens it again from disk with the same TPM identity, as a service
    /// restart would (e.g. after an administrator edited `state.json`).
    pub async fn restart_engine(&mut self) {
        self.relay_task.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (platform, fakes) = Platform::fake();
        let cfg = Self::config(&self.dir, &self.phone.test_root(), self.clock.clone(), platform);
        self.engine = Engine::open(self.keys.clone(), cfg).unwrap();
        self.fakes = fakes;
        self.relay_task = tokio::spawn(self.engine.clone().run_relay());
        self.wait_relay_up().await;
    }

    pub async fn wait_relay_up(&self) {
        for _ in 0..200 {
            if self.engine.gate_status().relay == "up" {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("engine never connected to relay");
    }

    pub fn advance(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    pub fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    /// Next relay message for the phone (skips acks).
    pub async fn phone_next(&mut self) -> (Id, Id, Vec<u8>) {
        loop {
            let m = tokio::time::timeout(Duration::from_secs(5), self.phone_rx.recv()).await.expect("phone timed out").expect("closed");
            if let Incoming::Msg { from, to, body } = m {
                return (from, to, body);
            }
        }
    }

    /// Next message of a given kind for the phone (skips other kinds such as notices).
    pub async fn phone_next_kind(&mut self, kind: Kind) -> (Id, Vec<u8>) {
        loop {
            let (from, _, body) = self.phone_next().await;
            if messages::unwire(&body).map(|(k, _)| k == kind).unwrap_or(false) {
                return (from, body);
            }
        }
    }

    pub async fn phone_silent(&mut self, ms: u64) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
        loop {
            match tokio::time::timeout_at(deadline, self.phone_rx.recv()).await {
                Err(_) => return true,
                Ok(Some(Incoming::Msg { .. })) => return false,
                Ok(_) => continue,
            }
        }
    }

    /// Full QR pairing through the relay; returns the SAS both sides displayed.
    pub async fn pair(&mut self) -> String {
        let (uri, _) = self.engine.pair_start().unwrap();
        let p = self.phone.begin_pairing(&uri).unwrap();
        self.phone_tx.subscribe(&p.slot()).unwrap();
        let (_, _, offer) = self.phone_next().await;
        let (join, sas) = self.phone.answer_offer(p, &offer, self.now()).unwrap();
        let slot = self.phone.pending_slot().unwrap();
        self.phone_tx.send_slot(&slot, &join, 300, "join").unwrap();
        let poll = self.wait_pair_state("confirm").await;
        assert_eq!(poll.sas.as_deref(), Some(sas.as_str()), "SAS must match on both screens");
        assert!(poll.attestation.as_ref().unwrap().is_verified(), "attestation: {:?}", poll.attestation);
        self.phone_tx.send_slot(&slot, &self.phone.confirm_pairing().unwrap(), 300, "confirm").unwrap();
        for _ in 0..200 {
            if self.engine.pair_poll().phone_confirmed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.engine.pair_decide(true, false).unwrap();
        let (_, _, complete) = self.phone_next().await;
        self.phone.complete_pairing(&complete).unwrap();
        assert_eq!(self.wait_pair_state("completed").await.state, "completed");
        sas
    }

    pub async fn wait_pair_state(&self, state: &str) -> pg_agent::engine::PairPoll {
        for _ in 0..300 {
            let p = self.engine.pair_poll();
            if p.state == state {
                return p;
            }
            if p.state == "failed" && state != "failed" {
                panic!("pairing failed: {:?}", p.error);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("pairing never reached {state}: {:?}", self.engine.pair_poll());
    }

    /// Pair + recovery codes + enable protection. Returns the recovery codes.
    pub async fn pair_and_enable(&mut self) -> Vec<String> {
        self.pair().await;
        let codes = self.engine.recovery_generate().unwrap();
        assert!(self.engine.recovery_confirm(&codes[0]).unwrap());
        self.engine.enable().unwrap();
        codes
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn req_bytes(b64: &str) -> [u8; 16] {
    pg_core::crypto::b64::decode_fixed(b64).unwrap()
}

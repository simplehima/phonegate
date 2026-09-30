//! Platform-neutral approval engine: pairing, approvals, offline codes, recovery, enforcement
//! state. Windows specifics (TPM, pipes, service) live in `win::*`; tests drive this engine with
//! a [`crate::keys::MemoryBackend`] and a real relay.
//!
//! Fail-secure rule: every path that does not end in a verified, single-use, in-time approval
//! signed by the pinned phone approve key results in "not approved".

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use pg_core::attestation::{self, AttestationResult};
use pg_core::crypto::{self, b64, Id, Pub};
use pg_core::envelope::{self, Dir, Envelope, SealParams};
use pg_core::messages::{self, ApprovalRequest, ApprovalResponse, Cancel, Decision, Kind, Notice, NoticeKind, Scenario, Status, Unpair};
use pg_core::offline::{self, OfflineChallenge};
use pg_core::pairing::{self, JoinInfo, PcPairing, PcPairingState};
use pg_core::recovery::{PendingNotice, RecoverySet, VerifyOutcome};
use pg_core::relay_client::{self, Incoming, RelaySender};
use pg_core::signer::Signer;
use pg_core::{store, Error, Result};
use serde::Serialize;
use tokio::sync::Notify;
use zeroize::Zeroizing;

use crate::keys::KeyBackend;
use crate::probe::{BitLockerInfo, Platform, Probe};
use crate::state::{AttemptRecord, Pairing, Paths, PcState};

pub const REQUEST_LIFETIME_MS: u64 = 60_000;
pub const COOLDOWN_WINDOW_MS: u64 = 5 * 60_000;
pub const COOLDOWN_THRESHOLD: usize = 3;
pub const COOLDOWN_BASE_MS: u64 = 60_000;
pub const COOLDOWN_MAX_MS: u64 = 30 * 60_000;
const SEEN_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub struct EngineConfig {
    pub paths: Paths,
    /// Trust anchors for phone key attestation (Google's roots in production).
    pub attestation_roots: Vec<Vec<u8>>,
    pub default_pc_name: String,
    pub clock: Clock,
    /// Integrity probe, BitLocker and network-logon backends (feature 002).
    pub platform: Platform,
    /// A status report is sent at least this often (300 s in production).
    pub status_interval: Duration,
    /// Integrity is re-probed this often to send a report as soon as something changes.
    pub probe_interval: Duration,
}

impl EngineConfig {
    pub fn production(paths: Paths, pc_name: String, platform: Platform) -> Self {
        EngineConfig {
            paths,
            attestation_roots: attestation::google_roots(),
            default_pc_name: pc_name,
            clock: Arc::new(pg_core::now_ms),
            platform,
            status_interval: Duration::from_secs(300),
            probe_interval: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReqState {
    Pending,
    Approved,
    Denied,
    NotMe,
    Expired,
    Error,
}

impl ReqState {
    pub fn as_str(self) -> &'static str {
        match self {
            ReqState::Pending => "pending",
            ReqState::Approved => "approved",
            ReqState::Denied => "denied",
            ReqState::NotMe => "not_me",
            ReqState::Expired => "expired",
            ReqState::Error => "error",
        }
    }
}

struct Outstanding {
    req: ApprovalRequest,
    digest: [u8; 32],
    state: ReqState,
    consumed: bool,
}

struct PairingSession {
    pc: PcPairing,
    join: Option<JoinInfo>,
    error: Option<String>,
    offer_wire: Vec<u8>,
}

struct OfflineEntry {
    chal: OfflineChallenge,
    attempts_left: u8,
}

struct Inner {
    state: PcState,
    k_pair: Option<Zeroizing<[u8; 32]>>,
    relay: Option<RelaySender>,
    outstanding: HashMap<[u8; 16], Outstanding>,
    pairing: Option<PairingSession>,
    offline: HashMap<[u8; 16], OfflineEntry>,
    failures: VecDeque<u64>,
    cooldown_until: u64,
    cooldown_level: u32,
    seen: HashMap<[u8; 16], u64>,
    /// Content (enforce + probe) of the last status sent and when, to send on change/interval.
    last_status: Option<(bool, Probe)>,
    last_status_sent: Option<std::time::Instant>,
    /// BitLocker helper: last 6 digits of the recovery password just shown (FR-113).
    bitlocker_last6: Option<Zeroizing<String>>,
    /// Watchdog repair notices already written to local history (a notice may be re-sent).
    logged_repairs: std::collections::HashSet<(u64, String)>,
}

pub struct Engine {
    keys: Arc<dyn KeyBackend>,
    cfg: EngineConfig,
    inner: Mutex<Inner>,
    changed: Notify,
    relay_changed: Notify,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GateStatus {
    pub enforce: bool,
    pub paired: bool,
    pub relay: &'static str,
    pub cooldown_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BeginOk {
    pub req: String,
    pub number: u64,
    pub expires_in_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    NotPaired,
    RelayDown,
    Cooldown { retry_s: u64 },
    Internal(String),
}

impl GateError {
    pub fn code(&self) -> &'static str {
        match self {
            GateError::NotPaired => "not_paired",
            GateError::RelayDown => "relay_down",
            GateError::Cooldown { .. } => "cooldown",
            GateError::Internal(_) => "internal",
        }
    }
}

impl From<Error> for GateError {
    fn from(e: Error) -> Self {
        GateError::Internal(e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairPoll {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sas: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub phone_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeCheck {
    pub valid: bool,
    pub remaining: usize,
    pub attempts_left: u8,
    pub locked_s: u64,
}

fn secs(ms: u64) -> u64 {
    ms.div_ceil(1000)
}

impl Engine {
    /// Loads (or initializes) PC state. `keys` must be the same identity across restarts.
    pub fn open(keys: Arc<dyn KeyBackend>, cfg: EngineConfig) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&cfg.paths.dir)?;
        let pc_pub = b64::encode(&keys.public());
        let state = match store::read_json::<PcState>(&cfg.paths.state())? {
            Some(s) => {
                if s.pc_pub != pc_pub {
                    // The identity key changed (e.g. TPM cleared). Fail secure: keep enforcement
                    // as-is but drop the pairing; only recovery codes can unlock.
                    let mut s = s;
                    s.pc_pub = pc_pub.clone();
                    s.key_backend = keys.kind().to_string();
                    s.pairing = None;
                    store::write_json_atomic(&cfg.paths.state(), &s)?;
                    s
                } else {
                    s
                }
            }
            None => {
                let s = PcState {
                    version: 1,
                    pc_name: cfg.default_pc_name.clone(),
                    relay_url: String::new(),
                    key_backend: keys.kind().to_string(),
                    software_ack: false,
                    pc_pub,
                    pairing: None,
                    enforce: false,
                    history: vec![],
                    status_seq: 0,
                };
                store::write_json_atomic(&cfg.paths.state(), &s)?;
                s
            }
        };
        let k_pair = match &state.pairing {
            Some(p) => {
                let blob = b64::decode(&p.k_pair_wrapped)?;
                let raw = keys.unwrap(&blob)?;
                let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| Error::Decode("bad wrapped k_pair"))?;
                Some(Zeroizing::new(arr))
            }
            None => None,
        };
        Ok(Arc::new(Engine {
            keys,
            cfg,
            inner: Mutex::new(Inner {
                state,
                k_pair,
                relay: None,
                outstanding: HashMap::new(),
                pairing: None,
                offline: HashMap::new(),
                failures: VecDeque::new(),
                cooldown_until: 0,
                cooldown_level: 0,
                seen: HashMap::new(),
                last_status: None,
                last_status_sent: None,
                bitlocker_last6: None,
                logged_repairs: Default::default(),
            }),
            changed: Notify::new(),
            relay_changed: Notify::new(),
        }))
    }

    fn now(&self) -> u64 {
        (self.cfg.clock)()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn save(&self, inner: &Inner) -> Result<()> {
        store::write_json_atomic(&self.cfg.paths.state(), &inner.state)
    }

    fn pc_id(&self) -> Id {
        crypto::id_of(&self.keys.public())
    }

    pub fn pc_public(&self) -> Pub {
        self.keys.public()
    }

    fn history(&self, inner: &mut Inner, account: &str, scenario: &str, outcome: &str, req_id: Option<&[u8; 16]>) {
        let rec = AttemptRecord {
            at: self.now(),
            pc_name: inner.state.pc_name.clone(),
            account: account.to_string(),
            scenario: scenario.to_string(),
            outcome: outcome.to_string(),
            req_id: req_id.map(|r| b64::encode(r)),
        };
        inner.state.push_history(rec);
        let _ = self.save(inner);
    }

    fn register_failure(&self, inner: &mut Inner) {
        let now = self.now();
        inner.failures.push_back(now);
        while inner.failures.front().is_some_and(|t| now.saturating_sub(*t) > COOLDOWN_WINDOW_MS) {
            inner.failures.pop_front();
        }
        if inner.failures.len() >= COOLDOWN_THRESHOLD {
            let len = (COOLDOWN_BASE_MS << inner.cooldown_level.min(10)).min(COOLDOWN_MAX_MS);
            inner.cooldown_until = now + len;
            inner.cooldown_level += 1;
            inner.failures.clear();
        }
    }

    // -----------------------------------------------------------------------------------------
    // Relay connection
    // -----------------------------------------------------------------------------------------

    /// Maintains the relay connection forever (reconnects with backoff).
    pub async fn run_relay(self: Arc<Self>) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let url = self.lock().state.relay_url.clone();
            if url.is_empty() {
                self.relay_changed.notified().await;
                continue;
            }
            let signer: Arc<dyn Signer> = self.keys.clone();
            match relay_client::connect(&url, signer).await {
                Ok((tx, mut rx, _)) => {
                    backoff = Duration::from_secs(1);
                    self.on_connected(tx);
                    let mut probe_tick = tokio::time::interval(self.cfg.probe_interval);
                    probe_tick.tick().await;
                    loop {
                        tokio::select! {
                            _ = probe_tick.tick() => {
                                let me = self.clone();
                                let _ = tokio::task::spawn_blocking(move || me.maybe_send_status()).await;
                            }
                            m = rx.recv() => match m {
                                Some(Incoming::Msg { from, to, body }) => self.handle_incoming(&from, &to, &body),
                                Some(Incoming::Closed) | None => break,
                                Some(_) => {}
                            },
                            _ = self.relay_changed.notified() => break,
                        }
                    }
                    self.lock().relay = None;
                    self.changed.notify_waiters();
                }
                Err(e) => {
                    tracing::warn!("relay connection failed: {e}");
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = self.relay_changed.notified() => {}
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
    }

    fn on_connected(&self, tx: RelaySender) {
        let mut inner = self.lock();
        if let Some(s) = &inner.pairing {
            if s.pc.state() == PcPairingState::Waiting || s.pc.state() == PcPairingState::Confirm {
                let _ = tx.subscribe(&s.pc.slot());
                let _ = tx.send_slot(&s.pc.slot(), &s.offer_wire, 300, "offer");
            }
        }
        inner.relay = Some(tx);
        drop(inner);
        self.flush_notices();
        let _ = self.send_status();
        self.changed.notify_waiters();
    }

    // -----------------------------------------------------------------------------------------
    // Feature 002: status reports and lifecycle notices
    // -----------------------------------------------------------------------------------------

    /// Probes integrity and sends a status report now (monotonic, persisted sequence).
    pub fn send_status(&self) -> Result<()> {
        let probe = self.cfg.platform.probe.probe();
        let mut inner = self.lock();
        if inner.state.pairing.is_none() || inner.relay.is_none() {
            return Err(Error::State("not paired or relay down"));
        }
        inner.state.status_seq += 1;
        let status = Status {
            seq: inner.state.status_seq,
            at: self.now(),
            enforce: inner.state.enforce,
            cp_registered: probe.cp_registered,
            filter_registered: probe.filter_registered,
            files_intact: probe.files_intact,
            watchdog_present: probe.watchdog_present,
            bitlocker: probe.bitlocker,
            netlogon_blocked: probe.netlogon_blocked,
            safe_mode: probe.safe_mode,
        };
        // Persist the sequence before sending, so a crash can never reuse it.
        self.save(&inner)?;
        self.send_to_phone(&inner, Kind::Status, &status.encode(), 300)?;
        inner.last_status = Some((status.enforce, probe));
        inner.last_status_sent = Some(std::time::Instant::now());
        Ok(())
    }

    /// Sends a report if anything changed since the last one or the interval elapsed.
    pub fn maybe_send_status(&self) {
        let probe = self.cfg.platform.probe.probe();
        let due = {
            let inner = self.lock();
            let changed = inner.last_status.as_ref() != Some(&(inner.state.enforce, probe));
            let stale = inner.last_status_sent.is_none_or(|t| t.elapsed() >= self.cfg.status_interval);
            changed || stale
        };
        if due {
            let _ = self.send_status();
        }
    }

    /// Records a lifecycle or setting notice: persisted, delivered now or on the next connect.
    pub fn lifecycle(&self, kind: NoticeKind, detail: &str) {
        if kind == NoticeKind::SafeModeBoot {
            let mut inner = self.lock();
            self.history(&mut inner, "", "settings", "safe_mode", None);
        }
        self.queue_notice(kind, detail);
    }

    /// `health` control op: the live status fields plus the watchdog summary.
    pub fn health_json(&self, watchdog: serde_json::Value) -> serde_json::Value {
        let p = self.cfg.platform.probe.probe();
        let inner = self.lock();
        let last_sent_at = inner.last_status_sent.map(|t| self.now().saturating_sub(t.elapsed().as_millis() as u64));
        serde_json::json!({
            "status": {
                "seq": inner.state.status_seq,
                "enforce": inner.state.enforce,
                "cp_registered": p.cp_registered,
                "filter_registered": p.filter_registered,
                "files_intact": p.files_intact,
                "watchdog_present": p.watchdog_present,
                "bitlocker": p.bitlocker.as_str(),
                "netlogon_blocked": p.netlogon_blocked,
                "safe_mode": p.safe_mode,
            },
            "last_sent_at": last_sent_at,
            "watchdog": watchdog,
        })
    }

    // BitLocker helper (US3) -------------------------------------------------------------------

    pub fn bitlocker_status(&self) -> Result<BitLockerInfo> {
        self.cfg.platform.bitlocker.status()
    }

    /// Adds a recovery-password protector and returns it for one-time display. Only its last six
    /// digits are kept in memory, to confirm the owner saved it before encryption starts.
    pub fn bitlocker_prepare(&self) -> Result<(String, String)> {
        let info = self.cfg.platform.bitlocker.status()?;
        if !info.supported {
            return Err(Error::State("unsupported"));
        }
        if info.state == "on-pin" {
            return Err(Error::State("drive encryption already uses a startup PIN"));
        }
        let (pw, id) = self.cfg.platform.bitlocker.prepare()?;
        let digits: String = pw.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() < 6 {
            return Err(Error::Decode("unexpected recovery password format"));
        }
        self.lock().bitlocker_last6 = Some(Zeroizing::new(digits[digits.len() - 6..].to_string()));
        Ok((pw, id))
    }

    pub fn bitlocker_enable(&self, pin: &str, recovery_last6: &str) -> Result<bool> {
        if !crate::probe::valid_pin(pin) {
            return Err(Error::State("bad_pin"));
        }
        let expected = self.lock().bitlocker_last6.clone().ok_or(Error::State("not_prepared"))?;
        let typed: String = recovery_last6.chars().filter(|c| c.is_ascii_digit()).collect();
        if !crypto::ct_eq(typed.as_bytes(), expected.as_bytes()) {
            return Err(Error::State("recovery_mismatch"));
        }
        let restart = self.cfg.platform.bitlocker.enable(pin)?;
        {
            let mut inner = self.lock();
            inner.bitlocker_last6 = None;
            self.history(&mut inner, "", "settings", "bitlocker_pin_enabled", None);
        }
        self.queue_notice(NoticeKind::SettingChanged, "drive encryption startup PIN turned on");
        let _ = self.send_status();
        Ok(restart)
    }

    // Network sign-in block (US4) --------------------------------------------------------------

    pub const NETLOGON_SETTING: &'static str = "Allow network sign-ins";

    pub fn netlogon_status(&self) -> Result<bool> {
        self.cfg.platform.netlogon.blocked()
    }

    /// Blocking is always allowed; unblocking while protection is on needs an approval (FR-116).
    pub fn netlogon_set(&self, block: bool) -> Result<()> {
        if !block && self.is_enforcing() {
            return Err(Error::State("approval_required"));
        }
        self.apply_netlogon(block)
    }

    fn apply_netlogon(&self, block: bool) -> Result<()> {
        self.cfg.platform.netlogon.set_blocked(block)?;
        {
            let mut inner = self.lock();
            self.history(&mut inner, "", "settings", if block { "netlogon_blocked" } else { "netlogon_unblocked" }, None);
        }
        self.queue_notice(NoticeKind::SettingChanged, if block { "network sign-ins blocked" } else { "network sign-ins allowed" });
        let _ = self.send_status();
        Ok(())
    }

    pub fn netlogon_unblock_begin(&self) -> std::result::Result<BeginOk, GateError> {
        self.begin(Scenario::ChangeSetting, Self::NETLOGON_SETTING, "")
    }

    pub async fn netlogon_unblock_wait(&self, req_id: &[u8; 16], timeout: Duration) -> Result<ReqState> {
        let ours = self
            .lock()
            .outstanding
            .get(req_id)
            .map(|o| o.req.scenario == Scenario::ChangeSetting && o.req.account == Self::NETLOGON_SETTING)
            .unwrap_or(false);
        if !ours {
            return Ok(ReqState::Expired);
        }
        let s = self.wait(req_id, timeout).await;
        if s == ReqState::Approved {
            self.apply_netlogon(false)?;
        }
        Ok(s)
    }

    pub fn netlogon_unblock_recovery(&self, code: &str) -> Result<CodeCheck> {
        let out = verify_recovery_file(&self.cfg.paths, code, self.now())?;
        if out.valid {
            self.apply_netlogon(false)?;
        }
        Ok(out)
    }

    fn seal_to_phone(&self, inner: &Inner, kind: Kind, plain: &[u8]) -> Result<(Id, Vec<u8>)> {
        let p = inner.state.pairing.as_ref().ok_or(Error::State("not paired"))?;
        let k = inner.k_pair.as_ref().ok_or(Error::State("not paired"))?;
        let phone_id: Id = b64::decode_fixed(&p.phone_id)?;
        let sp = SealParams { k_pair: k, dir: Dir::PcToPhone, kind, from: self.pc_id(), to: phone_id, signer: self.keys.as_ref() };
        let (env, _) = envelope::seal(&sp, plain)?;
        Ok((phone_id, messages::wire(kind, &env)))
    }

    fn send_to_phone(&self, inner: &Inner, kind: Kind, plain: &[u8], ttl: u32) -> Result<()> {
        let relay = inner.relay.as_ref().ok_or(Error::Io("relay down".into()))?;
        let (to, body) = self.seal_to_phone(inner, kind, plain)?;
        relay.send(&to, &body, ttl, kind.as_str())
    }

    /// Sends queued notices (e.g. recovery codes used while offline) to the phone.
    pub fn flush_notices(&self) {
        let path = self.cfg.paths.recovery();
        let pending: Vec<PendingNotice> = store::update_json::<RecoverySet, _>(&path, |s| Ok(s.as_mut().map(|s| std::mem::take(&mut s.pending_notices)).unwrap_or_default())).unwrap_or_default();
        if pending.is_empty() {
            return;
        }
        let mut inner = self.lock();
        let mut unsent = Vec::new();
        for n in pending {
            let kind = NoticeKind::parse(&n.kind).unwrap_or(NoticeKind::RecoveryCodeUsed);
            // Watchdog repairs are written straight to the queue; log each once in local history.
            if kind == NoticeKind::Repaired && inner.logged_repairs.insert((n.at, n.detail.clone())) {
                let outcome = format!("repaired:{}", n.detail);
                self.history(&mut inner, "", "settings", &outcome, None);
            }
            let notice = Notice { kind, at: n.at, detail: n.detail.clone() };
            if self.send_to_phone(&inner, Kind::Notice, &notice.encode(), 300).is_err() {
                unsent.push(n);
            }
        }
        drop(inner);
        if !unsent.is_empty() {
            let _ = store::update_json::<RecoverySet, _>(&path, |s| {
                if let Some(s) = s.as_mut() {
                    s.pending_notices.extend(unsent);
                }
                Ok(())
            });
        }
    }

    fn queue_notice(&self, kind: NoticeKind, detail: &str) {
        let at = self.now();
        let _ = store::update_json::<RecoverySet, _>(&self.cfg.paths.recovery(), |s| {
            if let Some(s) = s.as_mut() {
                s.pending_notices.push(PendingNotice { kind: kind.as_str().into(), at, detail: detail.into() });
            }
            Ok(())
        });
        self.flush_notices();
    }

    /// Entry point for every relay message. Anything that fails verification is dropped.
    pub fn handle_incoming(&self, from: &Id, to: &Id, body: &[u8]) {
        let Ok((kind, payload)) = messages::unwire(body) else { return };
        match kind {
            Kind::PairJoin | Kind::PairConfirm => self.handle_pairing_msg(to, kind, &payload),
            k if k.is_sealed() => {
                if let Err(e) = self.handle_sealed(from, kind, &payload) {
                    tracing::debug!("dropped {}: {e}", kind.as_str());
                }
            }
            _ => {}
        }
    }

    fn handle_sealed(&self, from: &Id, kind: Kind, payload: &[u8]) -> Result<()> {
        let mut inner = self.lock();
        let p = inner.state.pairing.clone().ok_or(Error::State("not paired"))?;
        let phone_id: Id = b64::decode_fixed(&p.phone_id)?;
        if !crypto::ct_eq(from, &phone_id) {
            return Err(Error::Verify("sender is not the paired phone"));
        }
        let device_pub: Pub = b64::decode_fixed(&p.phone_device_pub)?;
        let approve_pub: Pub = b64::decode_fixed(&p.phone_approve_pub)?;
        let env = Envelope::parse(payload)?;
        if env.kind != kind {
            return Err(Error::Verify("wire kind mismatch"));
        }
        let k = inner.k_pair.clone().ok_or(Error::State("not paired"))?;
        let plain = env.open(&device_pub, &k, Dir::PhoneToPc, &phone_id, &self.pc_id())?;
        let now = self.now();
        inner.seen.retain(|_, t| now.saturating_sub(*t) < SEEN_WINDOW_MS);
        if inner.seen.insert(env.msg_id, now).is_some() {
            return Err(Error::Replay);
        }
        match kind {
            Kind::ApprovalResponse => {
                let resp = ApprovalResponse::decode(&plain)?;
                self.apply_response(&mut inner, &resp, &approve_pub, &device_pub, now);
                drop(inner);
                self.changed.notify_waiters();
            }
            Kind::Unpair => {
                Unpair::decode(&plain)?;
                // Phone removed us. Keep enforcement on (fail-secure): recovery codes still work.
                inner.state.pairing = None;
                inner.k_pair = None;
                inner.outstanding.clear();
                self.history(&mut inner, "", "unpair", "unpaired_by_phone", None);
                drop(inner);
                self.changed.notify_waiters();
            }
            _ => {}
        }
        Ok(())
    }

    /// Protocol §4.2 acceptance rule.
    fn apply_response(&self, inner: &mut Inner, resp: &ApprovalResponse, approve_pub: &Pub, device_pub: &Pub, now: u64) {
        let Some((id, o)) = inner.outstanding.iter_mut().find(|(_, o)| crypto::ct_eq(&o.digest, &resp.request_digest)) else {
            return; // unknown or already-removed request
        };
        let id = *id;
        if o.consumed || o.state != ReqState::Pending {
            return;
        }
        if now >= o.req.expires_at {
            o.state = ReqState::Expired;
        } else if resp.verify_decision(approve_pub, device_pub).is_err() {
            o.state = ReqState::Error;
        } else {
            o.state = match resp.decision {
                Decision::Approve if resp.typed_number == o.req.match_number => ReqState::Approved,
                Decision::Approve => ReqState::NotMe, // wrong number: treated as suspicious
                Decision::Deny => ReqState::Denied,
                Decision::NotMe => ReqState::NotMe,
            };
        }
        let (state, account, scenario) = (o.state, o.req.account.clone(), o.req.scenario.as_str());
        let outcome = match (state, resp.decision) {
            (ReqState::Approved, _) => "approved",
            (ReqState::NotMe, Decision::Approve) => "wrong_number",
            (ReqState::NotMe, _) => "not_me",
            (ReqState::Denied, _) => "denied",
            (ReqState::Expired, _) => "expired",
            _ => "error",
        };
        self.history(inner, &account, scenario, outcome, Some(&id));
        if state == ReqState::Approved {
            inner.failures.clear();
            inner.cooldown_level = 0;
        } else {
            self.register_failure(inner);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Gate API (credential provider)
    // -----------------------------------------------------------------------------------------

    pub fn gate_status(&self) -> GateStatus {
        let inner = self.lock();
        GateStatus {
            enforce: inner.state.enforce,
            paired: inner.state.pairing.is_some(),
            relay: if inner.relay.is_some() { "up" } else { "down" },
            cooldown_s: secs(inner.cooldown_until.saturating_sub(self.now())),
        }
    }

    pub fn begin(&self, scenario: Scenario, account: &str, remote: &str) -> std::result::Result<BeginOk, GateError> {
        let mut inner = self.lock();
        let now = self.now();
        let p = inner.state.pairing.clone().ok_or(GateError::NotPaired)?;
        if inner.cooldown_until > now {
            return Err(GateError::Cooldown { retry_s: secs(inner.cooldown_until - now) });
        }
        if inner.relay.is_none() {
            return Err(GateError::RelayDown);
        }
        if account.len() > 256 || remote.len() > 256 {
            return Err(GateError::Internal("field too long".into()));
        }
        // Supersede older pending requests (edge case: rapid attempts).
        let old: Vec<[u8; 16]> = inner.outstanding.iter().filter(|(_, o)| o.state == ReqState::Pending).map(|(k, _)| *k).collect();
        for id in old {
            if let Some(o) = inner.outstanding.get_mut(&id) {
                o.state = ReqState::Expired;
            }
            let _ = self.send_to_phone(&inner, Kind::Cancel, &Cancel { req_id: id }.encode(), 60);
        }
        inner.outstanding.retain(|_, o| now < o.req.expires_at + 5 * 60_000);
        let req = ApprovalRequest {
            req_id: crypto::random()?,
            nonce: crypto::random()?,
            pc_id: self.pc_id(),
            phone_id: b64::decode_fixed(&p.phone_id)?,
            issued_at: now,
            expires_at: now + REQUEST_LIFETIME_MS,
            scenario,
            account: account.to_string(),
            pc_name: inner.state.pc_name.clone(),
            remote_addr: remote.to_string(),
            match_number: crypto::random_range(messages::MATCH_MIN, messages::MATCH_MAX)?,
        };
        self.send_to_phone(&inner, Kind::ApprovalRequest, &req.encode(), (REQUEST_LIFETIME_MS / 1000) as u32)
            .map_err(|_| GateError::RelayDown)?;
        let ok = BeginOk { req: b64::encode(&req.req_id), number: req.match_number, expires_in_s: REQUEST_LIFETIME_MS / 1000 };
        let digest = req.digest();
        inner.outstanding.insert(req.req_id, Outstanding { req, digest, state: ReqState::Pending, consumed: false });
        Ok(ok)
    }

    /// Non-blocking state read. `Approved` is returned exactly once; afterwards `Expired`.
    pub fn poll(&self, req_id: &[u8; 16]) -> ReqState {
        let mut inner = self.lock();
        let now = self.now();
        let Some(o) = inner.outstanding.get_mut(req_id) else {
            return ReqState::Expired;
        };
        if o.state == ReqState::Pending && now >= o.req.expires_at {
            o.state = ReqState::Expired;
            let (account, scenario) = (o.req.account.clone(), o.req.scenario.as_str());
            self.history(&mut inner, &account, scenario, "expired", Some(req_id));
            self.register_failure(&mut inner);
            return ReqState::Expired;
        }
        let o = inner.outstanding.get_mut(req_id).expect("present");
        if o.state == ReqState::Approved {
            if o.consumed {
                return ReqState::Expired;
            }
            o.consumed = true;
        }
        o.state
    }

    /// Read-only view of a request state (never consumes an approval, never records history).
    pub fn poll_peek(&self, req_id: &[u8; 16]) -> &'static str {
        let inner = self.lock();
        match inner.outstanding.get(req_id) {
            Some(o) if o.consumed => "expired",
            Some(o) => o.state.as_str(),
            None => "expired",
        }
    }

    /// Waits up to `timeout` for a terminal state.
    pub async fn wait(&self, req_id: &[u8; 16], timeout: Duration) -> ReqState {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.changed.notified();
            let s = self.poll(req_id);
            if s != ReqState::Pending {
                return s;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.poll(req_id);
            }
        }
    }

    pub fn cancel(&self, req_id: &[u8; 16]) {
        let mut inner = self.lock();
        if let Some(o) = inner.outstanding.get_mut(req_id) {
            if o.state == ReqState::Pending {
                o.state = ReqState::Expired;
                let _ = self.send_to_phone(&inner, Kind::Cancel, &Cancel { req_id: *req_id }.encode(), 60);
            }
        }
    }

    pub fn offline_begin(&self, scenario: Scenario, account: &str) -> Result<(String, String, u64)> {
        let mut inner = self.lock();
        if inner.state.pairing.is_none() {
            return Err(Error::State("not paired"));
        }
        let now = self.now();
        inner.offline.retain(|_, e| now < e.chal.expires_at);
        let chal = OfflineChallenge::new(self.pc_id(), scenario, account, now)?;
        let qr = chal.to_qr(self.keys.as_ref())?;
        let id = b64::encode(&chal.chal_id);
        inner.offline.insert(chal.chal_id, OfflineEntry { chal, attempts_left: offline::MAX_ATTEMPTS });
        Ok((id, qr, offline::OFFLINE_LIFETIME_MS / 1000))
    }

    pub fn offline_verify(&self, chal_id: &[u8; 16], code: &str) -> Result<CodeCheck> {
        let now = self.now();
        let rpath = self.cfg.paths.recovery();
        let locked = store::read_json::<RecoverySet>(&rpath)?.map(|s| s.lock_remaining_ms(now)).unwrap_or(0);
        if locked > 0 {
            return Ok(CodeCheck { valid: false, remaining: 0, attempts_left: 0, locked_s: secs(locked) });
        }
        let mut inner = self.lock();
        let k = inner.k_pair.clone().ok_or(Error::State("not paired"))?;
        let Some(entry) = inner.offline.get_mut(chal_id) else {
            return Ok(CodeCheck { valid: false, remaining: 0, attempts_left: 0, locked_s: 0 });
        };
        if now >= entry.chal.expires_at || entry.attempts_left == 0 {
            inner.offline.remove(chal_id);
            return Ok(CodeCheck { valid: false, remaining: 0, attempts_left: 0, locked_s: 0 });
        }
        if entry.chal.check_code(&pairing::k_offline(&k), code) {
            let chal = inner.offline.remove(chal_id).expect("present").chal;
            self.history(&mut inner, &chal.account, chal.scenario.as_str(), "offline_code", None);
            drop(inner);
            let _ = store::update_json::<RecoverySet, _>(&rpath, |s| {
                if let Some(s) = s.as_mut() {
                    s.record_success();
                }
                Ok(())
            });
            self.queue_notice(NoticeKind::OfflineCodeUsed, "");
            return Ok(CodeCheck { valid: true, remaining: 0, attempts_left: 0, locked_s: 0 });
        }
        entry.attempts_left -= 1;
        let attempts_left = entry.attempts_left;
        drop(inner);
        let lock_ms = store::update_json::<RecoverySet, _>(&rpath, |s| Ok(s.as_mut().map(|s| s.record_failure(now)).unwrap_or(0)))?;
        Ok(CodeCheck { valid: false, remaining: 0, attempts_left, locked_s: secs(lock_ms) })
    }

    /// Lock-screen recovery code (consumes on success).
    pub fn recovery_verify(&self, code: &str, account: &str) -> Result<CodeCheck> {
        let out = verify_recovery_file(&self.cfg.paths, code, self.now())?;
        if out.valid {
            let mut inner = self.lock();
            self.history(&mut inner, account, "unlock", "recovery_code", None);
            drop(inner);
            self.flush_notices();
        }
        Ok(out)
    }

    // -----------------------------------------------------------------------------------------
    // Control API (companion app, Administrators only)
    // -----------------------------------------------------------------------------------------

    pub fn status_json(&self) -> serde_json::Value {
        let inner = self.lock();
        let rec = store::read_json::<RecoverySet>(&self.cfg.paths.recovery()).ok().flatten();
        serde_json::json!({
            "pc_name": inner.state.pc_name,
            "relay_url": inner.state.relay_url,
            "relay": if inner.relay.is_some() { "up" } else { "down" },
            "key_backend": inner.state.key_backend,
            "software_ack": inner.state.software_ack,
            "paired": inner.state.pairing.is_some(),
            "phone_name": inner.state.pairing.as_ref().map(|p| p.phone_name.clone()),
            "attestation": inner.state.pairing.as_ref().map(|p| p.attestation.clone()),
            "enforce": inner.state.enforce,
            "recovery_remaining": rec.as_ref().map(|r| r.remaining()).unwrap_or(0),
            "recovery_confirmed": rec.as_ref().map(|r| r.confirmed).unwrap_or(false),
            "pc_id": b64::encode(&self.pc_id()),
        })
    }

    pub fn settings_set(&self, relay_url: Option<&str>, pc_name: Option<&str>, software_ack: Option<bool>) -> Result<()> {
        let mut inner = self.lock();
        if inner.state.enforce {
            return Err(Error::State("turn off protection before changing settings"));
        }
        if let Some(u) = relay_url {
            if inner.state.pairing.is_some() && u != inner.state.relay_url {
                return Err(Error::State("unpair before changing the relay"));
            }
            pairing::validate_relay_url(u)?;
            inner.state.relay_url = u.trim_end_matches('/').to_string();
        }
        if let Some(n) = pc_name {
            let n = n.trim();
            if n.is_empty() || n.len() > pairing::MAX_NAME {
                return Err(Error::Decode("pc name must be 1-64 characters"));
            }
            inner.state.pc_name = n.to_string();
        }
        if let Some(a) = software_ack {
            inner.state.software_ack = a;
        }
        self.save(&inner)?;
        drop(inner);
        self.relay_changed.notify_waiters();
        Ok(())
    }

    pub fn pair_start(&self) -> Result<(String, u64)> {
        let mut inner = self.lock();
        if inner.state.enforce {
            return Err(Error::State("turn off protection before pairing a new phone"));
        }
        if inner.state.relay_url.is_empty() {
            return Err(Error::State("set the relay server address first"));
        }
        if inner.state.key_backend == "software" && !inner.state.software_ack {
            return Err(Error::State("this PC has no TPM; acknowledge software key protection first"));
        }
        let (pc, offer) = PcPairing::start(self.keys.as_ref(), &inner.state.relay_url, &inner.state.pc_name, self.now())?;
        let uri = pc.qr.to_uri();
        let expires = pc.expires_at();
        let offer_wire = messages::wire(Kind::PairOffer, &offer);
        if let Some(r) = &inner.relay {
            let _ = r.subscribe(&pc.slot());
            let _ = r.send_slot(&pc.slot(), &offer_wire, 300, "offer");
        }
        inner.pairing = Some(PairingSession { pc, join: None, error: None, offer_wire });
        Ok((uri, expires))
    }

    fn handle_pairing_msg(&self, to: &Id, kind: Kind, payload: &[u8]) {
        let roots = &self.cfg.attestation_roots;
        let verifier = |chain: &[Vec<u8>], pubk: &Pub, ch: &[u8; 32], auth: bool| attestation::verify(chain, pubk, ch, auth, roots);
        let now = self.now();
        let mut inner = self.lock();
        let Some(s) = inner.pairing.as_mut() else { return };
        if &s.pc.slot() != to {
            return;
        }
        match kind {
            Kind::PairJoin => match s.pc.handle_join(payload, now, &verifier) {
                Ok(info) => s.join = Some(info),
                Err(e) => s.error = Some(format!("pairing failed: {e}")),
            },
            Kind::PairConfirm => {
                if let Err(e) = s.pc.handle_confirm(payload) {
                    s.error = Some(format!("pairing failed: {e}"));
                }
            }
            _ => {}
        }
        let _ = self.try_finish_pairing(&mut inner);
        drop(inner);
        self.changed.notify_waiters();
    }

    fn try_finish_pairing(&self, inner: &mut Inner) -> Result<()> {
        let now = self.now();
        let Some(s) = inner.pairing.as_mut() else { return Ok(()) };
        let done = match s.pc.try_complete(now) {
            Ok(d) => d,
            Err(e) => {
                s.error = Some(format!("pairing failed: {e}"));
                return Err(e);
            }
        };
        let Some((res, complete)) = done else { return Ok(()) };
        let slot = s.pc.slot();
        let wrapped = self.keys.wrap(res.k_pair.as_slice())?;
        let accepted_unverified = !res.attestation.is_verified();
        inner.state.pairing = Some(Pairing {
            phone_id: b64::encode(&crypto::id_of(&res.phone_device_pub)),
            phone_name: res.phone_name.clone(),
            phone_device_pub: b64::encode(&res.phone_device_pub),
            phone_approve_pub: b64::encode(&res.phone_approve_pub),
            attestation: res.attestation.clone(),
            accepted_unverified,
            k_pair_wrapped: b64::encode(&wrapped),
            paired_at: now,
        });
        inner.k_pair = Some(res.k_pair);
        inner.outstanding.clear();
        self.save(inner)?;
        if let Some(r) = &inner.relay {
            let _ = r.send_slot(&slot, &messages::wire(Kind::PairComplete, &complete), 300, "complete");
        }
        let name = res.phone_name;
        self.history(inner, "", "pairing", &format!("paired:{name}"), None);
        Ok(())
    }

    pub fn pair_poll(&self) -> PairPoll {
        let mut inner = self.lock();
        let now = self.now();
        let Some(s) = inner.pairing.as_mut() else {
            return PairPoll { state: "none", sas: None, phone_name: None, attestation: None, error: None, phone_confirmed: false };
        };
        if s.pc.state() == PcPairingState::Waiting && now >= s.pc.expires_at() {
            s.pc.reject();
            s.error = Some("the QR code expired; start again".into());
        }
        let state = match (s.pc.state(), &s.error) {
            (_, Some(_)) | (PcPairingState::Failed, _) => "failed",
            (PcPairingState::Waiting, _) => "waiting",
            (PcPairingState::Confirm, _) => "confirm",
            (PcPairingState::Completed, _) => "completed",
        };
        PairPoll {
            state,
            sas: s.join.as_ref().map(|j| j.sas.clone()),
            phone_name: s.join.as_ref().map(|j| j.phone_name.clone()),
            attestation: s.join.as_ref().map(|j| j.attestation.clone()),
            error: s.error.clone(),
            phone_confirmed: s.pc.is_phone_confirmed(),
        }
    }

    pub fn pair_decide(&self, accept: bool, accept_unverified: bool) -> Result<()> {
        let mut inner = self.lock();
        let s = inner.pairing.as_mut().ok_or(Error::State("no pairing in progress"))?;
        if !accept {
            s.pc.reject();
            s.error = Some("pairing cancelled".into());
            return Ok(());
        }
        let join = s.join.as_ref().ok_or(Error::State("phone has not joined yet"))?;
        if !join.attestation.is_verified() && !accept_unverified {
            return Err(Error::State("phone key attestation could not be verified; explicit acceptance required"));
        }
        s.pc.owner_accept()?;
        self.try_finish_pairing(&mut inner)?;
        drop(inner);
        self.changed.notify_waiters();
        Ok(())
    }

    /// Generates a new recovery set (shown once). Only while protection is off.
    pub fn recovery_generate(&self) -> Result<Vec<String>> {
        let inner = self.lock();
        if inner.state.enforce {
            return Err(Error::State("turn off protection before generating new recovery codes"));
        }
        if inner.state.pairing.is_none() {
            return Err(Error::State("pair a phone first"));
        }
        drop(inner);
        let (set, codes) = RecoverySet::generate()?;
        store::update_json::<RecoverySet, _>(&self.cfg.paths.recovery(), |s| {
            *s = Some(set);
            Ok(())
        })?;
        Ok(codes)
    }

    pub fn recovery_confirm(&self, code: &str) -> Result<bool> {
        store::update_json::<RecoverySet, _>(&self.cfg.paths.recovery(), |s| match s.as_mut() {
            Some(s) => s.confirm(code),
            None => Ok(false),
        })
    }

    pub fn enable(&self) -> Result<()> {
        let mut inner = self.lock();
        if inner.state.pairing.is_none() {
            return Err(Error::State("not_paired"));
        }
        let confirmed = store::read_json::<RecoverySet>(&self.cfg.paths.recovery())?.map(|r| r.confirmed && r.remaining() > 0).unwrap_or(false);
        if !confirmed {
            return Err(Error::State("recovery_unconfirmed"));
        }
        inner.state.enforce = true;
        self.save(&inner)?;
        self.history(&mut inner, "", "settings", "protection_enabled", None);
        drop(inner);
        self.queue_notice(NoticeKind::ProtectionEnabled, "");
        let _ = self.send_status();
        Ok(())
    }

    fn set_disabled(&self, how: &str) -> Result<()> {
        let mut inner = self.lock();
        inner.state.enforce = false;
        self.save(&inner)?;
        self.history(&mut inner, "", "settings", how, None);
        drop(inner);
        // Notice first, then status: the phone accepts "protection off" only after the notice.
        self.queue_notice(NoticeKind::ProtectionDisabled, how);
        let _ = self.send_status();
        Ok(())
    }

    pub fn disable_begin(&self) -> std::result::Result<Option<BeginOk>, GateError> {
        if !self.lock().state.enforce {
            return Ok(None);
        }
        self.begin(Scenario::DisableProtection, "PhoneGate settings", "").map(Some)
    }

    pub async fn disable_wait(&self, req_id: &[u8; 16], timeout: Duration) -> Result<ReqState> {
        let is_disable = self.lock().outstanding.get(req_id).map(|o| o.req.scenario == Scenario::DisableProtection).unwrap_or(false);
        if !is_disable {
            return Ok(ReqState::Expired);
        }
        let s = self.wait(req_id, timeout).await;
        if s == ReqState::Approved {
            self.set_disabled("protection_disabled_by_phone")?;
        }
        Ok(s)
    }

    pub fn disable_recovery(&self, code: &str) -> Result<CodeCheck> {
        let out = verify_recovery_file(&self.cfg.paths, code, self.now())?;
        if out.valid {
            self.set_disabled("protection_disabled_by_recovery_code")?;
        }
        Ok(out)
    }

    pub fn unpair(&self) -> Result<()> {
        let mut inner = self.lock();
        if inner.state.enforce {
            return Err(Error::State("turn off protection before unpairing"));
        }
        if inner.state.pairing.is_none() {
            return Ok(());
        }
        let _ = self.send_to_phone(&inner, Kind::Unpair, &Unpair { at: self.now() }.encode(), 300);
        inner.state.pairing = None;
        inner.k_pair = None;
        inner.outstanding.clear();
        self.save(&inner)?;
        self.history(&mut inner, "", "settings", "unpaired", None);
        Ok(())
    }

    pub fn history_items(&self, limit: usize) -> Vec<AttemptRecord> {
        let inner = self.lock();
        inner.state.history.iter().rev().take(limit).cloned().collect()
    }

    pub fn is_enforcing(&self) -> bool {
        self.lock().state.enforce
    }
}

/// Recovery-code verification shared by the agent and (when the agent is down) the credential
/// provider: same file, same lock, same lockout.
pub fn verify_recovery_file(paths: &Paths, code: &str, now: u64) -> Result<CodeCheck> {
    store::update_json::<RecoverySet, _>(&paths.recovery(), |s| {
        let Some(set) = s.as_mut() else {
            return Ok(CodeCheck { valid: false, remaining: 0, attempts_left: 0, locked_s: 0 });
        };
        Ok(match set.verify_and_consume(code, now)? {
            VerifyOutcome::Valid { remaining } => CodeCheck { valid: true, remaining, attempts_left: 0, locked_s: 0 },
            VerifyOutcome::Invalid { locked_ms } => CodeCheck { valid: false, remaining: set.remaining(), attempts_left: 0, locked_s: secs(locked_ms) },
            VerifyOutcome::Locked { remaining_ms } => CodeCheck { valid: false, remaining: set.remaining(), attempts_left: 0, locked_s: secs(remaining_ms) },
        })
    })
}

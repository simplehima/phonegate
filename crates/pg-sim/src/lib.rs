//! Software phone used by end-to-end tests. It follows the protocol exactly like the Android
//! app, but keeps keys in memory and fabricates attestation chains under a *test* root.
//! Never shipped; the agent only trusts it when a test explicitly passes [`SimPhone::test_root`].

use std::collections::HashSet;

use pg_core::attestation::der_writer::{key_description, KdSpec};
use pg_core::crypto::{self, Id, Pub};
use pg_core::envelope::{self, Dir, Envelope, SealParams};
use pg_core::health::{Alert, Health};
use pg_core::messages::{self, ApprovalRequest, ApprovalResponse, Command, Decision, Kind, Notice, Status};
use pg_core::offline::OfflineChallenge;
use pg_core::pairing::{self, PhoneKeys, PhonePairing};
use pg_core::signer::{Signer, SoftSigner};
use pg_core::{Error, Result};
use rcgen::{BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair};
use zeroize::Zeroizing;

/// A signer backed by an rcgen key pair so the same key appears in the attestation leaf.
pub struct RcgenSigner {
    inner: SoftSigner,
}

impl RcgenSigner {
    fn new() -> (Self, KeyPair) {
        let kp = KeyPair::generate().expect("keygen");
        let inner = SoftSigner::from_bytes(&scalar_from_pkcs8(&kp.serialize_der())).expect("valid scalar");
        assert_eq!(&inner.public()[..], kp.public_key_raw(), "same key in both representations");
        (RcgenSigner { inner }, kp)
    }
}

impl Signer for RcgenSigner {
    fn public(&self) -> Pub {
        self.inner.public()
    }
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64]> {
        self.inner.sign(msg)
    }
}

/// Extracts the 32-byte private scalar from a P-256 PKCS#8 document (RFC 5915 ECPrivateKey:
/// `INTEGER 1, OCTET STRING (32)`).
fn scalar_from_pkcs8(der: &[u8]) -> [u8; 32] {
    let marker = [0x02, 0x01, 0x01, 0x04, 0x20];
    let i = der.windows(marker.len()).position(|w| w == marker).expect("ECPrivateKey scalar");
    der[i + marker.len()..i + marker.len() + 32].try_into().expect("32 bytes")
}

pub struct SimPc {
    pub pc_pub: Pub,
    pub pc_name: String,
    pub relay_url: String,
    pub k_pair: Zeroizing<[u8; 32]>,
    /// Tamper-alarm state for this PC (feature 002), created on first contact.
    pub health: Option<Health>,
    pub statuses: Vec<Status>,
}

impl SimPc {
    pub fn pc_id(&self) -> Id {
        crypto::id_of(&self.pc_pub)
    }
}

/// A request the phone verified and would show to the owner.
#[derive(Debug, Clone)]
pub struct ShownRequest {
    pub request: ApprovalRequest,
    pub pc_index: usize,
}

pub struct SimPhone {
    pub name: String,
    pub device: SoftSigner,
    approve: RcgenSigner,
    approve_kp: KeyPair,
    device_kp: KeyPair,
    root_kp: KeyPair,
    root_der: Vec<u8>,
    pub pcs: Vec<SimPc>,
    seen: HashSet<[u8; 16]>,
    pending: Option<PhonePairing>,
    pub notices: Vec<Notice>,
    /// Alerts the phone would have shown, oldest first.
    pub alerts: Vec<Alert>,
}

impl SimPhone {
    pub fn new(name: &str) -> Self {
        let (approve, approve_kp) = RcgenSigner::new();
        let (dev, device_kp) = RcgenSigner::new();
        let root_kp = KeyPair::generate().expect("keygen");
        let mut rp = CertificateParams::new(vec![]).expect("params");
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = rp.self_signed(&root_kp).expect("root");
        SimPhone {
            name: name.to_string(),
            device: SoftSigner::from_bytes(&dev.inner.to_bytes()).expect("same key"),
            approve,
            approve_kp,
            device_kp,
            root_kp,
            root_der: root.der().to_vec(),
            pcs: vec![],
            seen: HashSet::new(),
            pending: None,
            notices: vec![],
            alerts: vec![],
        }
    }

    /// Trust anchor for this simulator's attestation chains (tests pass it to the agent).
    pub fn test_root(&self) -> Vec<u8> {
        self.root_der.clone()
    }

    pub fn id(&self) -> Id {
        crypto::id_of(&self.device.public())
    }

    pub fn approve_public(&self) -> Pub {
        self.approve.public()
    }

    fn chain(&self, key: &KeyPair, challenge: &[u8; 32], user_auth: bool) -> Vec<Vec<u8>> {
        let mut rp = CertificateParams::new(vec![]).expect("params");
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = rp.self_signed(&self.root_kp).expect("root");
        let kd = key_description(&KdSpec { challenge, security_level: 2, user_auth, auth_timeout: None, device_locked: true, boot_state: 0 });
        let mut lp = CertificateParams::new(vec![]).expect("params");
        lp.custom_extensions.push(CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17], kd));
        let leaf = lp.signed_by(key, &root, &self.root_kp).expect("leaf");
        vec![leaf.der().to_vec(), self.root_der.clone()]
    }

    /// Scans the QR and answers the offer. Returns `(slot, pair-join wire body, sas)`.
    pub fn begin_pairing(&mut self, qr_uri: &str) -> Result<PhonePairing> {
        PhonePairing::from_uri(qr_uri)
    }

    pub fn answer_offer(&mut self, mut p: PhonePairing, offer_wire: &[u8], now: u64) -> Result<(Vec<u8>, String)> {
        let (kind, payload) = messages::unwire(offer_wire)?;
        if kind != Kind::PairOffer {
            return Err(Error::Decode("expected pair-offer"));
        }
        let ch = p.attest_challenge();
        let keys = PhoneKeys {
            device: &self.device,
            approve: &self.approve,
            device_chain: self.chain(&self.device_kp, &ch, false),
            approve_chain: self.chain(&self.approve_kp, &ch, true),
        };
        let (join, sas) = p.handle_offer(&payload, now, &keys, &self.name)?;
        self.pending = Some(p);
        Ok((messages::wire(Kind::PairJoin, &join), sas))
    }

    /// Owner confirmed the SAS on the phone.
    pub fn confirm_pairing(&self) -> Result<Vec<u8>> {
        let p = self.pending.as_ref().ok_or(Error::State("no pairing in progress"))?;
        Ok(messages::wire(Kind::PairConfirm, &p.confirm()?))
    }

    pub fn complete_pairing(&mut self, complete_wire: &[u8]) -> Result<()> {
        let (kind, payload) = messages::unwire(complete_wire)?;
        if kind != Kind::PairComplete {
            return Err(Error::Decode("expected pair-complete"));
        }
        let mut p = self.pending.take().ok_or(Error::State("no pairing in progress"))?;
        let r = p.handle_complete(&payload)?;
        self.pcs.retain(|pc| pc.pc_pub != r.pc_pub);
        self.pcs.push(SimPc { pc_pub: r.pc_pub, pc_name: r.pc_name, relay_url: r.relay_url, k_pair: r.k_pair, health: None, statuses: vec![] });
        Ok(())
    }

    pub fn pending_slot(&self) -> Option<Id> {
        self.pending.as_ref().map(|p| p.slot())
    }

    /// Verifies an incoming sealed message from a paired PC (protocol §4.3).
    pub fn receive(&mut self, from: &Id, wire_body: &[u8], now: u64) -> Result<Option<ShownRequest>> {
        let (kind, payload) = messages::unwire(wire_body)?;
        let env = Envelope::parse(&payload)?;
        let idx = self.pcs.iter().position(|p| &p.pc_id() == from).ok_or(Error::Verify("message from unpaired pc"))?;
        let pc = &self.pcs[idx];
        let plain = env.open(&pc.pc_pub, &pc.k_pair, Dir::PcToPhone, &pc.pc_id(), &self.id())?;
        if !self.seen.insert(env.msg_id) {
            return Err(Error::Replay);
        }
        match kind {
            Kind::ApprovalRequest => {
                let r = ApprovalRequest::decode(&plain)?;
                if r.pc_id != pc.pc_id() || r.phone_id != self.id() {
                    return Err(Error::Verify("request ids do not match pairing"));
                }
                const SKEW: u64 = 300_000;
                if r.issued_at > now + SKEW || now > r.expires_at + SKEW {
                    return Err(Error::Expired);
                }
                Ok(Some(ShownRequest { request: r, pc_index: idx }))
            }
            Kind::Notice => {
                let n = Notice::decode(&plain)?;
                let h = self.pcs[idx].health.get_or_insert_with(|| Health::new(now));
                if let Some(a) = h.on_notice(n.kind, &n.detail, now) {
                    self.alerts.push(a);
                }
                self.notices.push(n);
                Ok(None)
            }
            Kind::Status => {
                let st = Status::decode(&plain)?;
                let pc = &mut self.pcs[idx];
                let h = pc.health.get_or_insert_with(|| Health::new(now));
                if let Some(a) = h.on_status(&st, now)? {
                    self.alerts.push(a);
                }
                pc.statuses.push(st);
                Ok(None)
            }
            Kind::Unpair => {
                self.pcs.remove(idx);
                Ok(None)
            }
            Kind::Cancel => Ok(None),
            _ => Err(Error::Decode("unexpected kind from pc")),
        }
    }

    /// Periodic silence check for every paired PC (the phone app runs this every minute).
    pub fn tick(&mut self, now: u64) {
        for pc in &mut self.pcs {
            let h = pc.health.get_or_insert_with(|| Health::new(now));
            if let Some(a) = h.tick(now) {
                self.alerts.push(a);
            }
        }
    }

    /// Builds the response the owner's choice produces. `Approve` uses the approve key; the
    /// real app would require the typed number and a biometric first.
    pub fn respond(&self, shown: &ShownRequest, decision: Decision, typed: u64, now: u64) -> Result<Vec<u8>> {
        let signer: &dyn Signer = if decision == Decision::Approve { &self.approve } else { &self.device };
        let resp = ApprovalResponse::create(signer, shown.request.digest(), decision, typed, now)?;
        self.seal_to_pc(shown.pc_index, Kind::ApprovalResponse, &resp.encode())
    }

    /// Raw response with an arbitrary signer (for negative tests).
    pub fn respond_with(&self, shown: &ShownRequest, signer: &dyn Signer, decision: Decision, typed: u64, now: u64) -> Result<Vec<u8>> {
        let resp = ApprovalResponse::create(signer, shown.request.digest(), decision, typed, now)?;
        self.seal_to_pc(shown.pc_index, Kind::ApprovalResponse, &resp.encode())
    }

    pub fn seal_to_pc(&self, idx: usize, kind: Kind, plain: &[u8]) -> Result<Vec<u8>> {
        let pc = &self.pcs[idx];
        let p = SealParams { k_pair: &pc.k_pair, dir: Dir::PhoneToPc, kind, from: self.id(), to: pc.pc_id(), signer: &self.device };
        let (env, _) = envelope::seal(&p, plain)?;
        Ok(messages::wire(kind, &env))
    }

    pub fn offline_code(&self, qr: &str, pc_index: usize, now: u64) -> Result<String> {
        let pc = &self.pcs[pc_index];
        let c = OfflineChallenge::parse_qr(qr, &pc.pc_pub, now)?;
        Ok(c.response_code(&pairing::k_offline(&pc.k_pair)))
    }

    /// Builds a phone→PC "turn off protection" command (feature 004), its authority signed by the
    /// chosen key. Use `approve = true` for a genuine command; `false` (device key) for the
    /// wrong-authority negative test.
    pub fn disable_command(&self, pc_index: usize, now: u64, approve: bool) -> Result<Vec<u8>> {
        let pc = &self.pcs[pc_index];
        let signer: &dyn Signer = if approve { &self.approve } else { &self.device };
        let cmd = Command::create(
            signer,
            pc.pc_id(),
            self.id(),
            "disable-protection",
            now,
            now + 120_000,
            crypto::random()?,
            crypto::random()?,
        )?;
        self.seal_to_pc(pc_index, Kind::Command, &cmd.encode())
    }
}

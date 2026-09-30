//! QR pairing (protocol §3). The QR code is the only authentic channel: it carries the one-time
//! `psk` and the hash of the PC key, so the relay can neither read nor substitute anything.

use zeroize::Zeroizing;

use crate::attestation::AttestationResult;
use crate::crypto::{self, EphemeralKey, Id, Pub};
use crate::encoding::{decode, Enc};
use crate::error::{Error, Result};
use crate::signer::Signer;

pub const PAIRING_LIFETIME_MS: u64 = 300_000;
pub const MAX_NAME: usize = 64;

// ---------------------------------------------------------------------------------------------
// QR payload
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingQr {
    pub relay_url: String,
    pub pairing_id: [u8; 16],
    pub psk: [u8; 32],
    pub pc_pub_hash: [u8; 32],
    pub pc_name: String,
}

fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn pct_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return Err(Error::Decode("truncated percent escape"));
            }
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).map_err(|_| Error::Decode("bad escape"))?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| Error::Decode("bad escape"))?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| Error::Decode("invalid utf-8 in uri"))
}

pub fn validate_relay_url(url: &str) -> Result<()> {
    let ok = url.starts_with("https://")
        || url.starts_with("http://localhost")
        || url.starts_with("http://127.0.0.1");
    if !ok || url.len() > 256 {
        return Err(Error::Decode("relay url must be https (http only for localhost)"));
    }
    Ok(())
}

impl PairingQr {
    pub fn to_uri(&self) -> String {
        format!(
            "phonegate://pair?v=1&r={}&i={}&k={}&h={}&n={}",
            pct_encode(&self.relay_url),
            crypto::b64::encode(&self.pairing_id),
            crypto::b64::encode(&self.psk),
            crypto::b64::encode(&self.pc_pub_hash),
            pct_encode(&self.pc_name)
        )
    }

    pub fn parse(uri: &str) -> Result<Self> {
        let q = uri.strip_prefix("phonegate://pair?").ok_or(Error::Decode("not a pairing uri"))?;
        let (mut v, mut r, mut i, mut k, mut h, mut n) = (None, None, None, None, None, None);
        for part in q.split('&') {
            let (key, val) = part.split_once('=').ok_or(Error::Decode("bad query"))?;
            let slot = match key {
                "v" => &mut v,
                "r" => &mut r,
                "i" => &mut i,
                "k" => &mut k,
                "h" => &mut h,
                "n" => &mut n,
                _ => continue, // forward compatible
            };
            if slot.is_some() {
                return Err(Error::Decode("duplicate query parameter"));
            }
            *slot = Some(val.to_string());
        }
        if v.as_deref() != Some("1") {
            return Err(Error::Decode("unsupported pairing version"));
        }
        let relay_url = pct_decode(&r.ok_or(Error::Decode("missing relay"))?)?;
        validate_relay_url(&relay_url)?;
        let pc_name = pct_decode(&n.ok_or(Error::Decode("missing name"))?)?;
        if pc_name.is_empty() || pc_name.len() > MAX_NAME {
            return Err(Error::Decode("bad pc name"));
        }
        Ok(PairingQr {
            relay_url,
            pairing_id: crypto::b64::decode_fixed(&i.ok_or(Error::Decode("missing id"))?)?,
            psk: crypto::b64::decode_fixed(&k.ok_or(Error::Decode("missing psk"))?)?,
            pc_pub_hash: crypto::b64::decode_fixed(&h.ok_or(Error::Decode("missing hash"))?)?,
            pc_name,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Derivations (protocol §3.2)
// ---------------------------------------------------------------------------------------------

pub fn slot(pairing_id: &[u8; 16]) -> Id {
    crypto::sha256(&Enc::new("phonegate/v1/pair-slot").bytes(pairing_id).finish())
}

pub fn k_join(psk: &[u8; 32], pairing_id: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    crypto::hkdf(psk, pairing_id, b"phonegate/v1/pair-join-key")
}

pub fn attest_challenge(psk: &[u8; 32], pairing_id: &[u8; 16]) -> [u8; 32] {
    crypto::hmac(psk, &Enc::new("phonegate/v1/attest").bytes(pairing_id).finish())
}

#[derive(Debug, Clone)]
pub struct TranscriptInput<'a> {
    pub pairing_id: &'a [u8; 16],
    pub pc_pub: &'a Pub,
    pub pc_eph_pub: &'a Pub,
    pub pc_name: &'a str,
    pub phone_device_pub: &'a Pub,
    pub phone_approve_pub: &'a Pub,
    pub phone_eph_pub: &'a Pub,
    pub phone_name: &'a str,
}

pub fn transcript(t: &TranscriptInput<'_>) -> [u8; 32] {
    crypto::sha256(
        &Enc::new("phonegate/v1/pair-transcript")
            .bytes(t.pairing_id)
            .bytes(t.pc_pub)
            .bytes(t.pc_eph_pub)
            .str(t.pc_name)
            .bytes(t.phone_device_pub)
            .bytes(t.phone_approve_pub)
            .bytes(t.phone_eph_pub)
            .str(t.phone_name)
            .finish(),
    )
}

pub fn k_pair(shared: &[u8; 32], psk: &[u8; 32], th: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    crypto::hkdf(shared, psk, &Enc::new("phonegate/v1/k-pair").bytes(th).finish())
}

pub fn sas(k_pair: &[u8; 32]) -> String {
    let d = crypto::hkdf(k_pair, b"", b"phonegate/v1/sas");
    let v = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{v:06}")
}

pub fn confirm_mac(k_pair: &[u8; 32], role: &str, th: &[u8; 32]) -> [u8; 32] {
    crypto::hmac(k_pair, &Enc::new("phonegate/v1/confirm").str(role).bytes(th).finish())
}

pub fn k_offline(k_pair: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    crypto::hkdf(k_pair, b"", b"phonegate/v1/offline")
}

// ---------------------------------------------------------------------------------------------
// Messages (protocol §3.3)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairOffer {
    pub pairing_id: [u8; 16],
    pub pc_pub: Pub,
    pub pc_eph_pub: Pub,
    pub pc_name: String,
    pub expires_at: u64,
}

impl PairOffer {
    fn body(&self) -> Vec<u8> {
        Enc::new("phonegate/v1/pair-offer")
            .bytes(&self.pairing_id)
            .bytes(&self.pc_pub)
            .bytes(&self.pc_eph_pub)
            .str(&self.pc_name)
            .u64(self.expires_at)
            .finish()
    }

    pub fn encode_signed(&self, signer: &dyn Signer) -> Result<Vec<u8>> {
        let body = self.body();
        let sig = signer.sign(&body)?;
        Ok(Enc::new("phonegate/v1/pair-offer-signed").bytes(&body).bytes(&sig).finish())
    }

    /// Parses and verifies against the QR (hash of PC key, pairing id) and the clock.
    pub fn verify(payload: &[u8], qr: &PairingQr, now: u64) -> Result<Self> {
        let outer = decode(payload, "phonegate/v1/pair-offer-signed", 3)?;
        let body = outer.bytes(1);
        let sig = outer.bytes(2);
        let f = decode(body, "phonegate/v1/pair-offer", 6)?;
        let offer = PairOffer {
            pairing_id: f.fixed(1)?,
            pc_pub: f.fixed(2)?,
            pc_eph_pub: f.fixed(3)?,
            pc_name: f.string_max(4, MAX_NAME)?,
            expires_at: f.u64(5)?,
        };
        if !crypto::ct_eq(&crypto::id_of(&offer.pc_pub), &qr.pc_pub_hash) {
            return Err(Error::Verify("pc key does not match the QR code"));
        }
        if offer.pairing_id != qr.pairing_id {
            return Err(Error::Verify("pairing id mismatch"));
        }
        crypto::verify(&offer.pc_pub, body, sig)?;
        crypto::parse_pub(&offer.pc_eph_pub)?;
        if now >= offer.expires_at {
            return Err(Error::Expired);
        }
        Ok(offer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairJoin {
    pub pairing_id: [u8; 16],
    pub phone_device_pub: Pub,
    pub phone_approve_pub: Pub,
    pub phone_eph_pub: Pub,
    pub phone_name: String,
    pub device_chain: Vec<Vec<u8>>,
    pub approve_chain: Vec<Vec<u8>>,
    pub sig_device: [u8; 64],
    pub sig_approve: [u8; 64],
}

pub fn join_sig_bytes(th: &[u8; 32]) -> Vec<u8> {
    Enc::new("phonegate/v1/pair-join-sig").bytes(th).finish()
}

fn join_aad(pairing_id: &[u8; 16]) -> Vec<u8> {
    Enc::new("phonegate/v1/pair-join-aad").bytes(pairing_id).finish()
}

impl PairJoin {
    pub fn encode_inner(&self) -> Vec<u8> {
        Enc::new("phonegate/v1/pair-join-body")
            .bytes(&self.pairing_id)
            .bytes(&self.phone_device_pub)
            .bytes(&self.phone_approve_pub)
            .bytes(&self.phone_eph_pub)
            .str(&self.phone_name)
            .list(&self.device_chain)
            .list(&self.approve_chain)
            .bytes(&self.sig_device)
            .bytes(&self.sig_approve)
            .finish()
    }

    pub fn seal(&self, psk: &[u8; 32], nonce: [u8; 12]) -> Result<Vec<u8>> {
        let key = k_join(psk, &self.pairing_id);
        let ct = crypto::aead_seal(&key, &nonce, &self.encode_inner(), &join_aad(&self.pairing_id))?;
        Ok(Enc::new("phonegate/v1/pair-join").bytes(&nonce).bytes(&ct).finish())
    }

    pub fn open(payload: &[u8], psk: &[u8; 32], pairing_id: &[u8; 16]) -> Result<Self> {
        let outer = decode(payload, "phonegate/v1/pair-join", 3)?;
        let nonce: [u8; 12] = outer.fixed(1)?;
        let key = k_join(psk, pairing_id);
        let inner = crypto::aead_open(&key, &nonce, outer.bytes(2), &join_aad(pairing_id))?;
        let f = decode(&inner, "phonegate/v1/pair-join-body", 10)?;
        let j = PairJoin {
            pairing_id: f.fixed(1)?,
            phone_device_pub: f.fixed(2)?,
            phone_approve_pub: f.fixed(3)?,
            phone_eph_pub: f.fixed(4)?,
            phone_name: f.string_max(5, MAX_NAME)?,
            device_chain: f.list(6)?,
            approve_chain: f.list(7)?,
            sig_device: f.fixed(8)?,
            sig_approve: f.fixed(9)?,
        };
        if &j.pairing_id != pairing_id {
            return Err(Error::Verify("pairing id mismatch"));
        }
        for k in [&j.phone_device_pub, &j.phone_approve_pub, &j.phone_eph_pub] {
            crypto::parse_pub(k)?;
        }
        if j.phone_device_pub == j.phone_approve_pub {
            return Err(Error::Verify("device and approve keys must differ"));
        }
        Ok(j)
    }
}

pub fn encode_confirm(label: &str, mac: &[u8; 32]) -> Vec<u8> {
    Enc::new(label).bytes(mac).finish()
}

pub fn decode_confirm(payload: &[u8], label: &str) -> Result<[u8; 32]> {
    decode(payload, label, 2)?.fixed(1)
}

pub const CONFIRM_LABEL: &str = "phonegate/v1/pair-confirm";
pub const COMPLETE_LABEL: &str = "phonegate/v1/pair-complete";

// ---------------------------------------------------------------------------------------------
// PC role
// ---------------------------------------------------------------------------------------------

/// Attestation verifier callback: `(chain, expected_pub, challenge, require_user_auth)`.
pub type AttestVerifier<'a> = &'a dyn Fn(&[Vec<u8>], &Pub, &[u8; 32], bool) -> AttestationResult;

struct Joined {
    device_pub: Pub,
    approve_pub: Pub,
    phone_name: String,
    th: [u8; 32],
    k_pair: Zeroizing<[u8; 32]>,
    attestation: AttestationResult,
}

#[derive(Debug, Clone)]
pub struct JoinInfo {
    pub sas: String,
    pub phone_name: String,
    pub attestation: AttestationResult,
}

pub struct PcPairingResult {
    pub phone_device_pub: Pub,
    pub phone_approve_pub: Pub,
    pub phone_name: String,
    pub k_pair: Zeroizing<[u8; 32]>,
    pub attestation: AttestationResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcPairingState {
    Waiting,
    Confirm,
    Completed,
    Failed,
}

pub struct PcPairing {
    pub qr: PairingQr,
    pc_pub: Pub,
    eph: EphemeralKey,
    expires_at: u64,
    joined: Option<Joined>,
    phone_confirmed: bool,
    owner_accepted: bool,
    state: PcPairingState,
}

impl PcPairing {
    pub fn start(signer: &dyn Signer, relay_url: &str, pc_name: &str, now: u64) -> Result<(Self, Vec<u8>)> {
        validate_relay_url(relay_url)?;
        if pc_name.is_empty() || pc_name.len() > MAX_NAME {
            return Err(Error::Decode("bad pc name"));
        }
        let pc_pub = signer.public();
        let eph = EphemeralKey::generate()?;
        let qr = PairingQr {
            relay_url: relay_url.to_string(),
            pairing_id: crypto::random()?,
            psk: crypto::random()?,
            pc_pub_hash: crypto::id_of(&pc_pub),
            pc_name: pc_name.to_string(),
        };
        let expires_at = now + PAIRING_LIFETIME_MS;
        let offer = PairOffer {
            pairing_id: qr.pairing_id,
            pc_pub,
            pc_eph_pub: eph.public(),
            pc_name: pc_name.to_string(),
            expires_at,
        };
        let payload = offer.encode_signed(signer)?;
        Ok((
            PcPairing {
                qr,
                pc_pub,
                eph,
                expires_at,
                joined: None,
                phone_confirmed: false,
                owner_accepted: false,
                state: PcPairingState::Waiting,
            },
            payload,
        ))
    }

    pub fn slot(&self) -> Id {
        slot(&self.qr.pairing_id)
    }

    pub fn state(&self) -> PcPairingState {
        self.state
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    fn fail<T>(&mut self, e: Error) -> Result<T> {
        self.state = PcPairingState::Failed;
        self.joined = None;
        Err(e)
    }

    pub fn handle_join(&mut self, payload: &[u8], now: u64, verify: AttestVerifier<'_>) -> Result<JoinInfo> {
        if self.state != PcPairingState::Waiting {
            return self.fail(Error::State("join not expected"));
        }
        if now >= self.expires_at {
            return self.fail(Error::Expired);
        }
        let j = match PairJoin::open(payload, &self.qr.psk, &self.qr.pairing_id) {
            Ok(j) => j,
            Err(e) => return self.fail(e),
        };
        let th = transcript(&TranscriptInput {
            pairing_id: &self.qr.pairing_id,
            pc_pub: &self.pc_pub,
            pc_eph_pub: &self.eph.public(),
            pc_name: &self.qr.pc_name,
            phone_device_pub: &j.phone_device_pub,
            phone_approve_pub: &j.phone_approve_pub,
            phone_eph_pub: &j.phone_eph_pub,
            phone_name: &j.phone_name,
        });
        let sb = join_sig_bytes(&th);
        if let Err(e) = crypto::verify(&j.phone_device_pub, &sb, &j.sig_device) {
            return self.fail(e);
        }
        if let Err(e) = crypto::verify(&j.phone_approve_pub, &sb, &j.sig_approve) {
            return self.fail(e);
        }
        let chal = attest_challenge(&self.qr.psk, &self.qr.pairing_id);
        let a_dev = verify(&j.device_chain, &j.phone_device_pub, &chal, false);
        let a_app = verify(&j.approve_chain, &j.phone_approve_pub, &chal, true);
        let attestation = a_dev.and(a_app);
        let shared = match self.eph.agree(&j.phone_eph_pub) {
            Ok(s) => s,
            Err(e) => return self.fail(e),
        };
        let kp = k_pair(&shared, &self.qr.psk, &th);
        let info = JoinInfo { sas: sas(&kp), phone_name: j.phone_name.clone(), attestation: attestation.clone() };
        self.joined = Some(Joined {
            device_pub: j.phone_device_pub,
            approve_pub: j.phone_approve_pub,
            phone_name: j.phone_name,
            th,
            k_pair: kp,
            attestation,
        });
        self.state = PcPairingState::Confirm;
        Ok(info)
    }

    pub fn handle_confirm(&mut self, payload: &[u8]) -> Result<()> {
        if self.state != PcPairingState::Confirm {
            return self.fail(Error::State("confirm not expected"));
        }
        let mac = match decode_confirm(payload, CONFIRM_LABEL) {
            Ok(m) => m,
            Err(e) => return self.fail(e),
        };
        let j = self.joined.as_ref().expect("joined in Confirm state");
        let expect = confirm_mac(&j.k_pair, "phone", &j.th);
        if !crypto::ct_eq(&mac, &expect) {
            return self.fail(Error::Verify("phone confirmation mac mismatch"));
        }
        self.phone_confirmed = true;
        Ok(())
    }

    /// The owner confirmed the SAS on the PC (or rejected it: then call [`PcPairing::reject`]).
    pub fn owner_accept(&mut self) -> Result<()> {
        if self.state != PcPairingState::Confirm {
            return Err(Error::State("nothing to accept"));
        }
        self.owner_accepted = true;
        Ok(())
    }

    pub fn reject(&mut self) {
        self.state = PcPairingState::Failed;
        self.joined = None;
    }

    pub fn is_phone_confirmed(&self) -> bool {
        self.phone_confirmed
    }

    /// Completes when both the phone confirmation and owner acceptance are present. Returns the
    /// pairing result and the `pair-complete` payload to send to the phone.
    pub fn try_complete(&mut self, now: u64) -> Result<Option<(PcPairingResult, Vec<u8>)>> {
        if self.state != PcPairingState::Confirm || !self.phone_confirmed || !self.owner_accepted {
            return Ok(None);
        }
        if now >= self.expires_at + PAIRING_LIFETIME_MS {
            return self.fail(Error::Expired);
        }
        let j = self.joined.take().expect("joined in Confirm state");
        let payload = encode_confirm(COMPLETE_LABEL, &confirm_mac(&j.k_pair, "pc", &j.th));
        self.state = PcPairingState::Completed;
        Ok(Some((
            PcPairingResult {
                phone_device_pub: j.device_pub,
                phone_approve_pub: j.approve_pub,
                phone_name: j.phone_name,
                k_pair: j.k_pair,
                attestation: j.attestation,
            },
            payload,
        )))
    }
}

// ---------------------------------------------------------------------------------------------
// Phone role (reference implementation; Android mirrors it in Kotlin)
// ---------------------------------------------------------------------------------------------

pub struct PhonePairingResult {
    pub pc_pub: Pub,
    pub pc_name: String,
    pub relay_url: String,
    pub k_pair: Zeroizing<[u8; 32]>,
}

pub struct PhonePairing {
    pub qr: PairingQr,
    offer: Option<PairOffer>,
    th: [u8; 32],
    k_pair: Option<Zeroizing<[u8; 32]>>,
}

pub struct PhoneKeys<'a> {
    pub device: &'a dyn Signer,
    pub approve: &'a dyn Signer,
    pub device_chain: Vec<Vec<u8>>,
    pub approve_chain: Vec<Vec<u8>>,
}

impl PhonePairing {
    pub fn from_uri(uri: &str) -> Result<Self> {
        Ok(PhonePairing { qr: PairingQr::parse(uri)?, offer: None, th: [0; 32], k_pair: None })
    }

    pub fn slot(&self) -> Id {
        slot(&self.qr.pairing_id)
    }

    pub fn attest_challenge(&self) -> [u8; 32] {
        attest_challenge(&self.qr.psk, &self.qr.pairing_id)
    }

    /// Verifies the offer and produces `(pair-join payload, sas)`.
    pub fn handle_offer(&mut self, payload: &[u8], now: u64, keys: &PhoneKeys<'_>, phone_name: &str) -> Result<(Vec<u8>, String)> {
        let eph = EphemeralKey::generate()?;
        self.handle_offer_with(payload, now, keys, phone_name, &eph, crypto::random()?)
    }

    pub fn handle_offer_with(
        &mut self,
        payload: &[u8],
        now: u64,
        keys: &PhoneKeys<'_>,
        phone_name: &str,
        eph: &EphemeralKey,
        nonce: [u8; 12],
    ) -> Result<(Vec<u8>, String)> {
        if self.offer.is_some() {
            return Err(Error::State("offer already handled"));
        }
        if phone_name.is_empty() || phone_name.len() > MAX_NAME {
            return Err(Error::Decode("bad phone name"));
        }
        let offer = PairOffer::verify(payload, &self.qr, now)?;
        let device_pub = keys.device.public();
        let approve_pub = keys.approve.public();
        let th = transcript(&TranscriptInput {
            pairing_id: &self.qr.pairing_id,
            pc_pub: &offer.pc_pub,
            pc_eph_pub: &offer.pc_eph_pub,
            pc_name: &offer.pc_name,
            phone_device_pub: &device_pub,
            phone_approve_pub: &approve_pub,
            phone_eph_pub: &eph.public(),
            phone_name,
        });
        let sb = join_sig_bytes(&th);
        let join = PairJoin {
            pairing_id: self.qr.pairing_id,
            phone_device_pub: device_pub,
            phone_approve_pub: approve_pub,
            phone_eph_pub: eph.public(),
            phone_name: phone_name.to_string(),
            device_chain: keys.device_chain.clone(),
            approve_chain: keys.approve_chain.clone(),
            sig_device: keys.device.sign(&sb)?,
            sig_approve: keys.approve.sign(&sb)?,
        };
        let shared = eph.agree(&offer.pc_eph_pub)?;
        let kp = k_pair(&shared, &self.qr.psk, &th);
        let code = sas(&kp);
        self.th = th;
        self.k_pair = Some(kp);
        self.offer = Some(offer);
        Ok((join.seal(&self.qr.psk, nonce)?, code))
    }

    /// Owner confirmed the SAS on the phone.
    pub fn confirm(&self) -> Result<Vec<u8>> {
        let kp = self.k_pair.as_ref().ok_or(Error::State("no offer yet"))?;
        Ok(encode_confirm(CONFIRM_LABEL, &confirm_mac(kp, "phone", &self.th)))
    }

    pub fn handle_complete(&mut self, payload: &[u8]) -> Result<PhonePairingResult> {
        let kp = self.k_pair.take().ok_or(Error::State("no offer yet"))?;
        let offer = self.offer.take().ok_or(Error::State("no offer yet"))?;
        let mac = decode_confirm(payload, COMPLETE_LABEL)?;
        if !crypto::ct_eq(&mac, &confirm_mac(&kp, "pc", &self.th)) {
            return Err(Error::Verify("pc confirmation mac mismatch"));
        }
        Ok(PhonePairingResult { pc_pub: offer.pc_pub, pc_name: offer.pc_name, relay_url: self.qr.relay_url.clone(), k_pair: kp })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::SoftSigner;

    fn accept_all(_: &[Vec<u8>], _: &Pub, _: &[u8; 32], _: bool) -> AttestationResult {
        AttestationResult::Verified
    }

    struct Phone {
        device: SoftSigner,
        approve: SoftSigner,
    }

    impl Phone {
        fn new() -> Self {
            Phone { device: SoftSigner::generate().unwrap(), approve: SoftSigner::generate().unwrap() }
        }
        fn keys(&self) -> PhoneKeys<'_> {
            PhoneKeys { device: &self.device, approve: &self.approve, device_chain: vec![], approve_chain: vec![] }
        }
    }

    #[test]
    fn full_pairing() {
        let pc_key = SoftSigner::generate().unwrap();
        let (mut pc, offer) = PcPairing::start(&pc_key, "https://relay.example", "Desk", 1_000).unwrap();
        let phone = Phone::new();
        let mut ph = PhonePairing::from_uri(&pc.qr.to_uri()).unwrap();
        let (join, sas_phone) = ph.handle_offer(&offer, 2_000, &phone.keys(), "Pixel").unwrap();
        let info = pc.handle_join(&join, 3_000, &accept_all).unwrap();
        assert_eq!(info.sas, sas_phone);
        assert_eq!(info.phone_name, "Pixel");
        pc.handle_confirm(&ph.confirm().unwrap()).unwrap();
        assert!(pc.try_complete(4_000).unwrap().is_none(), "owner has not accepted yet");
        pc.owner_accept().unwrap();
        let (res, complete) = pc.try_complete(4_000).unwrap().unwrap();
        let pres = ph.handle_complete(&complete).unwrap();
        assert_eq!(*res.k_pair, *pres.k_pair);
        assert_eq!(res.phone_approve_pub, phone.approve.public());
        assert_eq!(pres.pc_pub, pc_key.public());
        assert_eq!(pc.state(), PcPairingState::Completed);
    }

    #[test]
    fn qr_roundtrip_and_validation() {
        let qr = PairingQr {
            relay_url: "https://relay.example/x?y=z".into(),
            pairing_id: [1; 16],
            psk: [2; 32],
            pc_pub_hash: [3; 32],
            pc_name: "Ali's PC & more".into(),
        };
        assert_eq!(PairingQr::parse(&qr.to_uri()).unwrap(), qr);
        assert!(PairingQr::parse(&qr.to_uri().replace("v=1", "v=2")).is_err());
        let mut http = qr.clone();
        http.relay_url = "http://evil.example".into();
        assert!(PairingQr::parse(&http.to_uri()).is_err());
        assert!(PairingQr::parse("phonegate://pair?v=1&v=1").is_err());
        assert!(PairingQr::parse("https://example").is_err());
    }

    #[test]
    fn offer_substitution_rejected() {
        // A malicious relay swaps the PC key in the offer: the QR hash check catches it.
        let pc_key = SoftSigner::generate().unwrap();
        let (pc, _) = PcPairing::start(&pc_key, "https://r.example", "Desk", 0).unwrap();
        let evil = SoftSigner::generate().unwrap();
        let (_, evil_offer) = PcPairing::start(&evil, "https://r.example", "Desk", 0).unwrap();
        let mut ph = PhonePairing::from_uri(&pc.qr.to_uri()).unwrap();
        let phone = Phone::new();
        assert!(ph.handle_offer(&evil_offer, 1, &phone.keys(), "P").is_err());
    }

    #[test]
    fn expired_offer_rejected() {
        let pc_key = SoftSigner::generate().unwrap();
        let (pc, offer) = PcPairing::start(&pc_key, "https://r.example", "Desk", 0).unwrap();
        let mut ph = PhonePairing::from_uri(&pc.qr.to_uri()).unwrap();
        let phone = Phone::new();
        assert_eq!(ph.handle_offer(&offer, PAIRING_LIFETIME_MS, &phone.keys(), "P").unwrap_err(), Error::Expired);
    }

    #[test]
    fn join_from_attacker_without_psk_rejected() {
        let pc_key = SoftSigner::generate().unwrap();
        let (mut pc, offer) = PcPairing::start(&pc_key, "https://r.example", "Desk", 0).unwrap();
        // Attacker knows everything in the offer except psk; forges a QR with a guessed psk.
        let mut fake_qr = pc.qr.clone();
        fake_qr.psk = [0; 32];
        let mut ph = PhonePairing::from_uri(&fake_qr.to_uri()).unwrap();
        let phone = Phone::new();
        let (join, _) = ph.handle_offer(&offer, 1, &phone.keys(), "Evil").unwrap();
        assert!(pc.handle_join(&join, 2, &accept_all).is_err());
        assert_eq!(pc.state(), PcPairingState::Failed);
        // Burned: even a legitimate join now fails.
        let mut ph2 = PhonePairing::from_uri(&pc.qr.to_uri()).unwrap();
        let (join2, _) = ph2.handle_offer(&offer, 1, &phone.keys(), "P").unwrap();
        assert!(pc.handle_join(&join2, 2, &accept_all).is_err());
    }

    #[test]
    fn replayed_join_rejected() {
        let pc_key = SoftSigner::generate().unwrap();
        let (mut pc, offer) = PcPairing::start(&pc_key, "https://r.example", "Desk", 0).unwrap();
        let mut ph = PhonePairing::from_uri(&pc.qr.to_uri()).unwrap();
        let phone = Phone::new();
        let (join, _) = ph.handle_offer(&offer, 1, &phone.keys(), "P").unwrap();
        pc.handle_join(&join, 2, &accept_all).unwrap();
        assert!(pc.handle_join(&join, 3, &accept_all).is_err());
    }

    #[test]
    fn bad_confirm_mac_rejected() {
        let pc_key = SoftSigner::generate().unwrap();
        let (mut pc, offer) = PcPairing::start(&pc_key, "https://r.example", "Desk", 0).unwrap();
        let mut ph = PhonePairing::from_uri(&pc.qr.to_uri()).unwrap();
        let phone = Phone::new();
        let (join, _) = ph.handle_offer(&offer, 1, &phone.keys(), "P").unwrap();
        pc.handle_join(&join, 2, &accept_all).unwrap();
        assert!(pc.handle_confirm(&encode_confirm(CONFIRM_LABEL, &[0; 32])).is_err());
        assert_eq!(pc.state(), PcPairingState::Failed);
    }

    #[test]
    fn bad_complete_mac_rejected() {
        let pc_key = SoftSigner::generate().unwrap();
        let (pc, offer) = PcPairing::start(&pc_key, "https://r.example", "Desk", 0).unwrap();
        let mut ph = PhonePairing::from_uri(&pc.qr.to_uri()).unwrap();
        let phone = Phone::new();
        ph.handle_offer(&offer, 1, &phone.keys(), "P").unwrap();
        assert!(ph.handle_complete(&encode_confirm(COMPLETE_LABEL, &[0; 32])).is_err());
    }

    #[test]
    fn join_signed_by_wrong_approve_key_rejected() {
        struct Swapped<'a>(&'a SoftSigner, Pub);
        impl Signer for Swapped<'_> {
            fn public(&self) -> Pub {
                self.1
            }
            fn sign(&self, m: &[u8]) -> Result<[u8; 64]> {
                self.0.sign(m)
            }
        }
        let pc_key = SoftSigner::generate().unwrap();
        let (mut pc, offer) = PcPairing::start(&pc_key, "https://r.example", "Desk", 0).unwrap();
        let mut ph = PhonePairing::from_uri(&pc.qr.to_uri()).unwrap();
        let phone = Phone::new();
        let other = SoftSigner::generate().unwrap();
        // Claims `other`'s key as approve key but cannot sign with it.
        let fake = Swapped(&phone.approve, other.public());
        let keys = PhoneKeys { device: &phone.device, approve: &fake, device_chain: vec![], approve_chain: vec![] };
        let (join, _) = ph.handle_offer(&offer, 1, &keys, "P").unwrap();
        assert!(pc.handle_join(&join, 2, &accept_all).is_err());
    }

    #[test]
    fn attestation_result_propagates() {
        fn reject(_: &[Vec<u8>], _: &Pub, _: &[u8; 32], _: bool) -> AttestationResult {
            AttestationResult::Unverified("no chain".into())
        }
        let pc_key = SoftSigner::generate().unwrap();
        let (mut pc, offer) = PcPairing::start(&pc_key, "https://r.example", "Desk", 0).unwrap();
        let mut ph = PhonePairing::from_uri(&pc.qr.to_uri()).unwrap();
        let phone = Phone::new();
        let (join, _) = ph.handle_offer(&offer, 1, &phone.keys(), "P").unwrap();
        let info = pc.handle_join(&join, 2, &reject).unwrap();
        assert!(!info.attestation.is_verified());
    }
}

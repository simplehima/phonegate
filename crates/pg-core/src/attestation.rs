//! Android hardware key attestation verification (protocol §3.4).
//!
//! Proves to the PC that the phone's keys live in a TEE/StrongBox and that the approve key
//! requires user authentication on every use. The trust anchors are Google's *public*
//! attestation roots; nothing here is secret.

use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

use crate::crypto::Pub;

const KEY_DESCRIPTION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "reason", rename_all = "snake_case")]
pub enum AttestationResult {
    Verified,
    Unverified(String),
}

impl AttestationResult {
    pub fn is_verified(&self) -> bool {
        matches!(self, AttestationResult::Verified)
    }

    /// Both must be verified; the first failure reason wins.
    pub fn and(self, other: AttestationResult) -> AttestationResult {
        match (self, other) {
            (AttestationResult::Verified, AttestationResult::Verified) => AttestationResult::Verified,
            (AttestationResult::Unverified(r), _) | (_, AttestationResult::Unverified(r)) => AttestationResult::Unverified(r),
        }
    }
}

/// Google hardware attestation root certificates (public trust anchors), DER.
pub fn google_roots() -> Vec<Vec<u8>> {
    let pems = [include_str!("../roots/google-root-rsa.pem"), include_str!("../roots/google-root-ecdsa.pem")];
    pems.iter().flat_map(|p| pem_to_ders(p)).collect()
}

fn pem_to_ders(pem: &str) -> Vec<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inside = false;
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN CERTIFICATE") {
            inside = true;
            cur.clear();
        } else if line.starts_with("-----END CERTIFICATE") {
            inside = false;
            if let Ok(der) = STANDARD.decode(&cur) {
                out.push(der);
            }
        } else if inside {
            cur.push_str(line);
        }
    }
    out
}

/// Verifies an attestation chain with Google's roots.
pub fn verify_with_google_roots(chain: &[Vec<u8>], expected_pub: &Pub, challenge: &[u8; 32], require_user_auth: bool) -> AttestationResult {
    verify(chain, expected_pub, challenge, require_user_auth, &google_roots())
}

/// Verifies an attestation chain (leaf first) against the given trust anchors (DER).
pub fn verify(chain: &[Vec<u8>], expected_pub: &Pub, challenge: &[u8; 32], require_user_auth: bool, roots: &[Vec<u8>]) -> AttestationResult {
    match verify_inner(chain, expected_pub, challenge, require_user_auth, roots) {
        Ok(()) => AttestationResult::Verified,
        Err(reason) => AttestationResult::Unverified(reason),
    }
}

fn verify_inner(chain: &[Vec<u8>], expected_pub: &Pub, challenge: &[u8; 32], require_user_auth: bool, roots: &[Vec<u8>]) -> Result<(), String> {
    if chain.is_empty() {
        return Err("no attestation chain provided".into());
    }
    if chain.len() > 8 {
        return Err("attestation chain too long".into());
    }
    let certs: Vec<X509Certificate<'_>> = chain
        .iter()
        .map(|d| X509Certificate::from_der(d).map(|(_, c)| c).map_err(|_| "malformed certificate".to_string()))
        .collect::<Result<_, _>>()?;

    // 1. Signatures along the chain.
    for i in 0..certs.len() - 1 {
        certs[i]
            .verify_signature(Some(certs[i + 1].public_key()))
            .map_err(|_| format!("certificate {i} not signed by its issuer"))?;
    }
    // 1b. Intermediate certificates must be within their validity period. The leaf is exempt
    //     (KeyMint leaves often carry placeholder validity) and pinned anchors are trusted as-is.
    for (i, c) in certs.iter().enumerate().skip(1) {
        let is_anchor = roots.iter().any(|r| r == &chain[i]);
        if !is_anchor && !c.validity().is_valid() {
            return Err(format!("certificate {i} in the attestation chain is expired or not yet valid"));
        }
    }
    // 2. Chain terminates at a pinned root (either the root itself or signed by one).
    let last = certs.last().expect("non-empty");
    let last_der = chain.last().expect("non-empty");
    let anchored = roots.iter().any(|r| {
        if r == last_der {
            return true;
        }
        match X509Certificate::from_der(r) {
            Ok((_, root)) => last.verify_signature(Some(root.public_key())).is_ok(),
            Err(_) => false,
        }
    });
    if !anchored {
        return Err("chain does not lead to a trusted attestation root".into());
    }
    // 3. Leaf key is the declared key.
    let leaf = &certs[0];
    if leaf.public_key().subject_public_key.data.as_ref() != expected_pub.as_slice() {
        return Err("attested key does not match the declared key".into());
    }
    // 4. Key description extension.
    let ext = leaf
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == KEY_DESCRIPTION_OID)
        .ok_or_else(|| "no key attestation extension".to_string())?;
    let kd = KeyDescription::parse(ext.value).map_err(|e| format!("bad key description: {e}"))?;

    if kd.attestation_challenge != challenge {
        return Err("attestation challenge does not match this pairing".into());
    }
    if !matches!(kd.attestation_security_level, 1 | 2) || !matches!(kd.keymint_security_level, 1 | 2) {
        return Err("key is not hardware-backed (software attestation)".into());
    }
    let hw = &kd.hardware_enforced;
    if let Some(alg) = hw.algorithm {
        if alg != 3 {
            return Err("attested key is not an EC key".into());
        }
    }
    if !hw.purposes.contains(&2) {
        return Err("attested key cannot sign".into());
    }
    match &hw.root_of_trust {
        Some(rot) if rot.device_locked && matches!(rot.verified_boot_state, 0 | 1) => {}
        Some(_) => return Err("phone bootloader is unlocked or boot is unverified".into()),
        None => return Err("missing root of trust".into()),
    }
    if require_user_auth {
        if hw.no_auth_required {
            return Err("approve key does not require user authentication".into());
        }
        match hw.user_auth_type {
            Some(t) if t & 2 != 0 => {}
            _ => return Err("approve key is not bound to biometric authentication".into()),
        }
        if hw.auth_timeout.unwrap_or(0) != 0 {
            return Err("approve key allows reuse without per-use authentication".into());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Minimal strict DER reader for the KeyDescription structure.
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tag {
    class: u8,
    constructed: bool,
    number: u32,
}

struct Der<'a> {
    data: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Der { data }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn read(&mut self) -> Result<(Tag, &'a [u8]), &'static str> {
        let d = self.data;
        if d.is_empty() {
            return Err("unexpected end");
        }
        let b0 = d[0];
        let mut i = 1;
        let mut number = (b0 & 0x1f) as u32;
        if number == 0x1f {
            number = 0;
            loop {
                let b = *d.get(i).ok_or("truncated tag")?;
                i += 1;
                number = number.checked_mul(128).ok_or("tag overflow")? | (b & 0x7f) as u32;
                if b & 0x80 == 0 {
                    break;
                }
                if i > 6 {
                    return Err("tag too long");
                }
            }
        }
        let lb = *d.get(i).ok_or("truncated length")?;
        i += 1;
        let len = if lb & 0x80 == 0 {
            lb as usize
        } else {
            let n = (lb & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err("unsupported length");
            }
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | *d.get(i).ok_or("truncated length")? as usize;
                i += 1;
            }
            l
        };
        let end = i.checked_add(len).ok_or("length overflow")?;
        if end > d.len() {
            return Err("truncated value");
        }
        self.data = &d[end..];
        Ok((Tag { class: b0 >> 6, constructed: b0 & 0x20 != 0, number }, &d[i..end]))
    }

    fn expect(&mut self, number: u32) -> Result<&'a [u8], &'static str> {
        let (t, v) = self.read()?;
        if t.class != 0 || t.number != number {
            return Err("unexpected tag");
        }
        Ok(v)
    }
}

fn der_int(v: &[u8]) -> Result<i64, &'static str> {
    if v.is_empty() || v.len() > 8 {
        return Err("integer size");
    }
    let mut x: i64 = if v[0] & 0x80 != 0 { -1 } else { 0 };
    for b in v {
        x = (x << 8) | *b as i64;
    }
    Ok(x)
}

#[derive(Debug, Default)]
struct RootOfTrust {
    device_locked: bool,
    verified_boot_state: i64,
}

#[derive(Debug, Default)]
struct AuthorizationList {
    purposes: Vec<i64>,
    algorithm: Option<i64>,
    no_auth_required: bool,
    user_auth_type: Option<i64>,
    auth_timeout: Option<i64>,
    root_of_trust: Option<RootOfTrust>,
}

impl AuthorizationList {
    fn parse(v: &[u8]) -> Result<Self, &'static str> {
        let mut out = AuthorizationList::default();
        let mut d = Der::new(v);
        while !d.is_empty() {
            let (t, inner) = d.read()?;
            if t.class != 2 || !t.constructed {
                return Err("authorization list entry is not an explicit context tag");
            }
            let mut e = Der::new(inner);
            match t.number {
                1 => {
                    let set = e.expect(17)?;
                    let mut s = Der::new(set);
                    while !s.is_empty() {
                        out.purposes.push(der_int(s.expect(2)?)?);
                    }
                }
                2 => out.algorithm = Some(der_int(e.expect(2)?)?),
                503 => {
                    e.expect(5)?;
                    out.no_auth_required = true;
                }
                504 => out.user_auth_type = Some(der_int(e.expect(2)?)?),
                505 => out.auth_timeout = Some(der_int(e.expect(2)?)?),
                704 => {
                    let seq = e.expect(16)?;
                    let mut r = Der::new(seq);
                    r.expect(4)?; // verifiedBootKey
                    let locked = r.expect(1)?;
                    let state = r.expect(10)?;
                    out.root_of_trust = Some(RootOfTrust {
                        device_locked: locked.first().copied().unwrap_or(0) != 0,
                        verified_boot_state: der_int(state)?,
                    });
                }
                _ => {} // other tags are not needed for the decision
            }
        }
        Ok(out)
    }
}

#[derive(Debug)]
struct KeyDescription {
    attestation_security_level: i64,
    keymint_security_level: i64,
    attestation_challenge: Vec<u8>,
    hardware_enforced: AuthorizationList,
}

impl KeyDescription {
    fn parse(v: &[u8]) -> Result<Self, &'static str> {
        let mut outer = Der::new(v);
        let seq = outer.expect(16)?;
        if !outer.is_empty() {
            return Err("trailing data");
        }
        let mut d = Der::new(seq);
        der_int(d.expect(2)?)?; // attestationVersion
        let asl = der_int(d.expect(10)?)?;
        der_int(d.expect(2)?)?; // keyMintVersion
        let ksl = der_int(d.expect(10)?)?;
        let challenge = d.expect(4)?.to_vec();
        d.expect(4)?; // uniqueId
        AuthorizationList::parse(d.expect(16)?)?; // softwareEnforced: parsed for well-formedness only
        let hw = AuthorizationList::parse(d.expect(16)?)?;
        Ok(KeyDescription { attestation_security_level: asl, keymint_security_level: ksl, attestation_challenge: challenge, hardware_enforced: hw })
    }
}

/// DER writer used by tests (and by the simulator) to build KeyDescription extensions.
pub mod der_writer {
    fn len(n: usize) -> Vec<u8> {
        if n < 128 {
            vec![n as u8]
        } else {
            let b = (n as u32).to_be_bytes();
            let skip = b.iter().take_while(|x| **x == 0).count();
            let mut out = vec![0x80 | (4 - skip) as u8];
            out.extend_from_slice(&b[skip..]);
            out
        }
    }

    pub fn tlv(tag: &[u8], v: &[u8]) -> Vec<u8> {
        let mut out = tag.to_vec();
        out.extend(len(v.len()));
        out.extend_from_slice(v);
        out
    }

    pub fn int(x: i64) -> Vec<u8> {
        let b = x.to_be_bytes();
        let mut i = 0;
        while i < 7 && ((b[i] == 0 && b[i + 1] & 0x80 == 0) || (b[i] == 0xff && b[i + 1] & 0x80 != 0)) {
            i += 1;
        }
        tlv(&[0x02], &b[i..])
    }

    pub fn enumerated(x: i64) -> Vec<u8> {
        let mut v = int(x);
        v[0] = 0x0a;
        v
    }

    pub fn octets(b: &[u8]) -> Vec<u8> {
        tlv(&[0x04], b)
    }

    pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(&[0x30], &parts.concat())
    }

    pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(&[0x31], &parts.concat())
    }

    /// Explicit context-specific constructed tag `[n]`.
    pub fn explicit(n: u32, inner: &[u8]) -> Vec<u8> {
        let tag = if n < 31 {
            vec![0xa0 | n as u8]
        } else {
            let mut t = vec![0xbf];
            let mut groups = Vec::new();
            let mut x = n;
            groups.push((x & 0x7f) as u8);
            x >>= 7;
            while x > 0 {
                groups.push(0x80 | (x & 0x7f) as u8);
                x >>= 7;
            }
            groups.reverse();
            t.extend(groups);
            t
        };
        tlv(&tag, inner)
    }

    pub struct KdSpec<'a> {
        pub challenge: &'a [u8],
        pub security_level: i64,
        pub user_auth: bool,
        pub auth_timeout: Option<i64>,
        pub device_locked: bool,
        pub boot_state: i64,
    }

    pub fn key_description(s: &KdSpec<'_>) -> Vec<u8> {
        let mut hw = vec![explicit(1, &set(&[int(2)])), explicit(2, &int(3))];
        if s.user_auth {
            hw.push(explicit(504, &int(3)));
            if let Some(t) = s.auth_timeout {
                hw.push(explicit(505, &int(t)));
            }
        } else {
            hw.push(explicit(503, &[0x05, 0x00]));
        }
        hw.push(explicit(
            704,
            &seq(&[octets(&[0u8; 32]), tlv(&[0x01], &[if s.device_locked { 0xff } else { 0 }]), enumerated(s.boot_state)]),
        ));
        seq(&[
            int(200),
            enumerated(s.security_level),
            int(200),
            enumerated(s.security_level),
            octets(s.challenge),
            octets(&[]),
            seq(&[]),
            seq(&hw),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::der_writer::*;
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair};

    struct Chain {
        chain: Vec<Vec<u8>>,
        root: Vec<u8>,
        leaf_pub: Pub,
    }

    fn build(kd: Vec<u8>) -> Chain {
        build_with(kd, false)
    }

    fn build_with(kd: Vec<u8>, expired_intermediate: bool) -> Chain {
        let root_key = KeyPair::generate().unwrap();
        let mut rp = CertificateParams::new(vec![]).unwrap();
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = rp.self_signed(&root_key).unwrap();

        let int_key = KeyPair::generate().unwrap();
        let mut ip = CertificateParams::new(vec![]).unwrap();
        ip.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        if expired_intermediate {
            ip.not_before = rcgen::date_time_ymd(2000, 1, 1);
            ip.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        let inter = ip.signed_by(&int_key, &root, &root_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut lp = CertificateParams::new(vec![]).unwrap();
        lp.custom_extensions.push(CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17], kd));
        let leaf = lp.signed_by(&leaf_key, &inter, &int_key).unwrap();
        let leaf_pub: Pub = leaf_key.public_key_raw().try_into().unwrap();
        Chain {
            chain: vec![leaf.der().to_vec(), inter.der().to_vec(), root.der().to_vec()],
            root: root.der().to_vec(),
            leaf_pub,
        }
    }

    fn good_spec(ch: &[u8]) -> KdSpec<'_> {
        KdSpec { challenge: ch, security_level: 1, user_auth: true, auth_timeout: None, device_locked: true, boot_state: 0 }
    }

    const CH: [u8; 32] = [9; 32];

    #[test]
    fn valid_chain_verifies() {
        let c = build(key_description(&good_spec(&CH)));
        assert_eq!(verify(&c.chain, &c.leaf_pub, &CH, true, std::slice::from_ref(&c.root)), AttestationResult::Verified);
        // Also anchored when the root is omitted from the chain.
        let short = &c.chain[..2];
        assert!(verify(short, &c.leaf_pub, &CH, true, &[c.root]).is_verified());
    }

    #[test]
    fn untrusted_root_rejected() {
        let c = build(key_description(&good_spec(&CH)));
        let other = build(key_description(&good_spec(&CH)));
        assert!(!verify(&c.chain, &c.leaf_pub, &CH, true, &[other.root]).is_verified());
        assert!(!verify(&c.chain, &c.leaf_pub, &CH, true, &google_roots()).is_verified());
    }

    #[test]
    fn wrong_challenge_rejected() {
        let c = build(key_description(&good_spec(&CH)));
        assert!(!verify(&c.chain, &c.leaf_pub, &[8; 32], true, &[c.root]).is_verified());
    }

    #[test]
    fn software_level_rejected() {
        let mut s = good_spec(&CH);
        s.security_level = 0;
        let c = build(key_description(&s));
        assert!(!verify(&c.chain, &c.leaf_pub, &CH, true, &[c.root]).is_verified());
    }

    #[test]
    fn auth_rules_enforced_for_approve_key() {
        let mut s = good_spec(&CH);
        s.auth_timeout = Some(30);
        let c = build(key_description(&s));
        assert!(!verify(&c.chain, &c.leaf_pub, &CH, true, std::slice::from_ref(&c.root)).is_verified());

        let mut s = good_spec(&CH);
        s.user_auth = false;
        let c = build(key_description(&s));
        assert!(!verify(&c.chain, &c.leaf_pub, &CH, true, std::slice::from_ref(&c.root)).is_verified(), "approve key needs auth");
        assert!(verify(&c.chain, &c.leaf_pub, &CH, false, &[c.root]).is_verified(), "device key needs no auth");
    }

    #[test]
    fn unlocked_bootloader_rejected() {
        let mut s = good_spec(&CH);
        s.device_locked = false;
        let c = build(key_description(&s));
        assert!(!verify(&c.chain, &c.leaf_pub, &CH, true, std::slice::from_ref(&c.root)).is_verified());
        let mut s = good_spec(&CH);
        s.boot_state = 2;
        let c = build(key_description(&s));
        assert!(!verify(&c.chain, &c.leaf_pub, &CH, true, &[c.root]).is_verified());
    }

    #[test]
    fn wrong_key_and_broken_chain_rejected() {
        let c = build(key_description(&good_spec(&CH)));
        let mut other_pub = c.leaf_pub;
        other_pub[10] ^= 1;
        assert!(!verify(&c.chain, &other_pub, &CH, true, std::slice::from_ref(&c.root)).is_verified());
        let mut broken = c.chain.clone();
        broken.remove(1);
        assert!(!verify(&broken, &c.leaf_pub, &CH, true, &[c.root]).is_verified());
        assert!(!verify(&[], &c.leaf_pub, &CH, true, &google_roots()).is_verified());
    }

    #[test]
    fn expired_intermediate_rejected() {
        let c = build_with(key_description(&good_spec(&CH)), true);
        let r = verify(&c.chain, &c.leaf_pub, &CH, true, std::slice::from_ref(&c.root));
        assert!(matches!(r, AttestationResult::Unverified(ref m) if m.contains("expired")), "{r:?}");
    }

    #[test]
    fn google_roots_load() {
        let roots = google_roots();
        assert!(roots.len() >= 2, "expected both Google roots, got {}", roots.len());
        for r in roots {
            assert!(X509Certificate::from_der(&r).is_ok());
        }
    }

    #[test]
    fn der_tag_roundtrip_high_numbers() {
        for n in [1u32, 30, 31, 503, 704, 1000] {
            let e = explicit(n, &int(5));
            let (t, _) = Der::new(&e).read().unwrap();
            assert_eq!(t.number, n);
            assert_eq!(t.class, 2);
        }
    }
}

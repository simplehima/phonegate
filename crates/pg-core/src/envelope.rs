//! Sealed envelope for post-pairing traffic (protocol §4). Signature is verified *before*
//! decryption; any failure is an error.

use crate::crypto::{self, Id, Pub, Sig};
use crate::encoding::{decode, Enc};
use crate::error::{Error, Result};
use crate::messages::Kind;
use crate::signer::Signer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    PcToPhone,
    PhoneToPc,
}

impl Dir {
    fn as_str(self) -> &'static str {
        match self {
            Dir::PcToPhone => "pc->phone",
            Dir::PhoneToPc => "phone->pc",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kind: Kind,
    pub msg_id: [u8; 16],
    pub from: Id,
    pub to: Id,
    pub nonce: [u8; 12],
    pub ct: Vec<u8>,
    pub sig: Sig,
}

fn aad(kind: Kind, msg_id: &[u8; 16], from: &Id, to: &Id) -> Vec<u8> {
    Enc::new("phonegate/v1/envelope").str(kind.as_str()).bytes(msg_id).bytes(from).bytes(to).finish()
}

fn sig_bytes(aad: &[u8], nonce: &[u8; 12], ct: &[u8]) -> Vec<u8> {
    Enc::new("phonegate/v1/envelope-sig").bytes(aad).bytes(nonce).bytes(ct).finish()
}

fn msg_key(k_pair: &[u8; 32], msg_id: &[u8; 16], dir: Dir) -> zeroize::Zeroizing<[u8; 32]> {
    crypto::hkdf(k_pair, msg_id, &Enc::new("phonegate/v1/msg").str(dir.as_str()).finish())
}

pub struct SealParams<'a> {
    pub k_pair: &'a [u8; 32],
    pub dir: Dir,
    pub kind: Kind,
    pub from: Id,
    pub to: Id,
    pub signer: &'a dyn Signer,
}

/// Seals with fresh random `msg_id` and nonce.
pub fn seal(p: &SealParams<'_>, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 16])> {
    let msg_id = crypto::random::<16>()?;
    let nonce = crypto::random::<12>()?;
    Ok((seal_with(p, plaintext, msg_id, nonce)?, msg_id))
}

/// Deterministic sealing for test vectors.
pub fn seal_with(p: &SealParams<'_>, plaintext: &[u8], msg_id: [u8; 16], nonce: [u8; 12]) -> Result<Vec<u8>> {
    if !p.kind.is_sealed() {
        return Err(Error::State("kind is not a sealed kind"));
    }
    let aad = aad(p.kind, &msg_id, &p.from, &p.to);
    let key = msg_key(p.k_pair, &msg_id, p.dir);
    let ct = crypto::aead_seal(&key, &nonce, plaintext, &aad)?;
    let sig = p.signer.sign(&sig_bytes(&aad, &nonce, &ct))?;
    Ok(Envelope { kind: p.kind, msg_id, from: p.from, to: p.to, nonce, ct, sig }.encode())
}

impl Envelope {
    pub fn encode(&self) -> Vec<u8> {
        Enc::new("phonegate/v1/envelope-wire")
            .str(self.kind.as_str())
            .bytes(&self.msg_id)
            .bytes(&self.from)
            .bytes(&self.to)
            .bytes(&self.nonce)
            .bytes(&self.ct)
            .bytes(&self.sig)
            .finish()
    }

    pub fn parse(payload: &[u8]) -> Result<Self> {
        let f = decode(payload, "phonegate/v1/envelope-wire", 8)?;
        let kind = Kind::parse(&f.string(1)?)?;
        if !kind.is_sealed() {
            return Err(Error::Decode("kind is not a sealed kind"));
        }
        Ok(Envelope {
            kind,
            msg_id: f.fixed(2)?,
            from: f.fixed(3)?,
            to: f.fixed(4)?,
            nonce: f.fixed(5)?,
            ct: f.bytes(6).to_vec(),
            sig: f.fixed(7)?,
        })
    }

    /// Verifies routing ids and the sender signature, then decrypts.
    pub fn open(&self, sender_pub: &Pub, k_pair: &[u8; 32], dir: Dir, expect_from: &Id, expect_to: &Id) -> Result<Vec<u8>> {
        if !crypto::ct_eq(&self.from, expect_from) || !crypto::ct_eq(&self.to, expect_to) {
            return Err(Error::Verify("envelope routing ids do not match pairing"));
        }
        let aad = aad(self.kind, &self.msg_id, &self.from, &self.to);
        crypto::verify(sender_pub, &sig_bytes(&aad, &self.nonce, &self.ct), &self.sig)?;
        let key = msg_key(k_pair, &self.msg_id, dir);
        crypto::aead_open(&key, &self.nonce, &self.ct, &aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::SoftSigner;

    struct Fx {
        pc: SoftSigner,
        phone: SoftSigner,
        k: [u8; 32],
    }

    fn fx() -> Fx {
        Fx { pc: SoftSigner::generate().unwrap(), phone: SoftSigner::generate().unwrap(), k: [7; 32] }
    }

    fn ids(f: &Fx) -> (Id, Id) {
        (crypto::id_of(&f.pc.public()), crypto::id_of(&f.phone.public()))
    }

    fn sealed(f: &Fx) -> Vec<u8> {
        let (pc, ph) = ids(f);
        let p = SealParams { k_pair: &f.k, dir: Dir::PcToPhone, kind: Kind::Cancel, from: pc, to: ph, signer: &f.pc };
        seal(&p, b"hello").unwrap().0
    }

    #[test]
    fn roundtrip() {
        let f = fx();
        let (pc, ph) = ids(&f);
        let e = Envelope::parse(&sealed(&f)).unwrap();
        assert_eq!(e.open(&f.pc.public(), &f.k, Dir::PcToPhone, &pc, &ph).unwrap(), b"hello");
    }

    #[test]
    fn rejects_wrong_signer_direction_key_and_ids() {
        let f = fx();
        let (pc, ph) = ids(&f);
        let e = Envelope::parse(&sealed(&f)).unwrap();
        assert!(e.open(&f.phone.public(), &f.k, Dir::PcToPhone, &pc, &ph).is_err(), "wrong sender key");
        assert!(e.open(&f.pc.public(), &f.k, Dir::PhoneToPc, &pc, &ph).is_err(), "wrong direction");
        assert!(e.open(&f.pc.public(), &[8; 32], Dir::PcToPhone, &pc, &ph).is_err(), "wrong k_pair");
        assert!(e.open(&f.pc.public(), &f.k, Dir::PcToPhone, &ph, &pc).is_err(), "swapped ids");
    }

    #[test]
    fn rejects_tampering() {
        let f = fx();
        let (pc, ph) = ids(&f);
        let base = Envelope::parse(&sealed(&f)).unwrap();
        let mut t = base.clone();
        t.ct[0] ^= 1;
        assert!(t.open(&f.pc.public(), &f.k, Dir::PcToPhone, &pc, &ph).is_err());
        let mut t = base.clone();
        t.nonce[0] ^= 1;
        assert!(t.open(&f.pc.public(), &f.k, Dir::PcToPhone, &pc, &ph).is_err());
        let mut t = base.clone();
        t.msg_id[0] ^= 1;
        assert!(t.open(&f.pc.public(), &f.k, Dir::PcToPhone, &pc, &ph).is_err());
        let mut t = base.clone();
        t.kind = Kind::Notice;
        assert!(t.open(&f.pc.public(), &f.k, Dir::PcToPhone, &pc, &ph).is_err());
        let mut t = base;
        t.sig[5] ^= 1;
        assert!(t.open(&f.pc.public(), &f.k, Dir::PcToPhone, &pc, &ph).is_err());
    }

    #[test]
    fn refuses_unsealed_kinds() {
        let f = fx();
        let (pc, ph) = ids(&f);
        let p = SealParams { k_pair: &f.k, dir: Dir::PcToPhone, kind: Kind::PairOffer, from: pc, to: ph, signer: &f.pc };
        assert!(seal(&p, b"x").is_err());
    }
}

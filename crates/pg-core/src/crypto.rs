//! Cryptographic suite (protocol §1). Only well-reviewed RustCrypto primitives are used.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub type Pub = [u8; 65];
pub type Sig = [u8; 64];
pub type Id = [u8; 32];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// Constant-time MAC comparison.
pub fn hmac_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> Result<()> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(msg);
    m.verify_slice(tag).map_err(|_| Error::Verify("mac mismatch"))
}

/// Constant-time equality for secrets of equal public length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    // Prevent the compiler from short-circuiting the fold.
    std::hint::black_box(diff) == 0
}

pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, out.as_mut()).expect("32 bytes is a valid HKDF output length");
    out
}

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|_| Error::Crypto("system rng unavailable"))?;
    Ok(b)
}

/// Uniform integer in `[lo, hi]` by rejection sampling.
pub fn random_range(lo: u64, hi: u64) -> Result<u64> {
    assert!(lo <= hi);
    let span = hi - lo + 1;
    let zone = u64::MAX - (u64::MAX % span);
    loop {
        let v = u64::from_be_bytes(random::<8>()?);
        if v < zone {
            return Ok(lo + v % span);
        }
    }
}

pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto("bad aead key"))?;
    cipher
        .encrypt(&Nonce::from(*nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto("aead seal failed"))
}

pub fn aead_open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto("bad aead key"))?;
    cipher
        .decrypt(&Nonce::from(*nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| Error::Verify("aead authentication failed"))
}

/// Parses and validates an uncompressed SEC1 P-256 point (65 bytes, `0x04` prefix, on curve).
pub fn parse_pub(bytes: &[u8]) -> Result<VerifyingKey> {
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(Error::Decode("public key must be 65-byte uncompressed SEC1"));
    }
    VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::Decode("public key not on curve"))
}

pub fn pub_bytes(vk: &VerifyingKey) -> Pub {
    let ep = vk.to_encoded_point(false);
    ep.as_bytes().try_into().expect("uncompressed point is 65 bytes")
}

pub fn id_of(public: &[u8]) -> Id {
    sha256(public)
}

/// Verifies an ECDSA P-256/SHA-256 signature in raw `r‖s` form. Rejects `r` or `s` outside
/// `[1, n-1]`; accepts both low-S and high-S.
pub fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    let vk = parse_pub(public)?;
    let sig = Signature::from_slice(sig).map_err(|_| Error::Verify("malformed signature"))?;
    vk.verify(msg, &sig).map_err(|_| Error::Verify("bad signature"))
}

/// An ephemeral P-256 key pair for ECDH.
pub struct EphemeralKey {
    secret: SecretKey,
    public: Pub,
}

impl EphemeralKey {
    pub fn generate() -> Result<Self> {
        loop {
            let bytes = Zeroizing::new(random::<32>()?);
            if let Ok(k) = Self::from_bytes(&bytes) {
                return Ok(k);
            }
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let secret = SecretKey::from_slice(bytes).map_err(|_| Error::Crypto("invalid scalar"))?;
        let public = secret.public_key().to_encoded_point(false).as_bytes().try_into().expect("65 bytes");
        Ok(EphemeralKey { secret, public })
    }

    pub fn public(&self) -> Pub {
        self.public
    }

    /// Returns the 32-byte x-coordinate shared secret.
    pub fn agree(&self, peer: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        parse_pub(peer)?;
        let peer = PublicKey::from_sec1_bytes(peer).map_err(|_| Error::Decode("bad peer key"))?;
        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&shared.raw_secret_bytes()[..]);
        Ok(out)
    }
}

pub mod b64 {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    use crate::error::{Error, Result};

    pub fn encode(b: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(b)
    }

    pub fn decode(s: &str) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD.decode(s).map_err(|_| Error::Decode("invalid base64url"))
    }

    pub fn decode_fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
        decode(s)?.try_into().map_err(|_| Error::Decode("base64 field has wrong length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{Signer, SoftSigner};

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = h("000102030405060708090a0b0c");
        let info = h("f0f1f2f3f4f5f6f7f8f9");
        let okm = hkdf(&ikm, &salt, &info);
        assert_eq!(
            okm.as_slice(),
            &h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")[..]
        );
    }

    #[test]
    fn hmac_rfc4231_case2() {
        let tag = hmac(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(tag.to_vec(), h("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
        assert!(hmac_verify(b"Jefe", b"what do ya want for nothing?", &tag).is_ok());
        assert!(hmac_verify(b"Jefe", b"what do ya want for nothing!", &tag).is_err());
    }

    #[test]
    fn gcm_nist_vector() {
        // NIST GCM test case 16 (AES-256, 60-byte PT with AAD).
        let key: [u8; 32] = h("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308").try_into().unwrap();
        let nonce: [u8; 12] = h("cafebabefacedbaddecaf888").try_into().unwrap();
        let pt = h("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        let aad = h("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let ct = aead_seal(&key, &nonce, &pt, &aad).unwrap();
        assert_eq!(
            ct,
            h("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b")
        );
        assert_eq!(aead_open(&key, &nonce, &ct, &aad).unwrap(), pt);
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(aead_open(&key, &nonce, &bad, &aad).is_err());
        assert!(aead_open(&key, &nonce, &ct, b"other").is_err());
    }

    #[test]
    fn signature_roundtrip_and_rejections() {
        let s = SoftSigner::generate().unwrap();
        let sig = s.sign(b"msg").unwrap();
        assert!(verify(&s.public(), b"msg", &sig).is_ok());
        assert!(verify(&s.public(), b"msh", &sig).is_err());
        let other = SoftSigner::generate().unwrap();
        assert!(verify(&other.public(), b"msg", &sig).is_err());
        // r = 0 and s = 0 are rejected.
        let mut zero_r = sig;
        zero_r[..32].fill(0);
        assert!(verify(&s.public(), b"msg", &zero_r).is_err());
        assert!(verify(&s.public(), b"msg", &[0u8; 64]).is_err());
        assert!(verify(&s.public(), b"msg", &sig[..63]).is_err());
    }

    #[test]
    fn high_s_signature_is_accepted() {
        // Android Keystore does not normalize S; we must accept high-S (protocol §1).
        use p256::elliptic_curve::PrimeField;
        let s = SoftSigner::generate().unwrap();
        let sig = s.sign(b"msg").unwrap();
        let sig_obj = Signature::from_slice(&sig).unwrap();
        let (r, s_scalar) = sig_obj.split_scalars();
        let neg_s = -(*s_scalar);
        let mut high = [0u8; 64];
        high[..32].copy_from_slice(&r.to_repr());
        high[32..].copy_from_slice(&neg_s.to_repr());
        assert_ne!(high, sig);
        assert!(verify(&s.public(), b"msg", &high).is_ok());
    }

    #[test]
    fn pub_validation() {
        let s = SoftSigner::generate().unwrap();
        let mut p = s.public();
        assert!(parse_pub(&p).is_ok());
        p[0] = 0x02;
        assert!(parse_pub(&p).is_err());
        let mut off = s.public();
        off[64] ^= 1; // almost certainly not on the curve
        assert!(parse_pub(&off).is_err());
        assert!(parse_pub(&s.public()[..64]).is_err());
    }

    #[test]
    fn ecdh_agrees() {
        let a = EphemeralKey::generate().unwrap();
        let b = EphemeralKey::generate().unwrap();
        assert_eq!(*a.agree(&b.public()).unwrap(), *b.agree(&a.public()).unwrap());
    }

    #[test]
    fn random_range_bounds() {
        for _ in 0..1000 {
            let v = random_range(10, 99).unwrap();
            assert!((10..=99).contains(&v));
        }
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}

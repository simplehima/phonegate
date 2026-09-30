//! Signing abstraction. Production PC keys live in the TPM and production phone keys in Android
//! Keystore; [`SoftSigner`] exists for tests, the simulator, and the no-TPM fallback.

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use zeroize::Zeroizing;

use crate::crypto::{self, Pub, Sig};
use crate::error::{Error, Result};

pub trait Signer: Send + Sync {
    /// Uncompressed SEC1 public key.
    fn public(&self) -> Pub;
    /// ECDSA P-256 / SHA-256 over `msg`, raw `r‖s`.
    fn sign(&self, msg: &[u8]) -> Result<Sig>;
}

pub struct SoftSigner {
    key: SigningKey,
}

impl SoftSigner {
    pub fn generate() -> Result<Self> {
        loop {
            let bytes = Zeroizing::new(crypto::random::<32>()?);
            if let Ok(s) = Self::from_bytes(&bytes) {
                return Ok(s);
            }
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let key = SigningKey::from_slice(bytes).map_err(|_| Error::Crypto("invalid signing scalar"))?;
        Ok(SoftSigner { key })
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_bytes().into())
    }
}

impl Signer for SoftSigner {
    fn public(&self) -> Pub {
        crypto::pub_bytes(self.key.verifying_key())
    }

    fn sign(&self, msg: &[u8]) -> Result<Sig> {
        let sig: Signature = self.key.sign(msg);
        Ok(sig.to_bytes().into())
    }
}

impl<T: Signer + ?Sized> Signer for std::sync::Arc<T> {
    fn public(&self) -> Pub {
        (**self).public()
    }
    fn sign(&self, msg: &[u8]) -> Result<Sig> {
        (**self).sign(msg)
    }
}

impl<T: Signer + ?Sized> Signer for Box<T> {
    fn public(&self) -> Pub {
        (**self).public()
    }
    fn sign(&self, msg: &[u8]) -> Result<Sig> {
        (**self).sign(msg)
    }
}

//! PC key backends. Production: TPM via the Microsoft Platform Crypto Provider (see
//! `win::tpm`). Fallback: DPAPI machine scope (`win::dpapi`). Tests: [`MemoryBackend`].

use pg_core::crypto::{self, Pub, Sig};
use pg_core::signer::{Signer, SoftSigner};
use pg_core::{Error, Result};
use zeroize::Zeroizing;

/// A PC identity key plus a way to wrap local secrets so they are useless off this machine.
pub trait KeyBackend: Signer {
    /// `"tpm"`, `"software"` (DPAPI) or `"memory"` (tests only).
    fn kind(&self) -> &'static str;
    fn wrap(&self, secret: &[u8]) -> Result<Vec<u8>>;
    fn unwrap(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

/// In-memory backend for tests and the simulator. Never used by the service binary.
pub struct MemoryBackend {
    signer: SoftSigner,
    wrap_key: [u8; 32],
}

impl MemoryBackend {
    pub fn generate() -> Result<Self> {
        Ok(MemoryBackend { signer: SoftSigner::generate()?, wrap_key: crypto::random()? })
    }
}

impl Signer for MemoryBackend {
    fn public(&self) -> Pub {
        self.signer.public()
    }
    fn sign(&self, msg: &[u8]) -> Result<Sig> {
        self.signer.sign(msg)
    }
}

impl KeyBackend for MemoryBackend {
    fn kind(&self) -> &'static str {
        "memory"
    }

    fn wrap(&self, secret: &[u8]) -> Result<Vec<u8>> {
        let nonce: [u8; 12] = crypto::random()?;
        let mut out = nonce.to_vec();
        out.extend(crypto::aead_seal(&self.wrap_key, &nonce, secret, b"phonegate/v1/memory-wrap")?);
        Ok(out)
    }

    fn unwrap(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if blob.len() < 12 {
            return Err(Error::Decode("wrapped blob too short"));
        }
        let nonce: [u8; 12] = blob[..12].try_into().expect("12 bytes");
        Ok(Zeroizing::new(crypto::aead_open(&self.wrap_key, &nonce, &blob[12..], b"phonegate/v1/memory-wrap")?))
    }
}

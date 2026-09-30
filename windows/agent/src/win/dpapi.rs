//! Software fallback for PCs without a TPM: the identity key is a software P-256 key protected by
//! DPAPI in machine scope. Weaker than TPM (an administrator can decrypt it); the companion app
//! surfaces this and requires explicit acknowledgement before pairing.

use std::path::Path;

use pg_core::crypto::{Pub, Sig};
use pg_core::signer::{Signer, SoftSigner};
use pg_core::{Error, Result};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB};
use zeroize::Zeroizing;

use crate::keys::KeyBackend;

pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input points to `data` for the duration of the call; output freed with LocalFree.
    unsafe {
        CryptProtectData(&input, None, None, None, None, CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            .map_err(|_| Error::Crypto("DPAPI protect failed"))?;
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(out.pbData as _));
        Ok(v)
    }
}

pub fn unprotect(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let input = CRYPT_INTEGER_BLOB { cbData: blob.len() as u32, pbData: blob.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as above; plaintext copied into a zeroizing buffer, then the OS buffer is wiped.
    unsafe {
        CryptUnprotectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out).map_err(|_| Error::Crypto("DPAPI unprotect failed"))?;
        let s = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
        let v = Zeroizing::new(s.to_vec());
        s.fill(0);
        let _ = LocalFree(HLOCAL(out.pbData as _));
        Ok(v)
    }
}

pub struct DpapiBackend {
    signer: SoftSigner,
}

impl DpapiBackend {
    /// Loads the key from `path` or creates it.
    pub fn open(path: &Path) -> Result<Self> {
        if let Ok(blob) = std::fs::read(path) {
            let raw = unprotect(&blob)?;
            let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| Error::Decode("bad software key"))?;
            return Ok(DpapiBackend { signer: SoftSigner::from_bytes(&arr)? });
        }
        let signer = SoftSigner::generate()?;
        std::fs::write(path, protect(signer.to_bytes().as_slice())?)?;
        Ok(DpapiBackend { signer })
    }
}

impl Signer for DpapiBackend {
    fn public(&self) -> Pub {
        self.signer.public()
    }
    fn sign(&self, msg: &[u8]) -> Result<Sig> {
        self.signer.sign(msg)
    }
}

impl KeyBackend for DpapiBackend {
    fn kind(&self) -> &'static str {
        "software"
    }
    fn wrap(&self, secret: &[u8]) -> Result<Vec<u8>> {
        protect(secret)
    }
    fn unwrap(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        unprotect(blob)
    }
}

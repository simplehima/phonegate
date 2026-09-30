//! TPM-backed PC identity via the Microsoft Platform Crypto Provider (CNG / NCrypt).
//!
//! - `PhoneGate-Identity-v1`: ECDSA P-256 signing key, non-exportable, machine scope.
//! - `PhoneGate-Wrap-v1`: RSA-2048 key used with OAEP to wrap local secrets (the pairing key), so
//!   a copied `state.json` is useless without this machine's TPM.

use std::sync::Mutex;

use pg_core::crypto::{self, Pub, Sig};
use pg_core::signer::Signer;
use pg_core::{Error, Result};
use windows::core::{w, PCWSTR};
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash, BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM,
    BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM, CERT_KEY_SPEC, MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE,
    NCRYPT_SILENT_FLAG,
};
use zeroize::Zeroizing;

use crate::keys::KeyBackend;

fn werr(ctx: &'static str) -> impl Fn(windows::core::Error) -> Error {
    move |e| Error::Crypto(Box::leak(format!("{ctx}: {e}").into_boxed_str()))
}

struct Handles {
    prov: NCRYPT_PROV_HANDLE,
    sign: NCRYPT_KEY_HANDLE,
    wrap: NCRYPT_KEY_HANDLE,
}

// SAFETY: NCrypt handles may be used from any thread; all uses are serialized by the Mutex.
unsafe impl Send for Handles {}

impl Drop for Handles {
    fn drop(&mut self) {
        // SAFETY: handles were obtained from NCrypt and are freed exactly once.
        unsafe {
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.sign.0));
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.wrap.0));
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.prov.0));
        }
    }
}

pub struct TpmBackend {
    h: Mutex<Handles>,
    public: Pub,
    ephemeral: bool,
}

pub struct KeyNames {
    pub sign: PCWSTR,
    pub wrap: PCWSTR,
    pub machine: bool,
}

pub const PRODUCTION: KeyNames = KeyNames { sign: w!("PhoneGate-Identity-v1"), wrap: w!("PhoneGate-Wrap-v1"), machine: true };
pub const SELFTEST: KeyNames = KeyNames { sign: w!("PhoneGate-SelfTest-Sign"), wrap: w!("PhoneGate-SelfTest-Wrap"), machine: false };

unsafe fn open_or_create(prov: NCRYPT_PROV_HANDLE, name: PCWSTR, alg: PCWSTR, rsa_bits: Option<u32>, flags: NCRYPT_FLAGS) -> Result<NCRYPT_KEY_HANDLE> {
    let mut k = NCRYPT_KEY_HANDLE::default();
    // SAFETY (whole fn): caller passes a valid provider handle; out-pointers are valid locals.
    unsafe {
        if NCryptOpenKey(prov, &mut k, name, CERT_KEY_SPEC(0), flags | NCRYPT_SILENT_FLAG).is_ok() {
            return Ok(k);
        }
        NCryptCreatePersistedKey(prov, &mut k, alg, name, CERT_KEY_SPEC(0), flags).map_err(werr("create TPM key"))?;
        if let Some(bits) = rsa_bits {
            NCryptSetProperty(NCRYPT_HANDLE(k.0), NCRYPT_LENGTH_PROPERTY, &bits.to_le_bytes(), NCRYPT_FLAGS(0)).map_err(werr("set key length"))?;
        }
        NCryptFinalizeKey(k, NCRYPT_SILENT_FLAG).map_err(werr("finalize TPM key"))?;
    }
    Ok(k)
}

unsafe fn export_ec_public(k: NCRYPT_KEY_HANDLE) -> Result<Pub> {
    // SAFETY: two-call size pattern with a buffer of the reported size.
    unsafe {
        let mut len = 0u32;
        NCryptExportKey(k, NCRYPT_KEY_HANDLE::default(), BCRYPT_ECCPUBLIC_BLOB, None, None, &mut len, NCRYPT_FLAGS(0)).map_err(werr("export size"))?;
        let mut buf = vec![0u8; len as usize];
        NCryptExportKey(k, NCRYPT_KEY_HANDLE::default(), BCRYPT_ECCPUBLIC_BLOB, None, Some(&mut buf), &mut len, NCRYPT_FLAGS(0)).map_err(werr("export key"))?;
        let hdr = std::mem::size_of::<BCRYPT_ECCKEY_BLOB>();
        if buf.len() < hdr + 64 {
            return Err(Error::Crypto("unexpected ECC public blob"));
        }
        let blob = &*(buf.as_ptr() as *const BCRYPT_ECCKEY_BLOB);
        if blob.cbKey != 32 {
            return Err(Error::Crypto("TPM key is not P-256"));
        }
        let mut p = [0u8; 65];
        p[0] = 0x04;
        p[1..].copy_from_slice(&buf[hdr..hdr + 64]);
        crypto::parse_pub(&p)?;
        Ok(p)
    }
}

impl TpmBackend {
    pub fn open(names: &KeyNames) -> Result<Self> {
        let flags = if names.machine { NCRYPT_MACHINE_KEY_FLAG } else { NCRYPT_FLAGS(0) };
        let mut prov = NCRYPT_PROV_HANDLE::default();
        // SAFETY: FFI with valid out-pointers and static wide strings.
        unsafe {
            NCryptOpenStorageProvider(&mut prov, MS_PLATFORM_CRYPTO_PROVIDER, 0).map_err(werr("open Platform Crypto Provider (no TPM?)"))?;
            let sign = open_or_create(prov, names.sign, BCRYPT_ECDSA_P256_ALGORITHM, None, flags)?;
            let wrap = open_or_create(prov, names.wrap, BCRYPT_RSA_ALGORITHM, Some(2048), flags)?;
            let public = export_ec_public(sign)?;
            Ok(TpmBackend { h: Mutex::new(Handles { prov, sign, wrap }), public, ephemeral: !names.machine })
        }
    }

    /// Deletes the (self-test) keys from the TPM.
    pub fn delete(self) -> Result<()> {
        let h = self.h.into_inner().unwrap_or_else(|p| p.into_inner());
        // SAFETY: NCryptDeleteKey frees the handle on success; we forget the struct afterwards.
        unsafe {
            NCryptDeleteKey(h.sign, 0).map_err(werr("delete key"))?;
            NCryptDeleteKey(h.wrap, 0).map_err(werr("delete key"))?;
            let _ = NCryptFreeObject(NCRYPT_HANDLE(h.prov.0));
        }
        std::mem::forget(h);
        Ok(())
    }

    pub fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    fn oaep(alg: PCWSTR) -> BCRYPT_OAEP_PADDING_INFO {
        BCRYPT_OAEP_PADDING_INFO { pszAlgId: alg, pbLabel: std::ptr::null_mut(), cbLabel: 0 }
    }
}

impl Signer for TpmBackend {
    fn public(&self) -> Pub {
        self.public
    }

    fn sign(&self, msg: &[u8]) -> Result<Sig> {
        let hash = crypto::sha256(msg);
        let h = self.h.lock().unwrap_or_else(|p| p.into_inner());
        let mut sig = [0u8; 64];
        let mut len = 0u32;
        // SAFETY: valid key handle, 32-byte hash, 64-byte output buffer.
        unsafe {
            NCryptSignHash(h.sign, None, &hash, Some(&mut sig), &mut len, NCRYPT_SILENT_FLAG).map_err(werr("TPM sign"))?;
        }
        if len != 64 {
            return Err(Error::Crypto("unexpected TPM signature length"));
        }
        Ok(sig)
    }
}

impl KeyBackend for TpmBackend {
    fn kind(&self) -> &'static str {
        "tpm"
    }

    fn wrap(&self, secret: &[u8]) -> Result<Vec<u8>> {
        let h = self.h.lock().unwrap_or_else(|p| p.into_inner());
        // Prefer OAEP-SHA256; some TPMs only implement OAEP-SHA1 (still secure for encryption).
        for (tag, alg) in [(1u8, BCRYPT_SHA256_ALGORITHM), (2u8, BCRYPT_SHA1_ALGORITHM)] {
            let pad = Self::oaep(alg);
            let mut len = 0u32;
            // SAFETY: two-call size pattern; padding struct outlives the calls.
            unsafe {
                let pinfo = Some(&pad as *const _ as *const core::ffi::c_void);
                if NCryptEncrypt(h.wrap, Some(secret), pinfo, None, &mut len, NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG).is_err() {
                    continue;
                }
                let mut out = vec![0u8; len as usize];
                if NCryptEncrypt(h.wrap, Some(secret), pinfo, Some(&mut out), &mut len, NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG).is_ok() {
                    out.truncate(len as usize);
                    let mut blob = vec![tag];
                    blob.extend(out);
                    return Ok(blob);
                }
            }
        }
        Err(Error::Crypto("TPM wrap failed"))
    }

    fn unwrap(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let (tag, ct) = blob.split_first().ok_or(Error::Decode("empty wrapped blob"))?;
        let alg = match tag {
            1 => BCRYPT_SHA256_ALGORITHM,
            2 => BCRYPT_SHA1_ALGORITHM,
            _ => return Err(Error::Decode("unknown wrap format")),
        };
        let pad = Self::oaep(alg);
        let h = self.h.lock().unwrap_or_else(|p| p.into_inner());
        let mut len = 0u32;
        // SAFETY: two-call size pattern; output zeroized after use by Zeroizing.
        unsafe {
            let pinfo = Some(&pad as *const _ as *const core::ffi::c_void);
            NCryptDecrypt(h.wrap, Some(ct), pinfo, None, &mut len, NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG).map_err(werr("TPM unwrap"))?;
            let mut out = Zeroizing::new(vec![0u8; len as usize]);
            NCryptDecrypt(h.wrap, Some(ct), pinfo, Some(&mut out), &mut len, NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG).map_err(werr("TPM unwrap"))?;
            out.truncate(len as usize);
            Ok(out)
        }
    }
}

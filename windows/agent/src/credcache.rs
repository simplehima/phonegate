//! Stored-credential cache for passwordless sign-in (feature 004, US1).
//!
//! The Windows password is wrapped by the PC's key backend (TPM, or DPAPI without a TPM) and held
//! only on this machine, SYSTEM-only. It is released to the credential provider as a packed
//! `KERB_INTERACTIVE_UNLOCK_LOGON` **only after a verified phone approval** (the engine enforces
//! that; this module just stores, wraps and packs).
//!
//! Safety: if the stored password is wrong (changed in Windows later), LSA rejects the packed
//! buffer and the tile falls back to typing the password or a recovery code — never a lockout
//! (spec FR-405).

use pg_core::crypto::b64;
use pg_core::{Error, Result};
use zeroize::Zeroizing;

use crate::keys::KeyBackend;

/// Packs a `KERB_INTERACTIVE_UNLOCK_LOGON` for an interactive logon (message type 2), the same
/// byte layout the credential provider's `kerb` module parses. UNICODE_STRING buffers hold byte
/// offsets from the start of the buffer (x64). The LUID is left zero.
pub fn pack_kerb_logon(domain: &str, user: &str, password: &str) -> Vec<u8> {
    const HEADER_LEN: usize = 64; // MessageType(4)+pad(4)+3*UNICODE_STRING(16)+LUID(8)
    const KERB_INTERACTIVE_LOGON: u32 = 2;
    let parts: [Vec<u8>; 3] = [
        domain.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        user.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        password.encode_utf16().flat_map(u16::to_le_bytes).collect(),
    ];
    let mut out = vec![0u8; HEADER_LEN];
    out[0..4].copy_from_slice(&KERB_INTERACTIVE_LOGON.to_le_bytes());
    let mut off = HEADER_LEN;
    for (i, p) in parts.iter().enumerate() {
        let at = 8 + i * 16;
        let len = p.len() as u16;
        out[at..at + 2].copy_from_slice(&len.to_le_bytes()); // Length
        out[at + 2..at + 4].copy_from_slice(&len.to_le_bytes()); // MaximumLength
        out[at + 8..at + 16].copy_from_slice(&(off as u64).to_le_bytes()); // Buffer = byte offset
        off += p.len();
    }
    for p in parts {
        out.extend_from_slice(&p);
    }
    out
}

/// Splits a stored account string into `(domain, user)`. `DOMAIN\user` → ("DOMAIN","user");
/// `user@host` or bare `user` → ("", whole) so LSA resolves it.
pub fn split_account(account: &str) -> (String, String) {
    match account.split_once('\\') {
        Some((d, u)) if !d.is_empty() && !u.is_empty() => (d.to_string(), u.to_string()),
        _ => (String::new(), account.to_string()),
    }
}

/// Wraps a password with the key backend for at-rest storage (returns base64 of the wrapped blob).
pub fn wrap_password(keys: &dyn KeyBackend, password: &str) -> Result<String> {
    let mut bytes = Zeroizing::new(password.as_bytes().to_vec());
    let wrapped = keys.wrap(&bytes)?;
    bytes.iter_mut().for_each(|b| *b = 0);
    Ok(b64::encode(&wrapped))
}

/// Unwraps a stored password and packs it as a logon serialization for `account`.
pub fn release_serialization(keys: &dyn KeyBackend, account: &str, wrapped_b64: &str) -> Result<Zeroizing<Vec<u8>>> {
    let wrapped = b64::decode(wrapped_b64)?;
    let pw = keys.unwrap(&wrapped)?;
    let pw = String::from_utf8(pw.to_vec()).map_err(|_| Error::Decode("stored password is not valid UTF-8"))?;
    let pw = Zeroizing::new(pw);
    let (domain, user) = split_account(account);
    Ok(Zeroizing::new(pack_kerb_logon(&domain, &user, &pw)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MemoryBackend;

    #[test]
    fn account_split() {
        assert_eq!(split_account("DESK\\owner"), ("DESK".into(), "owner".into()));
        assert_eq!(split_account("owner"), (String::new(), "owner".into()));
        assert_eq!(split_account("a@b.com"), (String::new(), "a@b.com".into()));
        assert_eq!(split_account("\\x"), (String::new(), "\\x".into()));
    }

    #[test]
    fn kerb_pack_layout_roundtrips() {
        // The packed buffer must parse back to the same fields (header offsets correct).
        let buf = pack_kerb_logon("DESK", "owner", "p\u{e4}ss");
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 2);
        // Domain UNICODE_STRING at offset 8, length 8 bytes (4 UTF-16 chars).
        assert_eq!(u16::from_le_bytes(buf[8..10].try_into().unwrap()), 8);
        let doff = u64::from_le_bytes(buf[16..24].try_into().unwrap()) as usize;
        let dom: Vec<u16> = buf[doff..doff + 8].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        assert_eq!(String::from_utf16(&dom).unwrap(), "DESK");
    }

    #[test]
    fn wrap_release_roundtrip_and_no_plaintext_at_rest() {
        let keys = MemoryBackend::generate().unwrap();
        let wrapped = wrap_password(&keys, "hunter2").unwrap();
        assert!(!wrapped.contains("hunter2"));
        let ser = release_serialization(&keys, "DESK\\owner", &wrapped).unwrap();
        // The released serialization contains the password as UTF-16 (it is a logon buffer).
        let pw16: Vec<u8> = "hunter2".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(ser.windows(pw16.len()).any(|w| w == pw16));
        // A different backend cannot unwrap it.
        let other = MemoryBackend::generate().unwrap();
        assert!(release_serialization(&other, "DESK\\owner", &wrapped).is_err());
    }
}

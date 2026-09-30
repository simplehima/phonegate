//! Parsing of the packed `KERB_INTERACTIVE_UNLOCK_LOGON` produced by the wrapped Password
//! provider, so the typed credentials can be pre-checked locally before a phone request is sent
//! (research R9). The password never leaves LogonUI.
//!
//! Packed layout (x64): the `UNICODE_STRING::Buffer` members hold byte offsets from the start of
//! the buffer instead of pointers.

use zeroize::Zeroizing;

#[cfg(not(target_pointer_width = "64"))]
compile_error!("PhoneGate's credential provider supports 64-bit Windows only");

const KERB_INTERACTIVE_LOGON: u32 = 2;
const KERB_WORKSTATION_UNLOCK_LOGON: u32 = 7;
/// MessageType(4) + pad(4) + 3 * UNICODE_STRING(16) + LUID(8).
pub const HEADER_LEN: usize = 64;

#[derive(Debug)]
pub struct Credentials {
    pub domain: String,
    pub user: String,
    pub password: Zeroizing<Vec<u16>>,
}

impl Credentials {
    /// `DOMAIN\user` for display on the phone.
    pub fn account(&self) -> String {
        if self.domain.is_empty() {
            self.user.clone()
        } else {
            format!("{}\\{}", self.domain, self.user)
        }
    }

    /// Accounts whose passwords `LogonUserW(NETWORK)` may not validate reliably; for these we skip
    /// the local pre-check and let LSA decide (never block a correct password).
    pub fn precheck_supported(&self) -> bool {
        let d = self.domain.to_ascii_lowercase();
        !(d == "microsoftaccount" || d == "azuread" || self.user.contains('@'))
    }
}

fn read_u16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn read_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn read_u64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

fn unicode_string(b: &[u8], at: usize) -> Option<Vec<u16>> {
    let len = read_u16(b, at)? as usize;
    let off = usize::try_from(read_u64(b, at + 8)?).ok()?;
    if !len.is_multiple_of(2) || off.checked_add(len)? > b.len() || (len > 0 && off < HEADER_LEN) {
        return None;
    }
    Some(b[off..off + len].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect())
}

/// Parses a packed interactive/unlock logon buffer. Returns `None` for any other format.
pub fn parse(buf: &[u8]) -> Option<Credentials> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let mt = read_u32(buf, 0)?;
    if mt != KERB_INTERACTIVE_LOGON && mt != KERB_WORKSTATION_UNLOCK_LOGON {
        return None;
    }
    let domain = String::from_utf16(&unicode_string(buf, 8)?).ok()?;
    let user = String::from_utf16(&unicode_string(buf, 24)?).ok()?;
    let password = Zeroizing::new(unicode_string(buf, 40)?);
    if user.is_empty() {
        return None;
    }
    Some(Credentials { domain, user, password })
}

/// Builds a packed buffer (used by tests and mirrors the Microsoft sample's packing).
pub fn pack(message_type: u32, domain: &str, user: &str, password: &str) -> Vec<u8> {
    let parts: Vec<Vec<u8>> = [domain, user, password]
        .iter()
        .map(|s| s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect())
        .collect();
    let mut out = vec![0u8; HEADER_LEN];
    out[0..4].copy_from_slice(&message_type.to_le_bytes());
    let mut off = HEADER_LEN;
    for (i, p) in parts.iter().enumerate() {
        let at = 8 + i * 16;
        out[at..at + 2].copy_from_slice(&(p.len() as u16).to_le_bytes());
        out[at + 2..at + 4].copy_from_slice(&(p.len() as u16).to_le_bytes());
        out[at + 8..at + 16].copy_from_slice(&(off as u64).to_le_bytes());
        off += p.len();
    }
    for p in parts {
        out.extend(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_unlock_and_logon() {
        for mt in [KERB_INTERACTIVE_LOGON, KERB_WORKSTATION_UNLOCK_LOGON] {
            let b = pack(mt, "DESK", "owner", "s3cr3t-pässword");
            let c = parse(&b).unwrap();
            assert_eq!(c.domain, "DESK");
            assert_eq!(c.user, "owner");
            assert_eq!(String::from_utf16(&c.password).unwrap(), "s3cr3t-pässword");
            assert_eq!(c.account(), "DESK\\owner");
            assert!(c.precheck_supported());
        }
    }

    #[test]
    fn rejects_malformed_buffers() {
        let good = pack(2, "D", "u", "p");
        assert!(parse(&good[..HEADER_LEN - 1]).is_none());
        let mut bad_type = good.clone();
        bad_type[0] = 9;
        assert!(parse(&bad_type).is_none());
        let mut out_of_range = good.clone();
        out_of_range[24 + 8..24 + 16].copy_from_slice(&(10_000u64).to_le_bytes());
        assert!(parse(&out_of_range).is_none());
        let mut into_header = good.clone();
        into_header[40 + 8..40 + 16].copy_from_slice(&(4u64).to_le_bytes());
        assert!(parse(&into_header).is_none());
        let mut odd = good;
        odd[40] = 3;
        assert!(parse(&odd).is_none());
        assert!(parse(&pack(2, "D", "", "p")).is_none(), "empty user");
    }

    #[test]
    fn microsoft_accounts_skip_precheck() {
        assert!(!parse(&pack(2, "MicrosoftAccount", "a@b.com", "p")).unwrap().precheck_supported());
        assert!(!parse(&pack(2, "AzureAD", "a", "p")).unwrap().precheck_supported());
    }
}

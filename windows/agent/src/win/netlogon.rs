//! Network sign-in block (feature 002, US4): grants `SeDenyNetworkLogonRight` to the well-known
//! SID S-1-5-113 (NT AUTHORITY\Local account) through the LSA policy API.

use pg_core::{Error, Result};
use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL, NTSTATUS};
use windows::Win32::Security::Authentication::Identity::{
    LsaAddAccountRights, LsaClose, LsaEnumerateAccountRights, LsaFreeMemory, LsaNtStatusToWinError, LsaOpenPolicy, LsaRemoveAccountRights, LSA_HANDLE,
    LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, POLICY_CREATE_ACCOUNT, POLICY_LOOKUP_NAMES,
};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::PSID;

use crate::probe::NetLogon;

const RIGHT: &str = "SeDenyNetworkLogonRight";
const LOCAL_ACCOUNT_SID: &str = "S-1-5-113";
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;

fn check(st: NTSTATUS, ctx: &str) -> Result<()> {
    if st.0 == 0 {
        return Ok(());
    }
    // SAFETY: pure conversion.
    let code = unsafe { LsaNtStatusToWinError(st) };
    Err(Error::Io(format!("{ctx}: Win32 error {code}")))
}

struct Policy(LSA_HANDLE);
impl Drop for Policy {
    fn drop(&mut self) {
        // SAFETY: handle from LsaOpenPolicy, closed once.
        unsafe {
            let _ = LsaClose(self.0);
        }
    }
}

struct Sid(PSID);
impl Drop for Sid {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSidToSidW.
        unsafe {
            let _ = LocalFree(HLOCAL(self.0 .0));
        }
    }
}

fn open() -> Result<Policy> {
    let attrs = LSA_OBJECT_ATTRIBUTES::default();
    let mut h = LSA_HANDLE::default();
    // SAFETY: zeroed object attributes as documented; local system policy.
    let st = unsafe { LsaOpenPolicy(None, &attrs, (POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES) as u32, &mut h) };
    check(st, "LsaOpenPolicy")?;
    Ok(Policy(h))
}

fn sid() -> Result<Sid> {
    let mut p = PSID::default();
    // SAFETY: valid SID string; output freed by `Sid`'s drop.
    unsafe { ConvertStringSidToSidW(&HSTRING::from(LOCAL_ACCOUNT_SID), &mut p).map_err(|e| Error::Io(e.to_string()))? };
    Ok(Sid(p))
}

/// LSA_UNICODE_STRING borrowing a UTF-16 buffer (no terminator required).
fn lsa_str(w: &mut [u16]) -> LSA_UNICODE_STRING {
    let bytes = (w.len() * 2) as u16;
    LSA_UNICODE_STRING { Length: bytes, MaximumLength: bytes, Buffer: PWSTR(w.as_mut_ptr()) }
}

pub struct WinNetLogon;

impl NetLogon for WinNetLogon {
    fn blocked(&self) -> Result<bool> {
        let pol = open()?;
        let s = sid()?;
        let mut rights: *mut LSA_UNICODE_STRING = std::ptr::null_mut();
        let mut n = 0u32;
        // SAFETY: out-pointers are locals; the array is freed with LsaFreeMemory.
        let st = unsafe { LsaEnumerateAccountRights(pol.0, s.0, &mut rights, &mut n) };
        if st.0 == STATUS_OBJECT_NAME_NOT_FOUND {
            return Ok(false); // the SID holds no rights at all
        }
        check(st, "LsaEnumerateAccountRights")?;
        let mut found = false;
        // SAFETY: LSA returned `n` valid strings.
        unsafe {
            for r in std::slice::from_raw_parts(rights, n as usize) {
                let chars = std::slice::from_raw_parts(r.Buffer.0, (r.Length / 2) as usize);
                if String::from_utf16_lossy(chars) == RIGHT {
                    found = true;
                }
            }
            let _ = LsaFreeMemory(Some(rights as _));
        }
        Ok(found)
    }

    fn set_blocked(&self, block: bool) -> Result<()> {
        let pol = open()?;
        let s = sid()?;
        let mut w: Vec<u16> = RIGHT.encode_utf16().collect();
        let right = [lsa_str(&mut w)];
        // SAFETY: `right` borrows `w`, which outlives the call.
        let st = unsafe {
            if block {
                LsaAddAccountRights(pol.0, s.0, &right)
            } else {
                LsaRemoveAccountRights(pol.0, s.0, false, Some(&right))
            }
        };
        if !block && st.0 == STATUS_OBJECT_NAME_NOT_FOUND {
            return Ok(()); // nothing to remove
        }
        check(st, if block { "LsaAddAccountRights" } else { "LsaRemoveAccountRights" })
    }
}

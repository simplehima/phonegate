//! Restricts the data directory to SYSTEM and Administrators (protected DACL, inherited by files).

use std::path::Path;

use pg_core::{Error, Result};
use windows::core::HSTRING;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT};
use windows::Win32::Security::{GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

pub const DATA_DIR_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

pub fn restrict_dir(dir: &Path) -> Result<()> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: FFI with valid inputs; the descriptor is freed with LocalFree.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(&HSTRING::from(DATA_DIR_SDDL), SDDL_REVISION_1, &mut sd, None).map_err(|e| Error::Io(format!("sddl: {e}")))?;
        let mut present = false.into();
        let mut defaulted = false.into();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let r = GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted);
        let res = if r.is_ok() {
            SetNamedSecurityInfoW(
                &HSTRING::from(dir.as_os_str()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
            .ok()
            .map_err(|e| Error::Io(format!("set ACL on {}: {e}", dir.display())))
        } else {
            Err(Error::Io("read DACL".into()))
        };
        let _ = LocalFree(HLOCAL(sd.0));
        res
    }
}

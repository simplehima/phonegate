//! Credential Provider Filter: while PhoneGate enforces, only the PhoneGate tile is offered for
//! logon and unlock, so Password / PIN / Windows Hello / smart-card tiles cannot bypass the gate.

use windows::core::{implement, GUID};
use windows::Win32::Foundation::{BOOL, E_INVALIDARG, E_NOTIMPL};
use windows::Win32::UI::Shell::{
    ICredentialProviderFilter, ICredentialProviderFilter_Impl, CPUS_CHANGE_PASSWORD, CPUS_CREDUI, CPUS_LOGON, CPUS_UNLOCK_WORKSTATION,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_USAGE_SCENARIO,
};

use crate::com::{guard, ObjectToken, CLSID_PASSWORD_PROVIDER, CLSID_PROVIDER};
use crate::policy::{self, Usage};

pub fn usage_of(cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO) -> Usage {
    match cpus {
        CPUS_LOGON => Usage::Logon,
        CPUS_UNLOCK_WORKSTATION => Usage::Unlock,
        CPUS_CREDUI => Usage::CredUi,
        CPUS_CHANGE_PASSWORD => Usage::ChangePassword,
        _ => Usage::Other,
    }
}

#[implement(ICredentialProviderFilter)]
pub struct Filter {
    _t: ObjectToken,
}

impl Filter {
    pub fn new() -> Self {
        Filter { _t: ObjectToken::new() }
    }
}

impl ICredentialProviderFilter_Impl for Filter_Impl {
    fn Filter(&self, cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO, _flags: u32, clsids: *const GUID, allow: *mut BOOL, n: u32) -> windows::core::Result<()> {
        guard(|| {
            if n == 0 {
                return Ok(());
            }
            if clsids.is_null() || allow.is_null() {
                return Err(E_INVALIDARG.into());
            }
            // SAFETY: LogonUI passes arrays of `n` elements.
            let (ids, allow) = unsafe { (std::slice::from_raw_parts(clsids, n as usize), std::slice::from_raw_parts_mut(allow, n as usize)) };
            let providers: Vec<u128> = ids.iter().map(|g| g.to_u128()).collect();
            let mut decision: Vec<bool> = allow.iter().map(|b| b.as_bool()).collect();
            policy::filter(usage_of(cpus), policy::enforcing(&policy::state_path()), &providers, CLSID_PROVIDER.to_u128(), &mut decision);
            for (a, d) in allow.iter_mut().zip(decision) {
                *a = BOOL::from(d);
            }
            Ok(())
        })
    }

    /// Remote Desktop with NLA hands LogonUI a serialization for the Password provider; redirect
    /// it to PhoneGate so the phone step still applies (we unwrap it back for the inner provider).
    fn UpdateRemoteCredential(&self, input: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, output: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION) -> windows::core::Result<()> {
        guard(|| {
            if input.is_null() || output.is_null() {
                return Err(E_INVALIDARG.into());
            }
            if !policy::enforcing(&policy::state_path()) {
                return Err(E_NOTIMPL.into());
            }
            // SAFETY: LogonUI passes a valid serialization; we deep-copy its buffer.
            unsafe {
                let src = &*input;
                if src.clsidCredentialProvider != CLSID_PASSWORD_PROVIDER || src.rgbSerialization.is_null() {
                    return Err(E_NOTIMPL.into());
                }
                let data = std::slice::from_raw_parts(src.rgbSerialization, src.cbSerialization as usize);
                let copy = crate::win::co_bytes(data)?;
                *output = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
                    ulAuthenticationPackage: src.ulAuthenticationPackage,
                    clsidCredentialProvider: CLSID_PROVIDER,
                    cbSerialization: src.cbSerialization,
                    rgbSerialization: copy,
                };
            }
            Ok(())
        })
    }
}

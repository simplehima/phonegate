//! # phonegate_cp.dll
//!
//! Windows Credential Provider (wrapping the built-in Password provider) and Credential Provider
//! Filter. Loaded in-process by LogonUI.exe as SYSTEM on the secure desktop.
//!
//! Safety rules for this crate:
//! - every COM entry point runs inside [`guard`], so a Rust panic becomes `E_FAIL` instead of
//!   unwinding into LogonUI;
//! - no blocking network I/O on LogonUI's thread: the phone wait runs on a worker thread that
//!   talks to the SYSTEM agent over a named pipe;
//! - fail-secure: without a verified approval (or a valid recovery/offline code) no credential
//!   is ever returned.

// rustc emits its own .def for cdylibs; LNK4104 (COM exports "should be PRIVATE") is benign.
#![allow(linker_messages)]

pub mod gate;
pub mod kerb;
pub mod policy;
pub mod qr;

#[cfg(windows)]
mod credential;
#[cfg(windows)]
mod events;
#[cfg(windows)]
mod filter;
#[cfg(windows)]
mod provider;
#[cfg(windows)]
mod qrwin;
#[cfg(windows)]
mod win;

#[cfg(windows)]
pub use com::*;

#[cfg(windows)]
mod com {
    use std::ffi::c_void;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use windows::core::{implement, IUnknown, Interface, GUID, HRESULT};
    use windows::Win32::Foundation::{BOOL, CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_FAIL, E_POINTER, S_FALSE, S_OK};
    use windows::Win32::System::Com::{IClassFactory, IClassFactory_Impl};

    /// PhoneGate credential provider CLSID (public constant, not a secret).
    pub const CLSID_PROVIDER: GUID = GUID::from_u128(0xc8ee462b_90e1_4c2f_994d_1d808359162f);
    /// PhoneGate credential provider filter CLSID.
    pub const CLSID_FILTER: GUID = GUID::from_u128(0x44d3bbdf_b4a3_4bb0_acf0_114f5587c1e5);
    /// Built-in Windows Password credential provider (wrapped).
    pub const CLSID_PASSWORD_PROVIDER: GUID = GUID::from_u128(0x60b78e88_ead8_445c_9cfd_0b87f74ea6cd);

    static OBJECTS: AtomicUsize = AtomicUsize::new(0);
    static LOCKS: AtomicUsize = AtomicUsize::new(0);

    /// Live-object counter used by `DllCanUnloadNow`.
    pub(crate) struct ObjectToken;
    impl ObjectToken {
        pub(crate) fn new() -> Self {
            OBJECTS.fetch_add(1, Ordering::SeqCst);
            ObjectToken
        }
    }
    impl Drop for ObjectToken {
        fn drop(&mut self) {
            OBJECTS.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Runs a COM method body, converting panics into `E_FAIL`.
    pub(crate) fn guard<T>(f: impl FnOnce() -> windows::core::Result<T>) -> windows::core::Result<T> {
        catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| Err(E_FAIL.into()))
    }

    #[derive(Clone, Copy)]
    enum Kind {
        Provider,
        Filter,
    }

    #[implement(IClassFactory)]
    struct Factory {
        kind: Kind,
        _t: ObjectToken,
    }

    impl IClassFactory_Impl for Factory_Impl {
        fn CreateInstance(&self, outer: Option<&IUnknown>, riid: *const GUID, ppv: *mut *mut c_void) -> windows::core::Result<()> {
            guard(|| {
                if ppv.is_null() || riid.is_null() {
                    return Err(E_POINTER.into());
                }
                // SAFETY: checked non-null above.
                unsafe { *ppv = std::ptr::null_mut() };
                if outer.is_some() {
                    return Err(CLASS_E_NOAGGREGATION.into());
                }
                let unk: IUnknown = match self.kind {
                    Kind::Provider => crate::provider::Provider::new().into(),
                    Kind::Filter => crate::filter::Filter::new().into(),
                };
                // SAFETY: riid/ppv validated; QueryInterface writes an AddRef'd pointer.
                unsafe { unk.query(riid, ppv).ok() }
            })
        }

        fn LockServer(&self, lock: BOOL) -> windows::core::Result<()> {
            if lock.as_bool() {
                LOCKS.fetch_add(1, Ordering::SeqCst);
            } else {
                LOCKS.fetch_sub(1, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    /// # Safety
    /// Standard COM export; pointers come from the COM runtime.
    #[no_mangle]
    pub unsafe extern "system" fn DllGetClassObject(rclsid: *const GUID, riid: *const GUID, ppv: *mut *mut c_void) -> HRESULT {
        if rclsid.is_null() || riid.is_null() || ppv.is_null() {
            return E_POINTER;
        }
        // SAFETY: validated non-null pointers from COM.
        unsafe {
            *ppv = std::ptr::null_mut();
            let kind = match *rclsid {
                c if c == CLSID_PROVIDER => Kind::Provider,
                c if c == CLSID_FILTER => Kind::Filter,
                _ => return CLASS_E_CLASSNOTAVAILABLE,
            };
            let r = catch_unwind(AssertUnwindSafe(|| {
                let f: IClassFactory = Factory { kind, _t: ObjectToken::new() }.into();
                f.query(riid, ppv)
            }));
            r.unwrap_or(E_FAIL)
        }
    }

    #[no_mangle]
    pub extern "system" fn DllCanUnloadNow() -> HRESULT {
        if OBJECTS.load(Ordering::SeqCst) == 0 && LOCKS.load(Ordering::SeqCst) == 0 {
            S_OK
        } else {
            S_FALSE
        }
    }

    pub(crate) fn _assert_interface<I: Interface>() {}

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
        use windows::Win32::UI::Shell::{ICredentialProvider, ICredentialProviderFilter, CPUS_CREDUI, CPUS_LOGON};

        fn factory(clsid: GUID) -> IClassFactory {
            let mut p = std::ptr::null_mut();
            // SAFETY: valid pointers to locals.
            let hr = unsafe { DllGetClassObject(&clsid, &IClassFactory::IID, &mut p) };
            assert_eq!(hr, S_OK);
            // SAFETY: p is an AddRef'd IClassFactory.
            unsafe { IClassFactory::from_raw(p) }
        }

        #[test]
        fn com_plumbing_and_disabled_state() {
            // SAFETY: test-thread COM init.
            unsafe {
                let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            }
            let mut p = std::ptr::null_mut();
            let bogus = GUID::from_u128(1);
            // SAFETY: valid pointers.
            assert_eq!(unsafe { DllGetClassObject(&bogus, &IClassFactory::IID, &mut p) }, CLASS_E_CLASSNOTAVAILABLE);

            // SAFETY: CreateInstance per COM contract.
            let provider: ICredentialProvider = unsafe { factory(CLSID_PROVIDER).CreateInstance(None).unwrap() };
            // CredUI is never handled by PhoneGate.
            // SAFETY: plain COM call.
            assert!(unsafe { provider.SetUsageScenario(CPUS_CREDUI, 0) }.is_err());
            if !crate::policy::enforcing(&crate::policy::state_path()) {
                // Not installed/enforcing on this machine: the provider stays out of the way.
                // SAFETY: plain COM call.
                assert!(unsafe { provider.SetUsageScenario(CPUS_LOGON, 0) }.is_err());
            }

            // SAFETY: CreateInstance per COM contract.
            let filter: ICredentialProviderFilter = unsafe { factory(CLSID_FILTER).CreateInstance(None).unwrap() };
            let ids = [CLSID_PASSWORD_PROVIDER, CLSID_PROVIDER];
            let mut allow = [BOOL(1), BOOL(1)];
            // SAFETY: arrays of matching length.
            unsafe { filter.Filter(CPUS_CREDUI, 0, ids.as_ptr(), allow.as_mut_ptr(), 2).unwrap() };
            assert_eq!(allow, [BOOL(1), BOOL(1)], "CredUI never filtered");
            drop(provider);
            drop(filter);
        }
    }
}

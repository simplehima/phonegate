//! Wrapping credential provider: owns the built-in Password provider and exposes each of its
//! tiles wrapped in a PhoneGate credential that adds the phone step.

use std::sync::{Arc, Mutex};

use windows::core::{implement, AgileReference, Interface};
use windows::Win32::Foundation::{BOOL, E_INVALIDARG, E_NOTIMPL, E_UNEXPECTED};
use windows::Win32::System::Com::{CoCreateInstance, CoTaskMemFree, CLSCTX_INPROC_SERVER};
use windows::Win32::UI::Shell::{
    ICredentialProvider, ICredentialProviderCredential, ICredentialProviderEvents, ICredentialProviderSetUserArray, ICredentialProviderSetUserArray_Impl,
    ICredentialProviderUserArray, ICredentialProvider_Impl, CPFT_TILE_IMAGE, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO,
};

use crate::com::{guard, ObjectToken, CLSID_PASSWORD_PROVIDER, CLSID_PROVIDER};
use crate::credential::{self, Credential};
use crate::filter::usage_of;
use crate::policy::{self, Usage};

/// State shared between the provider, its credentials and their worker threads.
pub struct Shared {
    pub events: Mutex<Option<(AgileReference<ICredentialProviderEvents>, usize)>>,
    /// Index of the credential whose request was approved and must be auto-submitted.
    pub auto_submit: Mutex<Option<usize>>,
    pub scenario: Mutex<&'static str>,
}

impl Shared {
    /// Asks LogonUI to re-enumerate our credentials (safe from a worker thread via the agile ref).
    pub fn notify(&self) {
        let ev = self.events.lock().unwrap_or_else(|p| p.into_inner()).as_ref().and_then(|(a, ctx)| a.resolve().ok().map(|e| (e, *ctx)));
        if let Some((e, ctx)) = ev {
            // SAFETY: valid events interface resolved for this thread.
            unsafe {
                let _ = e.CredentialsChanged(ctx);
            }
        }
    }
}

#[implement(ICredentialProvider, ICredentialProviderSetUserArray)]
pub struct Provider {
    inner: Mutex<Option<ICredentialProvider>>,
    creds: Mutex<Vec<(ICredentialProviderCredential, ICredentialProviderCredential)>>,
    /// Per-tile state, kept by index so a pending approval survives even if the wrapped provider
    /// hands out new credential objects when LogonUI re-enumerates.
    states: Mutex<Vec<Arc<Mutex<credential::State>>>>,
    shared: Arc<Shared>,
    _t: ObjectToken,
}

impl Provider {
    pub fn new() -> Self {
        Provider {
            inner: Mutex::new(None),
            creds: Mutex::new(Vec::new()),
            states: Mutex::new(Vec::new()),
            shared: Arc::new(Shared { events: Mutex::new(None), auto_submit: Mutex::new(None), scenario: Mutex::new("unlock") }),
            _t: ObjectToken::new(),
        }
    }

    fn inner(&self) -> windows::core::Result<ICredentialProvider> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).clone().ok_or_else(|| E_UNEXPECTED.into())
    }

    /// Field id of the wrapped provider's tile image (where the offline QR is drawn).
    fn tile_field(inner: &ICredentialProvider, count: u32) -> Option<u32> {
        for i in 0..count {
            // SAFETY: descriptors are CoTaskMem-allocated by the inner provider; we free them.
            unsafe {
                let Ok(d) = inner.GetFieldDescriptorAt(i) else { continue };
                if d.is_null() {
                    continue;
                }
                let found = (*d).cpft == CPFT_TILE_IMAGE;
                let id = (*d).dwFieldID;
                if !(*d).pszLabel.is_null() {
                    CoTaskMemFree(Some((*d).pszLabel.0 as _));
                }
                CoTaskMemFree(Some(d as _));
                if found {
                    return Some(id);
                }
            }
        }
        None
    }
}

impl ICredentialProvider_Impl for Provider_Impl {
    fn SetUsageScenario(&self, cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO, flags: u32) -> windows::core::Result<()> {
        guard(|| {
            let usage = usage_of(cpus);
            // Only logon/unlock, and only while enforcing; otherwise stay out of the way.
            if !matches!(usage, Usage::Logon | Usage::Unlock) || !policy::enforcing(&policy::state_path()) {
                return Err(E_NOTIMPL.into());
            }
            let remote = crate::win::is_remote_session();
            *self.shared.scenario.lock().unwrap_or_else(|p| p.into_inner()) = policy::scenario(usage, remote).unwrap_or("unlock");
            // SAFETY: standard in-proc COM activation of the built-in Password provider.
            let inner: ICredentialProvider = unsafe { CoCreateInstance(&CLSID_PASSWORD_PROVIDER, None, CLSCTX_INPROC_SERVER)? };
            // SAFETY: forwarding.
            unsafe { inner.SetUsageScenario(cpus, flags)? };
            *self.inner.lock().unwrap_or_else(|p| p.into_inner()) = Some(inner);
            Ok(())
        })
    }

    fn SetSerialization(&self, pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION) -> windows::core::Result<()> {
        guard(|| {
            if pcpcs.is_null() {
                return Err(E_INVALIDARG.into());
            }
            let inner = self.inner()?;
            // SAFETY: valid serialization from LogonUI; a shallow copy with the Password
            // provider's CLSID restored lets the inner provider accept what the filter redirected.
            unsafe {
                let mut copy = *pcpcs;
                if copy.clsidCredentialProvider == CLSID_PROVIDER {
                    copy.clsidCredentialProvider = CLSID_PASSWORD_PROVIDER;
                }
                inner.SetSerialization(&copy)
            }
        })
    }

    fn Advise(&self, pcpe: Option<&ICredentialProviderEvents>, ctx: usize) -> windows::core::Result<()> {
        guard(|| {
            if let Some(e) = pcpe {
                *self.shared.events.lock().unwrap_or_else(|p| p.into_inner()) = Some((AgileReference::new(e)?, ctx));
            }
            // SAFETY: forwarding.
            unsafe { self.inner()?.Advise(pcpe, ctx) }
        })
    }

    fn UnAdvise(&self) -> windows::core::Result<()> {
        guard(|| {
            *self.shared.events.lock().unwrap_or_else(|p| p.into_inner()) = None;
            // SAFETY: forwarding.
            unsafe { self.inner()?.UnAdvise() }
        })
    }

    fn GetFieldDescriptorCount(&self) -> windows::core::Result<u32> {
        // SAFETY: forwarding.
        guard(|| Ok(unsafe { self.inner()?.GetFieldDescriptorCount()? } + credential::EXTRA_FIELDS))
    }

    fn GetFieldDescriptorAt(&self, index: u32) -> windows::core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        guard(|| {
            let inner = self.inner()?;
            // SAFETY: forwarding.
            let n = unsafe { inner.GetFieldDescriptorCount()? };
            if index < n {
                // SAFETY: forwarding.
                unsafe { inner.GetFieldDescriptorAt(index) }
            } else if index < n + credential::EXTRA_FIELDS {
                credential::descriptor(n, index - n)
            } else {
                Err(E_INVALIDARG.into())
            }
        })
    }

    fn GetCredentialCount(&self, count: *mut u32, default: *mut u32, autologon: *mut BOOL) -> windows::core::Result<()> {
        guard(|| {
            if count.is_null() || default.is_null() || autologon.is_null() {
                return Err(E_INVALIDARG.into());
            }
            let inner = self.inner()?;
            let (mut n, mut d, mut a) = (0u32, 0u32, BOOL(0));
            // SAFETY: forwarding with valid out-pointers.
            unsafe { inner.GetCredentialCount(&mut n, &mut d, &mut a)? };
            let fields = unsafe { inner.GetFieldDescriptorCount()? };
            let tile = Provider::tile_field(&inner, fields);
            let mut creds = self.creds.lock().unwrap_or_else(|p| p.into_inner());
            let mut states = self.states.lock().unwrap_or_else(|p| p.into_inner());
            states.resize_with(n as usize, Credential::new_state);
            let mut rebuilt = Vec::with_capacity(n as usize);
            for i in 0..n {
                // SAFETY: forwarding.
                let ic = unsafe { inner.GetCredentialAt(i)? };
                // Reuse our wrapper if the inner credential is unchanged, so pending state survives
                // LogonUI's re-enumeration after CredentialsChanged.
                let existing = creds.iter().find(|(inner_c, _)| inner_c.as_raw() == ic.as_raw()).map(|(_, w)| w.clone());
                let wrapper = match existing {
                    Some(w) => w,
                    None => {
                        let c2: windows::Win32::UI::Shell::ICredentialProviderCredential2 = Credential::new(ic.clone(), fields, tile, i as usize, self.shared.clone(), states[i as usize].clone()).into();
                        c2.cast()?
                    }
                };
                rebuilt.push((ic, wrapper));
            }
            *creds = rebuilt;
            let submit = *self.shared.auto_submit.lock().unwrap_or_else(|p| p.into_inner());
            // SAFETY: out-pointers validated above.
            unsafe {
                *count = n;
                match submit {
                    Some(i) if (i as u32) < n => {
                        *default = i as u32;
                        *autologon = BOOL(1);
                    }
                    _ => {
                        *default = d;
                        *autologon = a;
                    }
                }
            }
            Ok(())
        })
    }

    fn GetCredentialAt(&self, index: u32) -> windows::core::Result<ICredentialProviderCredential> {
        guard(|| {
            let creds = self.creds.lock().unwrap_or_else(|p| p.into_inner());
            creds.get(index as usize).map(|(_, w)| w.clone()).ok_or_else(|| E_INVALIDARG.into())
        })
    }
}

impl ICredentialProviderSetUserArray_Impl for Provider_Impl {
    fn SetUserArray(&self, users: Option<&ICredentialProviderUserArray>) -> windows::core::Result<()> {
        guard(|| {
            let inner = self.inner()?;
            match inner.cast::<ICredentialProviderSetUserArray>() {
                // SAFETY: forwarding.
                Ok(s) => unsafe { s.SetUserArray(users) },
                Err(_) => Ok(()),
            }
        })
    }
}

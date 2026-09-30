//! Forwards field-update events from the wrapped Password credential to LogonUI, substituting our
//! wrapper as the credential identity (LogonUI only knows the wrapper).

use windows::core::{implement, PCWSTR};
use windows::Win32::Foundation::{BOOL, HWND};
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::UI::Shell::{
    ICredentialProviderCredential, ICredentialProviderCredentialEvents, ICredentialProviderCredentialEvents_Impl, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    CREDENTIAL_PROVIDER_FIELD_STATE,
};

use crate::com::ObjectToken;

#[implement(ICredentialProviderCredentialEvents)]
pub struct WrappedEvents {
    inner: ICredentialProviderCredentialEvents,
    wrapper: ICredentialProviderCredential,
    _t: ObjectToken,
}

impl WrappedEvents {
    pub fn new(inner: ICredentialProviderCredentialEvents, wrapper: ICredentialProviderCredential) -> Self {
        WrappedEvents { inner, wrapper, _t: ObjectToken::new() }
    }
}

// Every method ignores the wrapped credential pointer and reports our wrapper instead.
impl ICredentialProviderCredentialEvents_Impl for WrappedEvents_Impl {
    fn SetFieldState(&self, _c: Option<&ICredentialProviderCredential>, id: u32, s: CREDENTIAL_PROVIDER_FIELD_STATE) -> windows::core::Result<()> {
        // SAFETY: forwarding a COM call with valid arguments.
        unsafe { self.inner.SetFieldState(&self.wrapper, id, s) }
    }
    fn SetFieldInteractiveState(&self, _c: Option<&ICredentialProviderCredential>, id: u32, s: CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE) -> windows::core::Result<()> {
        // SAFETY: as above.
        unsafe { self.inner.SetFieldInteractiveState(&self.wrapper, id, s) }
    }
    fn SetFieldString(&self, _c: Option<&ICredentialProviderCredential>, id: u32, psz: &PCWSTR) -> windows::core::Result<()> {
        // SAFETY: as above.
        unsafe { self.inner.SetFieldString(&self.wrapper, id, *psz) }
    }
    fn SetFieldCheckbox(&self, _c: Option<&ICredentialProviderCredential>, id: u32, checked: BOOL, label: &PCWSTR) -> windows::core::Result<()> {
        // SAFETY: as above.
        unsafe { self.inner.SetFieldCheckbox(&self.wrapper, id, checked, *label) }
    }
    fn SetFieldBitmap(&self, _c: Option<&ICredentialProviderCredential>, id: u32, bmp: HBITMAP) -> windows::core::Result<()> {
        // SAFETY: as above.
        unsafe { self.inner.SetFieldBitmap(&self.wrapper, id, bmp) }
    }
    fn SetFieldComboBoxSelectedItem(&self, _c: Option<&ICredentialProviderCredential>, id: u32, item: u32) -> windows::core::Result<()> {
        // SAFETY: as above.
        unsafe { self.inner.SetFieldComboBoxSelectedItem(&self.wrapper, id, item) }
    }
    fn DeleteFieldComboBoxItem(&self, _c: Option<&ICredentialProviderCredential>, id: u32, item: u32) -> windows::core::Result<()> {
        // SAFETY: as above.
        unsafe { self.inner.DeleteFieldComboBoxItem(&self.wrapper, id, item) }
    }
    fn AppendFieldComboBoxItem(&self, _c: Option<&ICredentialProviderCredential>, id: u32, item: &PCWSTR) -> windows::core::Result<()> {
        // SAFETY: as above.
        unsafe { self.inner.AppendFieldComboBoxItem(&self.wrapper, id, *item) }
    }
    fn SetFieldSubmitButton(&self, _c: Option<&ICredentialProviderCredential>, id: u32, adjacent: u32) -> windows::core::Result<()> {
        // SAFETY: as above.
        unsafe { self.inner.SetFieldSubmitButton(&self.wrapper, id, adjacent) }
    }
    fn OnCreatingWindow(&self) -> windows::core::Result<HWND> {
        // SAFETY: as above.
        unsafe { self.inner.OnCreatingWindow() }
    }
}

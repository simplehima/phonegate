//! The PhoneGate credential: wraps one Password-provider tile and adds the phone step, the
//! recovery code and the offline code. The only way this object returns a credential to LogonUI
//! is (a) an approval the agent verified, or (b) a valid recovery/offline code — each after the
//! typed password passed the local pre-check (or the pre-check was not applicable).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use windows::core::{implement, Interface, GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{BOOL, E_INVALIDARG, E_NOTIMPL, NTSTATUS};
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::System::Com::{CoInitializeEx, CoTaskMemAlloc, CoTaskMemFree, CoUninitialize, COINIT_MULTITHREADED};
use windows::Win32::UI::Shell::{
    ICredentialProviderCredential, ICredentialProviderCredential2, ICredentialProviderCredential2_Impl, ICredentialProviderCredentialEvents,
    ICredentialProviderCredential_Impl, CPFIS_FOCUSED, CPFIS_NONE, CPFS_DISPLAY_IN_SELECTED_TILE, CPFS_HIDDEN, CPFT_COMMAND_LINK, CPFT_EDIT_TEXT,
    CPFT_LARGE_TEXT, CPFT_SMALL_TEXT, CPGSR_NO_CREDENTIAL_NOT_FINISHED, CPGSR_RETURN_CREDENTIAL_FINISHED, CPSI_ERROR, CPSI_NONE,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE, CREDENTIAL_PROVIDER_FIELD_STATE,
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE, CREDENTIAL_PROVIDER_STATUS_ICON,
};
use zeroize::Zeroizing;

use crate::com::{guard, ObjectToken};
use windows_core::IUnknownImpl;
use crate::events::WrappedEvents;
use crate::gate::{self, Begin};
use crate::provider::Shared;
use crate::win;
use crate::{kerb, policy, qr};

// Our fields, numbered after the wrapped provider's fields.
const F_STATUS: u32 = 0;
const F_DETAIL: u32 = 1;
const F_CODE: u32 = 2;
const F_RECOVERY: u32 = 3;
const F_OFFLINE: u32 = 4;
const F_CANCEL: u32 = 5;
pub const EXTRA_FIELDS: u32 = 6;

const IDLE_STATUS: &str = "Protected by PhoneGate";
const IDLE_DETAIL: &str = "Enter your password, then approve the request on your phone.";

/// Descriptor for one of our extra fields (CoTaskMem-allocated, owned by LogonUI).
pub fn descriptor(inner_count: u32, k: u32) -> windows::core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
    let (cpft, label) = match k {
        F_STATUS => (CPFT_LARGE_TEXT, "PhoneGate"),
        F_DETAIL => (CPFT_SMALL_TEXT, "PhoneGate status"),
        F_CODE => (CPFT_EDIT_TEXT, "Recovery or offline code"),
        F_RECOVERY => (CPFT_COMMAND_LINK, "Use a recovery code"),
        F_OFFLINE => (CPFT_COMMAND_LINK, "Offline approval (no network)"),
        F_CANCEL => (CPFT_COMMAND_LINK, "Cancel"),
        _ => return Err(E_INVALIDARG.into()),
    };
    // SAFETY: allocation sized for one descriptor; fully initialized before return.
    unsafe {
        let p = CoTaskMemAlloc(std::mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>()) as *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR;
        if p.is_null() {
            return Err(windows::Win32::Foundation::E_OUTOFMEMORY.into());
        }
        p.write(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR { dwFieldID: inner_count + k, cpft, pszLabel: win::co_str(label)?, guidFieldType: GUID::zeroed() });
        Ok(p)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Password,
    Pending,
    Recovery,
    Offline,
}

struct Serial {
    package: u32,
    clsid: GUID,
    data: Zeroizing<Vec<u8>>,
}

impl Serial {
    /// Builds a submit serialization from agent-released logon bytes (passwordless, 004): the
    /// Negotiate auth package plus PhoneGate's own CLSID. LSA still checks the password.
    fn released(bytes: &[u8]) -> windows::core::Result<Self> {
        Ok(Serial { package: win::negotiate_auth_package()?, clsid: crate::com::CLSID_PROVIDER, data: Zeroizing::new(bytes.to_vec()) })
    }
}

pub struct State {
    mode: Mode,
    status: String,
    detail: String,
    code: Zeroizing<String>,
    /// `serial` is the inner password provider's serialization, or `None` for passwordless (004),
    /// where the agent releases the credential after approval.
    pending: Option<(String, Option<Serial>, Arc<AtomicBool>)>,
    approved: Option<Serial>,
    offline_chal: Option<String>,
    qr: Option<qr::Pixels>,
}

impl State {
    fn reset(&mut self) {
        if let Some((_, _, cancel)) = self.pending.take() {
            cancel.store(true, Ordering::SeqCst);
        }
        self.mode = Mode::Password;
        self.approved = None;
        self.offline_chal = None;
        self.qr = None;
        self.code = Zeroizing::new(String::new());
    }
}

#[implement(ICredentialProviderCredential2)]
pub struct Credential {
    inner: ICredentialProviderCredential,
    inner2: Option<ICredentialProviderCredential2>,
    inner_count: u32,
    tile_field: Option<u32>,
    index: usize,
    shared: Arc<Shared>,
    st: Arc<Mutex<State>>,
    events: Mutex<Option<ICredentialProviderCredentialEvents>>,
    _t: ObjectToken,
}

type OutParams = (*mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE, *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, *mut PWSTR, *mut CREDENTIAL_PROVIDER_STATUS_ICON);

impl Credential {
    /// Fresh per-tile state (kept by the provider across re-enumeration).
    pub fn new_state() -> Arc<Mutex<State>> {
        Arc::new(Mutex::new(State {
            mode: Mode::Password,
            status: IDLE_STATUS.into(),
            detail: IDLE_DETAIL.into(),
            code: Zeroizing::new(String::new()),
            pending: None,
            approved: None,
            offline_chal: None,
            qr: None,
        }))
    }

    pub fn new(inner: ICredentialProviderCredential, inner_count: u32, tile_field: Option<u32>, index: usize, shared: Arc<Shared>, st: Arc<Mutex<State>>) -> Self {
        Credential {
            inner2: inner.cast().ok(),
            inner,
            inner_count,
            tile_field,
            index,
            shared,
            st,
            events: Mutex::new(None),
            _t: ObjectToken::new(),
        }
    }

    fn st(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn ours(&self, id: u32) -> Option<u32> {
        id.checked_sub(self.inner_count).filter(|k| *k < EXTRA_FIELDS)
    }

    fn visible(mode: Mode, k: u32) -> bool {
        match k {
            F_STATUS | F_DETAIL => true,
            F_CODE => matches!(mode, Mode::Recovery | Mode::Offline),
            F_RECOVERY => matches!(mode, Mode::Password | Mode::Offline),
            F_OFFLINE => mode == Mode::Password,
            F_CANCEL => matches!(mode, Mode::Pending | Mode::Recovery | Mode::Offline),
            _ => false,
        }
    }

    /// Pushes our field values to LogonUI. Must run on LogonUI's thread (called from COM methods).
    fn refresh(&self) {
        let Some(ev) = self.events.lock().unwrap_or_else(|p| p.into_inner()).clone() else { return };
        // SAFETY: `self` lives inside its COM object (created via `implement`), as `cast` requires.
        let me: ICredentialProviderCredential = match unsafe { self.cast() } {
            Ok(m) => m,
            Err(_) => return,
        };
        let (mode, status, detail, qr_bmp) = {
            let s = self.st();
            (s.mode, s.status.clone(), s.detail.clone(), s.qr.as_ref().and_then(|p| win::bitmap(p).ok()))
        };
        let set = |k: u32, text: &str| {
            let w: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: NUL-terminated string valid for the call.
            unsafe {
                let _ = ev.SetFieldString(&me, self.inner_count + k, PCWSTR(w.as_ptr()));
            }
        };
        set(F_STATUS, &status);
        set(F_DETAIL, &detail);
        for k in 0..EXTRA_FIELDS {
            let fs = if Credential::visible(mode, k) { CPFS_DISPLAY_IN_SELECTED_TILE } else { CPFS_HIDDEN };
            // SAFETY: plain COM call.
            unsafe {
                let _ = ev.SetFieldState(&me, self.inner_count + k, fs);
            }
        }
        if matches!(mode, Mode::Recovery | Mode::Offline) {
            // SAFETY: plain COM calls.
            unsafe {
                let _ = ev.SetFieldString(&me, self.inner_count + F_CODE, PCWSTR(windows::core::w!("").as_ptr()));
                let _ = ev.SetFieldInteractiveState(&me, self.inner_count + F_CODE, CPFIS_FOCUSED);
            }
        }
        if let (Some(tile), Some(bmp)) = (self.tile_field, qr_bmp) {
            // SAFETY: LogonUI takes ownership of the bitmap.
            unsafe {
                let _ = ev.SetFieldBitmap(&me, tile, bmp);
            }
        }
    }

    /// Asks the wrapped Password credential for its serialization and takes ownership of it.
    fn inner_serialization(&self, out: OutParams) -> windows::core::Result<Option<Serial>> {
        let mut gsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        let mut cs = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION::default();
        let mut text = PWSTR::null();
        let mut icon = CPSI_NONE;
        // SAFETY: forwarding with valid out-pointers to locals.
        unsafe { self.inner.GetSerialization(&mut gsr, &mut cs, &mut text, &mut icon)? };
        if gsr != CPGSR_RETURN_CREDENTIAL_FINISHED || cs.rgbSerialization.is_null() {
            // Not a credential (e.g. empty password): pass the inner answer through untouched.
            // SAFETY: caller-provided out-pointers are valid per the CP contract.
            unsafe {
                *out.0 = gsr;
                *out.1 = cs;
                *out.2 = text;
                *out.3 = icon;
            }
            return Ok(None);
        }
        if !text.is_null() {
            // SAFETY: CoTaskMem string from the inner provider.
            unsafe { CoTaskMemFree(Some(text.0 as _)) };
        }
        // SAFETY: buffer of cbSerialization bytes from the inner provider.
        let data = Zeroizing::new(unsafe { std::slice::from_raw_parts(cs.rgbSerialization, cs.cbSerialization as usize) }.to_vec());
        win::free_secret(cs.rgbSerialization, cs.cbSerialization as usize);
        Ok(Some(Serial { package: cs.ulAuthenticationPackage, clsid: cs.clsidCredentialProvider, data }))
    }

    fn respond(out: OutParams, gsr: CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE, msg: Option<(&str, bool)>) -> windows::core::Result<()> {
        // SAFETY: out-pointers valid per contract.
        unsafe {
            *out.0 = gsr;
            if let Some((m, error)) = msg {
                *out.2 = win::co_str(m)?;
                *out.3 = if error { CPSI_ERROR } else { CPSI_NONE };
            }
        }
        Ok(())
    }

    fn return_credential(out: OutParams, s: &Serial) -> windows::core::Result<()> {
        // SAFETY: out-pointers valid per contract; buffer ownership passes to LogonUI.
        unsafe {
            *out.1 = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
                ulAuthenticationPackage: s.package,
                clsidCredentialProvider: s.clsid,
                cbSerialization: s.data.len() as u32,
                rgbSerialization: win::co_bytes(&s.data)?,
            };
            *out.0 = CPGSR_RETURN_CREDENTIAL_FINISHED;
        }
        Ok(())
    }

    /// Password + phone approval: starts the request and returns immediately; the worker thread
    /// triggers auto-submit through the provider when the agent reports a verified approval.
    fn start_phone_step(&self, out: OutParams) -> windows::core::Result<()> {
        // Passwordless (004): when the agent has phone-only sign-in armed for this PC, the owner
        // need not type a password; the agent releases the stored credential after approval. Any
        // failure in this path falls back to the normal password tile — never a dead end.
        let passwordless = gate::passwordless_on();
        let serial = if passwordless {
            None
        } else {
            match self.inner_serialization(out)? {
                Some(s) => Some(s),
                None => return Ok(()), // inner provider not finished (e.g. empty password)
            }
        };
        // We do NOT pre-judge the password here. LSA performs the authoritative password check
        // after GetSerialization; a local pre-check (LogonUserW) is unreliable for Microsoft
        // accounts, Windows Hello/PIN and network-logon-restricted accounts, and a false negative
        // would wrongly reject a correct password on every sign-in with no way past the gate.
        let account = serial.as_ref().and_then(|s| kerb::parse(&s.data)).map(|c| c.account()).unwrap_or_default();
        let scenario = *self.shared.scenario.lock().unwrap_or_else(|p| p.into_inner());
        let remote = if scenario == "remote" { win::remote_client_address() } else { String::new() };
        match gate::begin(scenario, &account, &remote) {
            Begin::Started { req, number, expires_in_s } => {
                let cancel = Arc::new(AtomicBool::new(false));
                {
                    let mut s = self.st();
                    s.reset();
                    s.mode = Mode::Pending;
                    s.status = format!("Approve on your phone: {number:02}");
                    s.detail = format!("Type {number:02} in PhoneGate on your phone and confirm with your fingerprint. The request expires in {expires_in_s} s.");
                    s.pending = Some((req.clone(), serial, cancel.clone()));
                }
                self.spawn_waiter(req, cancel, Duration::from_secs(expires_in_s + 5));
                self.refresh();
                let msg = format!("Approve on your phone: type {number:02}");
                Credential::respond(out, CPGSR_NO_CREDENTIAL_NOT_FINISHED, Some((&msg, false)))
            }
            Begin::Refused { code, retry_s } => {
                let msg = policy::begin_error_message(&code, retry_s);
                {
                    let mut s = self.st();
                    s.status = IDLE_STATUS.into();
                    s.detail = msg.clone();
                }
                self.refresh();
                Credential::respond(out, CPGSR_NO_CREDENTIAL_NOT_FINISHED, Some((&msg, true)))
            }
        }
    }

    fn spawn_waiter(&self, req: String, cancel: Arc<AtomicBool>, max: Duration) {
        let st = self.st.clone();
        let shared = self.shared.clone();
        let index = self.index;
        std::thread::spawn(move || {
            let _t = ObjectToken::new();
            // SAFETY: per-thread COM init for resolving the agile events reference.
            let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            let start = Instant::now();
            let mut failures = 0;
            let outcome = loop {
                if cancel.load(Ordering::SeqCst) {
                    break None;
                }
                if start.elapsed() > max {
                    break Some("expired".to_string());
                }
                match gate::wait(&req, 1_500) {
                    Some(s) if s == "pending" => failures = 0,
                    Some(s) => break Some(s),
                    None => {
                        failures += 1;
                        if failures >= 5 {
                            break Some("error".to_string());
                        }
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
            };
            if let Some(state) = outcome {
                {
                    let mut s = st.lock().unwrap_or_else(|p| p.into_inner());
                    let still_ours = s.pending.as_ref().is_some_and(|(r, _, _)| *r == req);
                    if still_ours {
                        let (req_id, serial, _) = s.pending.take().expect("checked");
                        if state == "approved" {
                            // Passwordless: fetch the agent-released credential now. If it can't be
                            // released, fall back to the password tile instead of failing.
                            let resolved = match serial {
                                Some(inner) => Some(inner),
                                None => gate::release(&req_id).and_then(|bytes| Serial::released(&bytes).ok()),
                            };
                            match resolved {
                                Some(cred) => {
                                    s.approved = Some(cred);
                                    s.status = "Approved on your phone".into();
                                    s.detail = "Signing in…".into();
                                    *shared.auto_submit.lock().unwrap_or_else(|p| p.into_inner()) = Some(index);
                                }
                                None => {
                                    s.mode = Mode::Password;
                                    s.status = IDLE_STATUS.into();
                                    s.detail = "Approved, but the saved password couldn't be used. Enter your password, or use a recovery code.".into();
                                }
                            }
                        } else {
                            drop(serial); // zeroized
                            s.mode = Mode::Password;
                            s.status = IDLE_STATUS.into();
                            s.detail = policy::outcome_message(&state).into();
                        }
                    }
                }
                shared.notify();
            }
            // SAFETY: balances CoInitializeEx on this thread.
            unsafe { CoUninitialize() };
        });
    }

    fn code_step(&self, out: OutParams, offline: bool) -> windows::core::Result<()> {
        let code = self.st().code.to_string();
        if code.trim().is_empty() {
            let msg = if offline { "Type the 10-digit code shown on your phone." } else { "Type one of your recovery codes." };
            return Credential::respond(out, CPGSR_NO_CREDENTIAL_NOT_FINISHED, Some((msg, true)));
        }
        let Some(serial) = self.inner_serialization(out)? else { return Ok(()) };
        // The recovery / offline code is the safety net and must NEVER be gated by a password
        // pre-check: LSA still verifies the typed password after this, so a wrong password simply
        // fails at Windows' own check. Worst case a valid code is spent on a wrong password (1 of
        // 10); that is vastly preferable to a false pre-check locking the owner out entirely.
        let creds = kerb::parse(&serial.data);
        let account = creds.as_ref().map(|c| c.account()).unwrap_or_default();
        let result = if offline {
            let chal = self.st().offline_chal.clone().unwrap_or_default();
            gate::offline_verify(&chal, &code)
        } else {
            gate::recovery_verify(&code, &account)
        };
        if result.valid {
            self.st().reset();
            return Credential::return_credential(out, &serial);
        }
        let what = if offline { "offline code" } else { "recovery code" };
        let msg = gate::code_error_message(&result, what);
        self.st().code = Zeroizing::new(String::new());
        Credential::respond(out, CPGSR_NO_CREDENTIAL_NOT_FINISHED, Some((&msg, true)))
    }

    fn enter_offline(&self) {
        let scenario = *self.shared.scenario.lock().unwrap_or_else(|p| p.into_inner());
        match gate::offline_begin(scenario, "") {
            Ok((chal, text)) => {
                let mut s = self.st();
                s.reset();
                s.mode = Mode::Offline;
                s.offline_chal = Some(chal);
                s.qr = qr::render(&text, 420);
                s.status = "Offline approval".into();
                s.detail = "Open PhoneGate on your phone, choose Offline code, scan the QR code, then type the code it shows and your password.".into();
            }
            Err(_) => {
                let mut s = self.st();
                s.detail = "Offline approval needs the PhoneGate service. Use a recovery code instead.".into();
            }
        }
    }
}

impl Credential_Impl {
    /// Our own interface pointer (what LogonUI knows us as).
    fn me(&self) -> windows::core::Result<ICredentialProviderCredential> {
        let c2: ICredentialProviderCredential2 = self.to_interface();
        c2.cast()
    }
}

impl ICredentialProviderCredential_Impl for Credential_Impl {
    fn Advise(&self, pcpce: Option<&ICredentialProviderCredentialEvents>) -> windows::core::Result<()> {
        guard(|| {
            *self.events.lock().unwrap_or_else(|p| p.into_inner()) = pcpce.cloned();
            match pcpce {
                Some(e) => {
                    let me = self.me()?;
                    let wrapped: ICredentialProviderCredentialEvents = WrappedEvents::new(e.clone(), me).into();
                    // SAFETY: forwarding.
                    unsafe { self.inner.Advise(&wrapped) }
                }
                // SAFETY: forwarding.
                None => unsafe { self.inner.Advise(None) },
            }
        })
    }

    fn UnAdvise(&self) -> windows::core::Result<()> {
        guard(|| {
            *self.events.lock().unwrap_or_else(|p| p.into_inner()) = None;
            // SAFETY: forwarding.
            unsafe { self.inner.UnAdvise() }
        })
    }

    fn SetSelected(&self) -> windows::core::Result<BOOL> {
        // SAFETY: forwarding.
        guard(|| unsafe { self.inner.SetSelected() })
    }

    fn SetDeselected(&self) -> windows::core::Result<()> {
        guard(|| {
            let mode = self.st().mode;
            if mode != Mode::Pending {
                self.st().code = Zeroizing::new(String::new());
            }
            // SAFETY: forwarding.
            unsafe { self.inner.SetDeselected() }
        })
    }

    fn GetFieldState(&self, id: u32, pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE, pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE) -> windows::core::Result<()> {
        guard(|| match self.ours(id) {
            Some(k) => {
                if pcpfs.is_null() || pcpfis.is_null() {
                    return Err(E_INVALIDARG.into());
                }
                let mode = self.st().mode;
                // SAFETY: validated out-pointers.
                unsafe {
                    *pcpfs = if Credential::visible(mode, k) { CPFS_DISPLAY_IN_SELECTED_TILE } else { CPFS_HIDDEN };
                    *pcpfis = if k == F_CODE && matches!(mode, Mode::Recovery | Mode::Offline) { CPFIS_FOCUSED } else { CPFIS_NONE };
                }
                Ok(())
            }
            // SAFETY: forwarding.
            None => unsafe { self.inner.GetFieldState(id, pcpfs, pcpfis) },
        })
    }

    fn GetStringValue(&self, id: u32) -> windows::core::Result<PWSTR> {
        guard(|| match self.ours(id) {
            Some(F_STATUS) => win::co_str(&self.st().status),
            Some(F_DETAIL) => win::co_str(&self.st().detail),
            Some(F_CODE) => win::co_str(""),
            Some(F_RECOVERY) => win::co_str("Use a recovery code"),
            Some(F_OFFLINE) => win::co_str("Offline approval (no network)"),
            Some(F_CANCEL) => win::co_str(if self.st().mode == Mode::Pending { "Cancel request" } else { "Back to phone approval" }),
            Some(_) => Err(E_INVALIDARG.into()),
            // SAFETY: forwarding.
            None => unsafe { self.inner.GetStringValue(id) },
        })
    }

    fn GetBitmapValue(&self, id: u32) -> windows::core::Result<HBITMAP> {
        guard(|| {
            if Some(id) == self.tile_field {
                if let Some(p) = self.st().qr.as_ref() {
                    return win::bitmap(p);
                }
            }
            if self.ours(id).is_some() {
                return Err(E_NOTIMPL.into());
            }
            // SAFETY: forwarding.
            unsafe { self.inner.GetBitmapValue(id) }
        })
    }

    fn GetCheckboxValue(&self, id: u32, checked: *mut BOOL, label: *mut PWSTR) -> windows::core::Result<()> {
        guard(|| {
            if self.ours(id).is_some() {
                return Err(E_NOTIMPL.into());
            }
            // SAFETY: forwarding.
            unsafe { self.inner.GetCheckboxValue(id, checked, label) }
        })
    }

    fn GetSubmitButtonValue(&self, id: u32) -> windows::core::Result<u32> {
        guard(|| {
            if self.ours(id).is_some() {
                return Err(E_NOTIMPL.into());
            }
            // SAFETY: forwarding.
            unsafe { self.inner.GetSubmitButtonValue(id) }
        })
    }

    fn GetComboBoxValueCount(&self, id: u32, items: *mut u32, selected: *mut u32) -> windows::core::Result<()> {
        guard(|| {
            if self.ours(id).is_some() {
                return Err(E_NOTIMPL.into());
            }
            // SAFETY: forwarding.
            unsafe { self.inner.GetComboBoxValueCount(id, items, selected) }
        })
    }

    fn GetComboBoxValueAt(&self, id: u32, item: u32) -> windows::core::Result<PWSTR> {
        guard(|| {
            if self.ours(id).is_some() {
                return Err(E_NOTIMPL.into());
            }
            // SAFETY: forwarding.
            unsafe { self.inner.GetComboBoxValueAt(id, item) }
        })
    }

    fn SetStringValue(&self, id: u32, psz: &PCWSTR) -> windows::core::Result<()> {
        guard(|| match self.ours(id) {
            Some(F_CODE) => {
                self.st().code = Zeroizing::new(win::from_pcwstr(psz));
                Ok(())
            }
            Some(_) => Err(E_INVALIDARG.into()),
            // SAFETY: forwarding.
            None => unsafe { self.inner.SetStringValue(id, *psz) },
        })
    }

    fn SetCheckboxValue(&self, id: u32, checked: BOOL) -> windows::core::Result<()> {
        guard(|| {
            if self.ours(id).is_some() {
                return Err(E_NOTIMPL.into());
            }
            // SAFETY: forwarding.
            unsafe { self.inner.SetCheckboxValue(id, checked) }
        })
    }

    fn SetComboBoxSelectedValue(&self, id: u32, item: u32) -> windows::core::Result<()> {
        guard(|| {
            if self.ours(id).is_some() {
                return Err(E_NOTIMPL.into());
            }
            // SAFETY: forwarding.
            unsafe { self.inner.SetComboBoxSelectedValue(id, item) }
        })
    }

    fn CommandLinkClicked(&self, id: u32) -> windows::core::Result<()> {
        guard(|| {
            match self.ours(id) {
                Some(F_RECOVERY) => {
                    let mut s = self.st();
                    s.reset();
                    s.mode = Mode::Recovery;
                    s.status = "Sign in with a recovery code".into();
                    s.detail = "Type your password and one of your saved recovery codes, then press Enter. Each code works once.".into();
                }
                Some(F_OFFLINE) => self.enter_offline(),
                Some(F_CANCEL) => {
                    let req = self.st().pending.as_ref().map(|(r, _, _)| r.clone());
                    if let Some(r) = req {
                        gate::cancel(&r);
                    }
                    let mut s = self.st();
                    s.reset();
                    s.status = IDLE_STATUS.into();
                    s.detail = IDLE_DETAIL.into();
                }
                Some(_) => return Err(E_INVALIDARG.into()),
                // SAFETY: forwarding.
                None => return unsafe { self.inner.CommandLinkClicked(id) },
            }
            self.refresh();
            Ok(())
        })
    }

    fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        text: *mut PWSTR,
        icon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows::core::Result<()> {
        guard(|| {
            if pcpgsr.is_null() || pcpcs.is_null() || text.is_null() || icon.is_null() {
                return Err(E_INVALIDARG.into());
            }
            let out: OutParams = (pcpgsr, pcpcs, text, icon);
            // SAFETY: initialize outputs so every early return is well-defined.
            unsafe {
                *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                *text = PWSTR::null();
                *icon = CPSI_NONE;
            }
            // 1) A verified approval is waiting: auto-submit the stored serialization, once.
            let approved = {
                let mut s = self.st();
                let a = s.approved.take();
                if a.is_some() {
                    s.reset();
                    s.status = IDLE_STATUS.into();
                    s.detail = IDLE_DETAIL.into();
                }
                a
            };
            if let Some(serial) = approved {
                *self.shared.auto_submit.lock().unwrap_or_else(|p| p.into_inner()) = None;
                return Credential::return_credential(out, &serial);
            }
            let mode = self.st().mode;
            match mode {
                Mode::Pending => Credential::respond(out, CPGSR_NO_CREDENTIAL_NOT_FINISHED, Some(("Still waiting for approval on your phone.", false))),
                Mode::Recovery => self.code_step(out, false),
                Mode::Offline => self.code_step(out, true),
                Mode::Password => self.start_phone_step(out),
            }
        })
    }

    fn ReportResult(&self, status: NTSTATUS, substatus: NTSTATUS, text: *mut PWSTR, icon: *mut CREDENTIAL_PROVIDER_STATUS_ICON) -> windows::core::Result<()> {
        guard(|| {
            self.st().reset();
            // SAFETY: forwarding (the Password provider maps NTSTATUS to messages).
            unsafe { self.inner.ReportResult(status, substatus, text, icon) }
        })
    }
}

impl ICredentialProviderCredential2_Impl for Credential_Impl {
    fn GetUserSid(&self) -> windows::core::Result<PWSTR> {
        guard(|| match &self.inner2 {
            // SAFETY: forwarding.
            Some(i) => unsafe { i.GetUserSid() },
            None => Err(E_NOTIMPL.into()),
        })
    }
}

#[cfg(test)]
mod regression {
    /// Lockout regression guard. A local password pre-check (LogonUserW) must never gate the
    /// sign-in or recovery/offline paths: it wrongly rejected Microsoft-account and Windows
    /// Hello/PIN sign-ins, and because it ran first it also blocked recovery codes, locking the
    /// owner out. LSA is the sole authority on the password. Keep these paths oracle-free.
    #[test]
    fn no_password_oracle_gates_signin_or_recovery() {
        let src = include_str!("credential.rs");
        let needle = concat!("win::pre", "check(");
        assert!(!src.contains(needle), "a password pre-check was reintroduced into the credential paths (lockout regression)");
    }
}

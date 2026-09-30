//! Named-pipe servers with explicit DACLs (contracts/agent-pipes.md).

use std::fs::File;
use std::os::windows::io::FromRawHandle;
use std::sync::Arc;

use pg_core::ipc::{read_frame, write_frame};
use pg_core::{Error, Result};
use windows::core::HSTRING;
use windows::Win32::Foundation::{LocalFree, ERROR_PIPE_CONNECTED, HLOCAL, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

/// Gate pipe: LocalSystem only (LogonUI).
pub const GATE_SDDL: &str = "D:P(A;;GA;;;SY)";
/// Control pipe: LocalSystem and elevated Administrators (companion app).
pub const CONTROL_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

pub type Handler = Arc<dyn Fn(Vec<u8>) -> Vec<u8> + Send + Sync>;

struct Sd(PSECURITY_DESCRIPTOR);
impl Drop for Sd {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            let _ = LocalFree(HLOCAL(self.0 .0));
        }
    }
}

fn security_descriptor(sddl: &str) -> Result<Sd> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: valid wide string; out-pointer is a local.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(&HSTRING::from(sddl), SDDL_REVISION_1, &mut sd, None).map_err(|e| Error::Io(format!("sddl: {e}")))?;
    }
    Ok(Sd(sd))
}

/// Serves `name` forever, one thread per connection. The first instance is created with
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`, so the service refuses to start if another process squatted
/// the name.
pub fn serve(name: &str, sddl: &str, handler: Handler) -> Result<()> {
    let sd = security_descriptor(sddl)?;
    let wname = HSTRING::from(name);
    let mut first = true;
    loop {
        let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0 .0, bInheritHandle: false.into() };
        let open_mode = if first { PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE } else { PIPE_ACCESS_DUPLEX };
        // SAFETY: parameters follow the CreateNamedPipeW contract; `sa`/`sd` outlive the call.
        let h = unsafe {
            CreateNamedPipeW(
                &wname,
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                Some(&sa),
            )
        };
        if h == INVALID_HANDLE_VALUE || h.is_invalid() {
            return Err(Error::Io(format!("cannot create pipe {name}: {}", windows::core::Error::from_win32())));
        }
        first = false;
        // SAFETY: blocking connect on a handle we own.
        let connected = unsafe { ConnectNamedPipe(h, None) };
        if let Err(e) = connected {
            if e.code() != ERROR_PIPE_CONNECTED.to_hresult() {
                // SAFETY: handle is ours; wrap to close.
                drop(unsafe { File::from_raw_handle(h.0 as _) });
                continue;
            }
        }
        let handler = handler.clone();
        let raw = h.0 as usize;
        std::thread::spawn(move || {
            // SAFETY: ownership of the pipe handle moves into this File.
            let mut f = unsafe { File::from_raw_handle(raw as _) };
            if let Ok(req) = read_frame(&mut f) {
                let resp = handler(req);
                let _ = write_frame(&mut f, &resp);
                // SAFETY: valid handle owned by `f`.
                unsafe {
                    let hh = windows::Win32::Foundation::HANDLE(raw as _);
                    let _ = FlushFileBuffers(hh);
                    let _ = DisconnectNamedPipe(hh);
                }
            }
        });
    }
}

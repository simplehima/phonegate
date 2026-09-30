//! Local IPC framing (contracts/agent-pipes.md): `u32` little-endian length + UTF-8 JSON.

use std::io::{Read, Write};

use crate::error::{Error, Result};

pub const MAX_FRAME: usize = 64 * 1024;
pub const GATE_PIPE: &str = r"\\.\pipe\phonegate.gate";
pub const CONTROL_PIPE: &str = r"\\.\pipe\phonegate.control";

pub fn write_frame(w: &mut impl Write, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME {
        return Err(Error::Io("frame too large".into()));
    }
    w.write_all(&(data.len() as u32).to_le_bytes())?;
    w.write_all(data)?;
    w.flush()?;
    Ok(())
}

pub fn read_frame(r: &mut impl Read) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(Error::Io("frame too large".into()));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Named-pipe client that refuses to talk to a server that is not running as LocalSystem, so a
/// squatting user-mode process cannot impersonate the agent.
#[cfg(windows)]
pub mod client {
    use std::fs::File;
    use std::os::windows::io::FromRawHandle;

    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, IsWellKnownSid, TokenUser, WinLocalSystemSid, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT};
    use windows::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
    use windows::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};

    use super::{read_frame, write_frame};
    use crate::error::{Error, Result};

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: handle was returned by a successful Open* call and is closed exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn server_is_system(pipe: HANDLE) -> Result<bool> {
        // SAFETY: plain Win32 calls on handles we own; buffers are sized per the API contract.
        unsafe {
            let mut pid = 0u32;
            GetNamedPipeServerProcessId(pipe, &mut pid).map_err(|e| Error::Io(e.to_string()))?;
            let proc = OwnedHandle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| Error::Io(e.to_string()))?);
            let mut tok = HANDLE::default();
            OpenProcessToken(proc.0, TOKEN_QUERY, &mut tok).map_err(|e| Error::Io(e.to_string()))?;
            let tok = OwnedHandle(tok);
            let mut len = 0u32;
            let _ = GetTokenInformation(tok.0, TokenUser, None, 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            GetTokenInformation(tok.0, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len).map_err(|e| Error::Io(e.to_string()))?;
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            Ok(IsWellKnownSid(user.User.Sid, WinLocalSystemSid).as_bool())
        }
    }

    /// Sends one request and returns the response frame.
    pub fn call(pipe_name: &str, request: &[u8], connect_timeout_ms: u32) -> Result<Vec<u8>> {
        let name = HSTRING::from(pipe_name);
        // SAFETY: Win32 calls with a valid, NUL-terminated wide string.
        let handle = unsafe {
            let _ = WaitNamedPipeW(PCWSTR(name.as_ptr()), connect_timeout_ms);
            CreateFileW(
                PCWSTR(name.as_ptr()),
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                // Identification-level impersonation only: the server cannot act as us.
                FILE_FLAGS_AND_ATTRIBUTES(SECURITY_SQOS_PRESENT.0 | SECURITY_IDENTIFICATION.0),
                None,
            )
            .map_err(|e| Error::Io(format!("agent unavailable: {e}")))?
        };
        if !server_is_system(handle).unwrap_or(false) {
            // SAFETY: closing the handle we just opened.
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Err(Error::Verify("pipe server is not LocalSystem"));
        }
        // SAFETY: we own `handle`; File takes ownership and closes it on drop.
        let mut f = unsafe { File::from_raw_handle(handle.0 as _) };
        write_frame(&mut f, request)?;
        read_frame(&mut f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_and_limits() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"op\":\"status\"}").unwrap();
        assert_eq!(&buf[..4], &15u32.to_le_bytes());
        assert_eq!(read_frame(&mut buf.as_slice()).unwrap(), b"{\"op\":\"status\"}");
        let mut big = Vec::new();
        big.extend_from_slice(&((MAX_FRAME + 1) as u32).to_le_bytes());
        assert!(read_frame(&mut big.as_slice()).is_err());
        assert!(write_frame(&mut Vec::new(), &vec![0; MAX_FRAME + 1]).is_err());
    }
}

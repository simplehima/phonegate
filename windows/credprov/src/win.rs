//! Small Win32 helpers used by the COM objects.

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_LOGON_FAILURE, HANDLE};
use windows::Win32::Graphics::Gdi::{CreateDIBSection, GetDC, ReleaseDC, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HBITMAP};
use windows::Win32::Security::Credentials::{CredIsProtectedW, CredUnprotectW, CRED_PROTECTION_TYPE};
use windows::Win32::Security::{LogonUserW, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT};
use windows::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows::Win32::System::RemoteDesktop::{WTSClientAddress, WTSFreeMemory, WTSQuerySessionInformationW, WTS_CLIENT_ADDRESS, WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION};
use windows::Win32::UI::Shell::SHStrDupW;
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION};
use zeroize::Zeroizing;

use crate::kerb::Credentials;
use crate::qr::Pixels;

/// CoTaskMem-allocated copy of `s` (ownership passes to the caller, per the CP contract).
pub fn co_str(s: &str) -> windows::core::Result<PWSTR> {
    let w: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `w` is NUL-terminated and outlives the call.
    unsafe { SHStrDupW(PCWSTR(w.as_ptr())) }
}

pub fn from_pcwstr(p: &PCWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: LogonUI passes a valid NUL-terminated string.
    unsafe { p.to_string().unwrap_or_default() }
}

/// Copies `data` into a CoTaskMem buffer (for returning a serialization to LogonUI).
pub fn co_bytes(data: &[u8]) -> windows::core::Result<*mut u8> {
    // SAFETY: allocation of the requested size; copy stays within bounds.
    unsafe {
        let p = CoTaskMemAlloc(data.len()) as *mut u8;
        if p.is_null() {
            return Err(windows::Win32::Foundation::E_OUTOFMEMORY.into());
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
        Ok(p)
    }
}

/// Zeroes and frees a CoTaskMem buffer received from the wrapped provider.
pub fn free_secret(p: *mut u8, len: usize) {
    if p.is_null() {
        return;
    }
    // SAFETY: buffer of `len` bytes allocated with CoTaskMemAlloc by the wrapped provider.
    unsafe {
        std::ptr::write_bytes(p, 0, len);
        CoTaskMemFree(Some(p as _));
    }
}

pub fn is_remote_session() -> bool {
    // SAFETY: simple query.
    unsafe { GetSystemMetrics(SM_REMOTESESSION) != 0 }
}

/// IPv4/IPv6 address of the RDP client for the current session, if any.
pub fn remote_client_address() -> String {
    // SAFETY: WTS allocates the buffer; we read it as WTS_CLIENT_ADDRESS and free it.
    unsafe {
        let mut buf = PWSTR::null();
        let mut len = 0u32;
        if WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSClientAddress, &mut buf, &mut len).is_err() || buf.is_null() {
            return String::new();
        }
        let out = if (len as usize) >= std::mem::size_of::<WTS_CLIENT_ADDRESS>() {
            let a = &*(buf.0 as *const WTS_CLIENT_ADDRESS);
            match a.AddressFamily {
                2 => format!("{}.{}.{}.{}", a.Address[2], a.Address[3], a.Address[4], a.Address[5]),
                23 => a.Address[2..18].chunks(2).map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]]))).collect::<Vec<_>>().join(":"),
                _ => String::new(),
            }
        } else {
            String::new()
        };
        WTSFreeMemory(buf.0 as _);
        out
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Precheck {
    Ok,
    WrongPassword,
    Skipped,
}

/// Validates the typed credentials locally with a network-type logon (no session is created).
/// Only a definite `ERROR_LOGON_FAILURE` counts as a wrong password; anything else defers to LSA.
pub fn precheck(c: &Credentials) -> Precheck {
    if !c.precheck_supported() {
        return Precheck::Skipped;
    }
    let mut pw: Zeroizing<Vec<u16>> = Zeroizing::new(c.password.to_vec());
    pw.push(0);
    // Unprotect if the wrapped provider protected the password (CredUI-style).
    // SAFETY: NUL-terminated buffers; output buffer sized from the first call.
    unsafe {
        let mut prot = CRED_PROTECTION_TYPE(0);
        if CredIsProtectedW(PCWSTR(pw.as_ptr()), &mut prot).is_ok() && prot.0 != 0 {
            let mut n = 0u32;
            let _ = CredUnprotectW(false, &pw[..pw.len() - 1], PWSTR::null(), &mut n);
            let mut out: Zeroizing<Vec<u16>> = Zeroizing::new(vec![0u16; n as usize + 1]);
            if CredUnprotectW(false, &pw[..pw.len() - 1], PWSTR(out.as_mut_ptr()), &mut n).is_err() {
                return Precheck::Skipped;
            }
            out.truncate(n as usize);
            if out.last() != Some(&0) {
                out.push(0);
            }
            pw = out;
        }
    }
    let user: Vec<u16> = c.user.encode_utf16().chain(std::iter::once(0)).collect();
    let domain: Vec<u16> = c.domain.encode_utf16().chain(std::iter::once(0)).collect();
    let mut token = HANDLE::default();
    // SAFETY: NUL-terminated inputs; token closed on success.
    unsafe {
        match LogonUserW(PCWSTR(user.as_ptr()), PCWSTR(domain.as_ptr()), PCWSTR(pw.as_ptr()), LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &mut token) {
            Ok(()) => {
                let _ = CloseHandle(token);
                Precheck::Ok
            }
            Err(_) if GetLastError() == ERROR_LOGON_FAILURE => Precheck::WrongPassword,
            Err(_) => Precheck::Skipped,
        }
    }
}

/// Converts rendered QR pixels into a 32-bpp top-down DIB section (ownership to LogonUI).
pub fn bitmap(p: &Pixels) -> windows::core::Result<HBITMAP> {
    let info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: p.size as i32,
        biHeight: -(p.size as i32),
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    // SAFETY: DIB section of size*size 32-bit pixels; we write exactly that many.
    unsafe {
        let dc = GetDC(None);
        let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
        let bmp = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &mut bits, None, 0);
        ReleaseDC(None, dc);
        let bmp = bmp?;
        let px = std::slice::from_raw_parts_mut(bits as *mut u32, p.size * p.size);
        for (i, d) in p.dark.iter().enumerate() {
            px[i] = if *d { 0xFF00_0000 } else { 0xFFFF_FFFF };
        }
        Ok(bmp)
    }
}

//! Small Win32 helpers used by the COM objects.

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Graphics::Gdi::{CreateDIBSection, GetDC, ReleaseDC, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HBITMAP};
use windows::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows::Win32::System::RemoteDesktop::{WTSClientAddress, WTSFreeMemory, WTSQuerySessionInformationW, WTS_CLIENT_ADDRESS, WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION};
use windows::Win32::UI::Shell::SHStrDupW;
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION};

use crate::qr::Pixels;

/// Looks up the "Negotiate" authentication package id, which a returned logon serialization must
/// name (standard credential-provider pattern for passwordless submit, feature 004).
pub fn negotiate_auth_package() -> windows::core::Result<u32> {
    use windows::Win32::Security::Authentication::Identity::{LsaConnectUntrusted, LsaDeregisterLogonProcess, LsaLookupAuthenticationPackage, LSA_STRING};
    // SAFETY: LSA calls with a local handle and a fixed ASCII package name; handle closed after.
    unsafe {
        let mut lsa = windows::Win32::Foundation::HANDLE::default();
        LsaConnectUntrusted(&mut lsa).ok()?;
        let name = b"Negotiate";
        let s = LSA_STRING { Length: name.len() as u16, MaximumLength: name.len() as u16, Buffer: windows::core::PSTR(name.as_ptr() as *mut u8) };
        let mut pkg = 0u32;
        let r = LsaLookupAuthenticationPackage(lsa, &s, &mut pkg);
        let _ = LsaDeregisterLogonProcess(lsa);
        r.ok()?;
        Ok(pkg)
    }
}

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

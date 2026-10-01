//! A large, crisp offline-QR window next to the sign-in tile.
//!
//! The wrapped Password provider's tile image is drawn at avatar size (roughly 100 to 200 px) and
//! smoothed when LogonUI rescales it, which makes a ~340 character offline challenge impossible to
//! scan. This window draws the same QR at an exact whole-pixel scale in its own topmost window.
//!
//! It is purely a display. It never takes focus (so typing the password or code is unaffected),
//! never touches credentials, closes itself when the challenge expires, and any failure in here is
//! swallowed: the password, phone and recovery paths do not depend on it.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicIsize, Ordering};

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, BitBlt, CreateCompatibleDC, CreateFontW, CreateSolidBrush, DeleteDC, DeleteObject, DrawTextW, EndPaint, FillRect, SelectObject,
    SetBkMode, SetTextColor, CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS, DEFAULT_CHARSET, DT_CENTER, DT_WORDBREAK, FW_SEMIBOLD, HBITMAP, HGDIOBJ,
    OUT_DEFAULT_PRECIS, PAINTSTRUCT, SRCCOPY, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, GetSystemMetrics, KillTimer, PostMessageW, PostQuitMessage,
    RegisterClassW, SetTimer, ShowWindow, TranslateMessage, CS_HREDRAW, CS_VREDRAW, MSG, SM_CXSCREEN, SM_CYSCREEN, SW_SHOWNOACTIVATE, WM_CLOSE,
    WM_DESTROY, WM_PAINT, WM_TIMER, WNDCLASSW, WS_BORDER, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP,
};

use crate::{qr, win};

/// Current window (0 = none). Only used to ask it to close.
static CURRENT: AtomicIsize = AtomicIsize::new(0);
// The QR bitmap and its side in pixels (one window at a time).
static BITMAP: AtomicIsize = AtomicIsize::new(0);
static QR_SIZE: AtomicIsize = AtomicIsize::new(0);

const CAPTION: &str = "Open PhoneGate on your phone, choose Offline code, and scan this.";
const PAD: i32 = 24;
const CAPTION_H: i32 = 84;
const TIMER_ID: usize = 1;

/// Shows the QR for `text` for at most `lifetime_ms`. Replaces any window already showing.
pub fn show(text: &str, lifetime_ms: u32) {
    hide();
    let text = text.to_string();
    let _ = std::thread::Builder::new().name("phonegate-qr".into()).spawn(move || {
        let _ = catch_unwind(AssertUnwindSafe(|| run(&text, lifetime_ms)));
    });
}

/// Closes the window if one is showing.
pub fn hide() {
    let h = CURRENT.swap(0, Ordering::SeqCst);
    if h != 0 {
        // SAFETY: posting WM_CLOSE to a window handle is safe even if it is already gone.
        unsafe {
            let _ = PostMessageW(HWND(h as _), WM_CLOSE, WPARAM(0), LPARAM(0));
        }
    }
}

fn run(text: &str, lifetime_ms: u32) {
    // SAFETY: plain Win32 calls on this thread; every handle created here is destroyed here.
    unsafe {
        let (cx, cy) = (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
        // Largest QR that fits comfortably: up to 62% of the screen height, at most 640 px.
        let target = ((cy as f32 * 0.62) as usize).clamp(300, 640);
        let Some(px) = qr::render(text, target) else { return };
        let Ok(bmp) = win::bitmap(&px) else { return };
        BITMAP.store(bmp.0 as isize, Ordering::SeqCst);
        QR_SIZE.store(px.size as isize, Ordering::SeqCst);

        let hinst = GetModuleHandleW(PCWSTR::null()).unwrap_or_default();
        let class = w!("PhoneGateOfflineQr");
        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            hInstance: hinst.into(),
            lpszClassName: class,
            ..Default::default()
        };
        // Registering twice returns 0 (already exists); the existing class is fine.
        RegisterClassW(&wc);

        let w_px = px.size as i32 + 2 * PAD;
        let h_px = px.size as i32 + 2 * PAD + CAPTION_H;
        let x = (cx - w_px - cx / 25).max(0);
        let y = ((cy - h_px) / 2).max(0);
        let Ok(hwnd) = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            class,
            w!("PhoneGate offline code"),
            WS_POPUP | WS_BORDER,
            x,
            y,
            w_px,
            h_px,
            None,
            None,
            hinst,
            None,
        ) else {
            let _ = DeleteObject(HGDIOBJ(BITMAP.swap(0, Ordering::SeqCst) as _));
            return;
        };
        CURRENT.store(hwnd.0 as isize, Ordering::SeqCst);
        SetTimer(hwnd, TIMER_ID, lifetime_ms.max(1000), None);
        let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        let _ = DeleteObject(HGDIOBJ(BITMAP.swap(0, Ordering::SeqCst) as _));
        // Only clear CURRENT if it is still us (a newer window may have replaced it).
        let _ = CURRENT.compare_exchange(hwnd.0 as isize, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let dc = BeginPaint(hwnd, &mut ps);
            let size = QR_SIZE.load(Ordering::SeqCst) as i32;
            let bmp = HBITMAP(BITMAP.load(Ordering::SeqCst) as _);
            // White card so the quiet zone is real even over a dark background.
            let white = CreateSolidBrush(COLORREF(0x00FF_FFFF));
            let full = RECT { left: 0, top: 0, right: size + 2 * PAD, bottom: size + 2 * PAD + CAPTION_H };
            FillRect(dc, &full, white);
            let _ = DeleteObject(HGDIOBJ(white.0));
            if size > 0 && !bmp.is_invalid() {
                let mem = CreateCompatibleDC(dc);
                let old = SelectObject(mem, HGDIOBJ(bmp.0));
                let _ = BitBlt(dc, PAD, PAD, size, size, mem, 0, 0, SRCCOPY);
                SelectObject(mem, old);
                let _ = DeleteDC(mem);
            }
            let font = CreateFontW(
                22,
                0,
                0,
                0,
                FW_SEMIBOLD.0 as i32,
                0,
                0,
                0,
                DEFAULT_CHARSET.0 as u32,
                OUT_DEFAULT_PRECIS.0 as u32,
                CLIP_DEFAULT_PRECIS.0 as u32,
                CLEARTYPE_QUALITY.0 as u32,
                0,
                w!("Segoe UI"),
            );
            let old_font = SelectObject(dc, HGDIOBJ(font.0));
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, COLORREF(0x0020_1A13));
            let mut text: Vec<u16> = CAPTION.encode_utf16().collect();
            let mut r = RECT { left: PAD, top: size + PAD + 12, right: size + PAD, bottom: size + PAD + CAPTION_H };
            DrawTextW(dc, &mut text, &mut r, DT_CENTER | DT_WORDBREAK);
            SelectObject(dc, old_font);
            let _ = DeleteObject(HGDIOBJ(font.0));
            let _ = EndPaint(hwnd, &ps);
            LRESULT(0)
        }
        WM_TIMER | WM_CLOSE => {
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            let _ = KillTimer(hwnd, TIMER_ID);
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Manual visual check on a normal desktop:
    /// `cargo test -p phonegate-credprov qrwin -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn shows_a_qr_window_for_a_few_seconds() {
        let text = format!("PGO1:{}", "Zm9vYmFy".repeat(42));
        show(&text, 9000);
        std::thread::sleep(std::time::Duration::from_secs(9));
        hide();
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(CURRENT.load(Ordering::SeqCst), 0);
    }
}

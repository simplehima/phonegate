//! Security posture checks surfaced by the companion app (FR-028, SECURITY.md hardening list).

use std::os::windows::process::CommandExt;
use std::process::Command;

use serde_json::{json, Value};
use windows::core::HSTRING;
use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn reg_dword(key: &str, value: &str) -> Option<u32> {
    let mut data = 0u32;
    let mut len = 4u32;
    // SAFETY: 4-byte DWORD buffer with matching length.
    let r = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, &HSTRING::from(key), &HSTRING::from(value), RRF_RT_REG_DWORD, None, Some(&mut data as *mut u32 as *mut _), Some(&mut len))
    };
    r.is_ok().then_some(data)
}

fn bitlocker() -> &'static str {
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) if o.status.success() => match String::from_utf8_lossy(&o.stdout).trim() {
            "On" => "on",
            "Off" => "off",
            _ => "unknown",
        },
        _ => "unknown",
    }
}

pub fn security_check(key_backend: &str) -> Value {
    let secure_boot = reg_dword(r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled").map(|v| v == 1);
    let rdp_enabled = reg_dword(r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections").map(|v| v == 0).unwrap_or(false);
    let passwordless_only = reg_dword(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device", "DevicePasswordLessBuildVersion").map(|v| v == 2).unwrap_or(false);
    json!({
        "tpm": key_backend == "tpm",
        "bitlocker": bitlocker(),
        "secure_boot": secure_boot,
        "rdp_enabled": rdp_enabled,
        "passwordless_only": passwordless_only,
    })
}

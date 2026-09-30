//! Runs the BitLocker helper scripts (`bitlocker_logic`) with Windows PowerShell as SYSTEM.

use std::io::Write;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};

use pg_core::{Error, Result};
use zeroize::Zeroizing;

use crate::bitlocker_logic as logic;
use crate::probe::{BitLockerInfo, BitLockerOps};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `-EncodedCommand` payload: base64 of the UTF-16LE script. Scripts contain no secrets.
pub fn encode_command(script: &str) -> String {
    use base64::Engine;
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    base64::engine::general_purpose::STANDARD.encode(utf16)
}

fn run(script: &str, stdin: Option<&str>) -> Result<String> {
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &encode_command(script)])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| Error::Io(format!("powershell: {e}")))?;
    {
        // Only the secret (if any) travels on stdin, read by the script's [Console]::In.ReadLine().
        let mut input = child.stdin.take().ok_or(Error::Io("powershell stdin".into()))?;
        if let Some(s) = stdin {
            let line = Zeroizing::new(format!("{s}\n"));
            input.write_all(line.as_bytes())?;
        }
    }
    let out = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(Error::Io(format!("BitLocker command failed: {}", err.lines().next().unwrap_or("unknown error"))));
    }
    Ok(stdout)
}

pub struct WinBitLocker;

impl BitLockerOps for WinBitLocker {
    fn status(&self) -> Result<BitLockerInfo> {
        Ok(logic::parse_status(&run(logic::STATUS_SCRIPT, None)?))
    }

    fn prepare(&self) -> Result<(String, String)> {
        logic::parse_prepare(&run(logic::PREPARE_SCRIPT, None)?).ok_or(Error::Decode("unexpected BitLocker output"))
    }

    fn enable(&self, pin: &str) -> Result<bool> {
        // The script is sent first; the PIN is the next line on stdin. It never appears on a
        // command line (visible to other processes) or in logs.
        logic::parse_enable(&run(logic::ENABLE_SCRIPT, Some(pin))?).ok_or(Error::Decode("unexpected BitLocker output"))
    }
}

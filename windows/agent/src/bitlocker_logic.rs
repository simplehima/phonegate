//! BitLocker helper logic (feature 002, US3): the PowerShell scripts the agent runs and the
//! parsers for their JSON output. Pure and unit-tested; `win::bitlocker` executes them.
//!
//! Secrets never appear in a script or command line: the PIN is read by the script from stdin.

use serde_json::Value;

use crate::probe::BitLockerInfo;

/// Reports edition support, volume status, protection and key-protector types as JSON.
pub const STATUS_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { @{ supported = $false } | ConvertTo-Json -Compress; exit 0 }
$v = Get-BitLockerVolume -MountPoint $env:SystemDrive
@{
  supported  = $true
  volume     = "$($v.VolumeStatus)"
  protection = "$($v.ProtectionStatus)"
  percent    = [int]$v.EncryptionPercentage
  protectors = @($v.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
} | ConvertTo-Json -Compress
"#;

/// Allows a TPM+PIN startup protector by policy, then adds a recovery-password protector and
/// prints it once (the agent relays it to the owner and keeps only its last 6 digits).
pub const PREPARE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
New-Item -Path $k -Force | Out-Null
foreach ($n in 'UseAdvancedStartup') { Set-ItemProperty -Path $k -Name $n -Value 1 -Type DWord }
foreach ($n in 'UseTPM','UseTPMPIN','UseTPMKey','UseTPMKeyPIN') { Set-ItemProperty -Path $k -Name $n -Value 2 -Type DWord }
Set-ItemProperty -Path $k -Name 'EnableBDEWithNoTPM' -Value 0 -Type DWord
$v = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -WarningAction SilentlyContinue
$kp = $v.KeyProtector | Where-Object { "$($_.KeyProtectorType)" -eq 'RecoveryPassword' } | Select-Object -Last 1
@{ id = "$($kp.KeyProtectorId)"; password = "$($kp.RecoveryPassword)" } | ConvertTo-Json -Compress
"#;

/// Reads the PIN from stdin. Encrypts with TPM+PIN if the drive is decrypted, otherwise adds a
/// TPM+PIN protector and removes TPM-only protectors (upgrade).
pub const ENABLE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$pin = [Console]::In.ReadLine()
$sec = ConvertTo-SecureString -String $pin -AsPlainText -Force
Remove-Variable pin
$v = Get-BitLockerVolume -MountPoint $env:SystemDrive
if ("$($v.VolumeStatus)" -eq 'FullyDecrypted') {
  Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmAndPinProtector -Pin $sec -WarningAction SilentlyContinue | Out-Null
  $restart = $true
} else {
  Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinProtector -Pin $sec -WarningAction SilentlyContinue | Out-Null
  $v = Get-BitLockerVolume -MountPoint $env:SystemDrive
  $v.KeyProtector | Where-Object { "$($_.KeyProtectorType)" -eq 'Tpm' } | ForEach-Object {
    Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $_.KeyProtectorId | Out-Null
  }
  $restart = $false
}
@{ restart = $restart } | ConvertTo-Json -Compress
"#;

fn last_json_line(out: &str) -> Option<Value> {
    out.lines().rev().find_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
}

/// Maps `STATUS_SCRIPT` output to the helper's state vocabulary.
pub fn parse_status(out: &str) -> BitLockerInfo {
    let unknown = BitLockerInfo { supported: false, state: "unknown".into(), percent: None };
    let Some(v) = last_json_line(out) else { return unknown };
    if v["supported"] != true {
        return BitLockerInfo { supported: false, state: "unknown".into(), percent: None };
    }
    let volume = v["volume"].as_str().unwrap_or("");
    let percent = v["percent"].as_u64().map(|p| p.min(100) as u8);
    // ConvertTo-Json renders a one-element array as a bare string on older PowerShell.
    let protectors: Vec<String> = match &v["protectors"] {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        Value::String(s) => vec![s.clone()],
        _ => vec![],
    };
    let has_pin = protectors.iter().any(|p| p.starts_with("TpmPin"));
    let state = match volume {
        "FullyDecrypted" => "off",
        "EncryptionInProgress" => "encrypting",
        "FullyEncrypted" if has_pin => "on-pin",
        "FullyEncrypted" => "on-no-pin",
        _ => "unknown",
    };
    BitLockerInfo { supported: true, state: state.into(), percent }
}

/// Parses `PREPARE_SCRIPT` output into `(recovery_password, protector_id)`.
pub fn parse_prepare(out: &str) -> Option<(String, String)> {
    let v = last_json_line(out)?;
    let pw = v["password"].as_str()?.to_string();
    let id = v["id"].as_str()?.to_string();
    // Recovery passwords are 8 groups of 6 digits.
    let groups: Vec<&str> = pw.split('-').collect();
    let well_formed = groups.len() == 8 && groups.iter().all(|g| g.len() == 6 && g.bytes().all(|b| b.is_ascii_digit()));
    (well_formed && !id.is_empty()).then_some((pw, id))
}

pub fn parse_enable(out: &str) -> Option<bool> {
    last_json_line(out)?["restart"].as_bool()
}

/// Maps the helper state to the status-report enum.
pub fn to_report(info: &BitLockerInfo) -> pg_core::messages::BitLocker {
    use pg_core::messages::BitLocker;
    match info.state.as_str() {
        "off" | "encrypting" => BitLocker::Off,
        "on-no-pin" => BitLocker::OnNoPin,
        "on-pin" => BitLocker::OnPin,
        _ => BitLocker::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_never_embed_secrets() {
        for s in [STATUS_SCRIPT, PREPARE_SCRIPT, ENABLE_SCRIPT] {
            assert!(!s.contains("{pin}") && !s.contains("$args"), "no interpolation hooks");
        }
        assert!(ENABLE_SCRIPT.contains("[Console]::In.ReadLine()"), "PIN comes from stdin");
    }

    #[test]
    fn status_states() {
        let s = |j: &str| parse_status(j).state;
        assert_eq!(s(r#"{"supported":false}"#), "unknown");
        assert!(!parse_status(r#"{"supported":false}"#).supported);
        assert_eq!(s(r#"{"supported":true,"volume":"FullyDecrypted","protection":"Off","percent":0,"protectors":[]}"#), "off");
        assert_eq!(s(r#"{"supported":true,"volume":"EncryptionInProgress","percent":37,"protectors":["Tpm"]}"#), "encrypting");
        assert_eq!(parse_status(r#"{"supported":true,"volume":"EncryptionInProgress","percent":37,"protectors":["Tpm"]}"#).percent, Some(37));
        assert_eq!(s(r#"{"supported":true,"volume":"FullyEncrypted","protectors":["Tpm","RecoveryPassword"]}"#), "on-no-pin");
        assert_eq!(s(r#"{"supported":true,"volume":"FullyEncrypted","protectors":["TpmPin","RecoveryPassword"]}"#), "on-pin");
        assert_eq!(s(r#"{"supported":true,"volume":"FullyEncrypted","protectors":"TpmPin"}"#), "on-pin", "single protector as bare string");
        assert_eq!(s("WARNING: noise\n{\"supported\":true,\"volume\":\"FullyDecrypted\"}"), "off", "last JSON line wins");
        assert_eq!(s("garbage"), "unknown");
    }

    #[test]
    fn prepare_output_validated() {
        let ok = r#"{"id":"{A1}","password":"111111-222222-333333-444444-555555-666666-777777-888888"}"#;
        assert_eq!(parse_prepare(ok).unwrap().1, "{A1}");
        assert!(parse_prepare(r#"{"id":"{A1}","password":"12-34"}"#).is_none());
        assert!(parse_prepare(r#"{"id":"","password":"111111-222222-333333-444444-555555-666666-777777-888888"}"#).is_none());
        assert_eq!(parse_enable(r#"{"restart":true}"#), Some(true));
        assert_eq!(parse_enable("nope"), None);
    }

    #[test]
    fn report_mapping() {
        use pg_core::messages::BitLocker;
        let i = |s: &str| BitLockerInfo { supported: true, state: s.into(), percent: None };
        assert_eq!(to_report(&i("encrypting")), BitLocker::Off, "not protected until encryption completes");
        assert_eq!(to_report(&i("on-pin")), BitLocker::OnPin);
        assert_eq!(to_report(&i("unknown")), BitLocker::Unknown);
    }
}

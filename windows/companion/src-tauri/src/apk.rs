//! The bundled Android app (feature 003, FR-307).
//!
//! The installer puts `PhoneGate.apk` at `<folder of PhoneGate.exe>\Android\PhoneGate.apk` with a
//! build-time sidecar `PhoneGate.apk.json`:
//! `{"version":"0.1.0","sha256":"<hex of the APK>","signer_sha256":"<hex of the signing cert>"}`.
//!
//! The UI never supplies a path: both the lookup and "Show the file" derive it from
//! `current_exe()`. The APK's SHA-256 is recomputed here and must equal the sidecar before the
//! UI calls the file verified.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const APK_DIR: &str = "Android";
pub const APK_NAME: &str = "PhoneGate.apk";
pub const SIDECAR_NAME: &str = "PhoneGate.apk.json";

/// Refuse to hash anything absurdly large (a release APK is a few MB).
const MAX_APK_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SIDECAR_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sidecar {
    pub version: String,
    pub sha256: String,
    pub signer_sha256: String,
}

fn hex64(v: &Value, key: &str) -> Result<String, String> {
    let s = v[key].as_str().ok_or_else(|| format!("sidecar_missing:{key}"))?.trim().to_ascii_lowercase();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("sidecar_bad:{key}"));
    }
    Ok(s)
}

/// Parses and validates the sidecar JSON. Hex is normalised to lowercase.
pub fn parse_sidecar(bytes: &[u8]) -> Result<Sidecar, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|_| "sidecar_bad_json".to_string())?;
    let version = v["version"].as_str().ok_or("sidecar_missing:version")?.trim().to_string();
    if version.is_empty() || version.len() > 64 || !version.chars().all(|c| c.is_ascii_alphanumeric() || ".-+_".contains(c)) {
        return Err("sidecar_bad:version".into());
    }
    Ok(Sidecar { version, sha256: hex64(&v, "sha256")?, signer_sha256: hex64(&v, "signer_sha256")? })
}

/// Streams the file through SHA-256 and returns lowercase hex.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// `<exe dir>\Android\PhoneGate.apk`.
pub fn apk_path_for_exe(exe: &Path) -> Option<PathBuf> {
    Some(exe.parent()?.join(APK_DIR).join(APK_NAME))
}

/// Everything the "Get the phone app" step shows, for an APK at `apk`.
pub fn inspect(apk: &Path) -> Value {
    let path = apk.display().to_string();
    let meta = match std::fs::symlink_metadata(apk) {
        Ok(m) if m.is_file() => m,
        Ok(_) => return json!({"found": false, "verified": false, "reason": "not_a_file"}),
        Err(_) => return json!({"found": false, "verified": false, "reason": "missing"}),
    };
    if meta.len() > MAX_APK_BYTES {
        return json!({"found": true, "path": path, "verified": false, "reason": "too_large"});
    }
    let sidecar_path = apk.with_file_name(SIDECAR_NAME);
    let sidecar = match std::fs::metadata(&sidecar_path) {
        Ok(m) if m.is_file() && m.len() <= MAX_SIDECAR_BYTES => std::fs::read(&sidecar_path).map_err(|_| "sidecar_unreadable".to_string()).and_then(|b| parse_sidecar(&b)),
        Ok(_) => Err("sidecar_bad".to_string()),
        Err(_) => Err("sidecar_missing".to_string()),
    };
    let actual = match sha256_file(apk) {
        Ok(h) => h,
        Err(_) => return json!({"found": true, "path": path, "verified": false, "reason": "unreadable"}),
    };
    match sidecar {
        Err(reason) => json!({"found": true, "path": path, "sha256": actual, "verified": false, "reason": reason}),
        Ok(sc) if sc.sha256 != actual => json!({
            "found": true, "path": path, "version": sc.version, "sha256": actual, "expected_sha256": sc.sha256,
            "signer_sha256": sc.signer_sha256, "verified": false, "reason": "changed",
        }),
        Ok(sc) => json!({"found": true, "path": path, "version": sc.version, "sha256": actual, "signer_sha256": sc.signer_sha256, "verified": true}),
    }
}

/// Strips the `\\?\` prefix that `canonicalize` adds, which Explorer does not understand.
fn plain(p: &Path) -> String {
    let s = p.display().to_string();
    s.strip_prefix(r"\\?\").filter(|r| r.as_bytes().get(1) == Some(&b':')).map(str::to_string).unwrap_or(s)
}

/// Checks that `apk` is exactly `<exe dir>\Android\PhoneGate.apk` after resolving links, and
/// returns the path to hand to Explorer.
pub fn validated_reveal_path(exe: &Path) -> Result<String, String> {
    let apk = apk_path_for_exe(exe).ok_or("apk_missing")?;
    let meta = std::fs::symlink_metadata(&apk).map_err(|_| "apk_missing".to_string())?;
    if !meta.is_file() {
        return Err("apk_missing".into());
    }
    let canon = std::fs::canonicalize(&apk).map_err(|_| "apk_missing".to_string())?;
    let exe_dir = std::fs::canonicalize(exe.parent().ok_or("apk_missing")?).map_err(|_| "apk_missing".to_string())?;
    if canon != exe_dir.join(APK_DIR).join(APK_NAME) {
        return Err("apk_path_mismatch".into());
    }
    let s = plain(&canon);
    if s.contains('"') {
        return Err("apk_path_mismatch".into());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let p = std::env::temp_dir().join(format!("pg-apk-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(p.join(APK_DIR)).unwrap();
            TempDir(p)
        }
        fn apk(&self) -> PathBuf {
            self.0.join(APK_DIR).join(APK_NAME)
        }
        fn write(&self, name: &str, bytes: &[u8]) {
            File::create(self.0.join(APK_DIR).join(name)).unwrap().write_all(bytes).unwrap();
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const SIGNER: &str = "3b1f0c9a7d52e84f6a0b2c4d6e8f90123456789abcdef0123456789abcdef012";

    fn sidecar_for(bytes: &[u8]) -> String {
        let h: String = Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect();
        format!(r#"{{"version":"0.1.0","sha256":"{h}","signer_sha256":"{SIGNER}"}}"#)
    }

    #[test]
    fn sidecar_parsing_validates_every_field() {
        let ok = parse_sidecar(format!(r#"{{"version":"0.1.0","sha256":"{}","signer_sha256":"{SIGNER}"}}"#, "AB".repeat(32)).as_bytes()).unwrap();
        assert_eq!(ok.version, "0.1.0");
        assert_eq!(ok.sha256, "ab".repeat(32), "hex is normalised to lowercase");
        assert_eq!(parse_sidecar(b"not json").unwrap_err(), "sidecar_bad_json");
        assert_eq!(parse_sidecar(format!(r#"{{"sha256":"{SIGNER}","signer_sha256":"{SIGNER}"}}"#).as_bytes()).unwrap_err(), "sidecar_missing:version");
        assert_eq!(parse_sidecar(format!(r#"{{"version":"0.1.0","sha256":"abc","signer_sha256":"{SIGNER}"}}"#).as_bytes()).unwrap_err(), "sidecar_bad:sha256");
        assert_eq!(parse_sidecar(format!(r#"{{"version":"0.1.0","sha256":"{}","signer_sha256":"{SIGNER}"}}"#, "zz".repeat(32)).as_bytes()).unwrap_err(), "sidecar_bad:sha256");
        assert_eq!(parse_sidecar(format!(r#"{{"version":"0.1.0","sha256":"{SIGNER}"}}"#).as_bytes()).unwrap_err(), "sidecar_missing:signer_sha256");
        assert_eq!(parse_sidecar(format!(r#"{{"version":"<b>","sha256":"{SIGNER}","signer_sha256":"{SIGNER}"}}"#).as_bytes()).unwrap_err(), "sidecar_bad:version");
    }

    #[test]
    fn sha256_matches_known_vector() {
        let d = TempDir::new("vec");
        d.write(APK_NAME, b"abc");
        assert_eq!(sha256_file(&d.apk()).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn verified_when_sidecar_matches() {
        let d = TempDir::new("ok");
        let body = b"PK\x03\x04 pretend apk contents";
        d.write(APK_NAME, body);
        d.write(SIDECAR_NAME, sidecar_for(body).as_bytes());
        let v = inspect(&d.apk());
        assert_eq!(v["found"], true);
        assert_eq!(v["verified"], true);
        assert_eq!(v["version"], "0.1.0");
        assert_eq!(v["signer_sha256"], SIGNER);
        assert!(v.get("reason").is_none());
    }

    #[test]
    fn mismatch_is_detected_after_the_file_changes() {
        let d = TempDir::new("changed");
        d.write(SIDECAR_NAME, sidecar_for(b"original apk").as_bytes());
        d.write(APK_NAME, b"tampered apk");
        let v = inspect(&d.apk());
        assert_eq!(v["found"], true);
        assert_eq!(v["verified"], false);
        assert_eq!(v["reason"], "changed");
        assert_ne!(v["sha256"], v["expected_sha256"]);
    }

    #[test]
    fn missing_apk_and_missing_or_bad_sidecar() {
        let d = TempDir::new("missing");
        let v = inspect(&d.apk());
        assert_eq!(v["found"], false);
        assert_eq!(v["reason"], "missing");
        d.write(APK_NAME, b"apk without sidecar");
        let v = inspect(&d.apk());
        assert_eq!((v["found"].clone(), v["verified"].clone(), v["reason"].clone()), (json!(true), json!(false), json!("sidecar_missing")));
        d.write(SIDECAR_NAME, b"{\"version\":\"0.1.0\"}");
        assert_eq!(inspect(&d.apk())["reason"], "sidecar_missing:sha256");
    }

    #[cfg(windows)]
    #[test]
    fn reveal_path_is_derived_from_the_exe_only() {
        let d = TempDir::new("reveal");
        let exe = d.0.join("PhoneGate.exe");
        assert_eq!(validated_reveal_path(&exe).unwrap_err(), "apk_missing");
        d.write(APK_NAME, b"apk");
        let p = validated_reveal_path(&exe).unwrap();
        assert!(p.ends_with(r"Android\PhoneGate.apk"), "{p}");
        assert!(!p.starts_with(r"\\?\"));
        // A directory with the APK's name is not a file.
        let d2 = TempDir::new("reveal-dir");
        std::fs::create_dir_all(d2.apk()).unwrap();
        assert_eq!(validated_reveal_path(&d2.0.join("PhoneGate.exe")).unwrap_err(), "apk_missing");
    }
}

//! Single-use offline recovery codes (protocol §7, FR-022..FR-026).
//!
//! Each code carries 128 bits of entropy, so a fast salted hash is enough: a stolen
//! `recovery.json` cannot be brute-forced. Online guessing at the lock screen is throttled by an
//! escalating, persisted lockout.

use serde::{Deserialize, Serialize};

use crate::crypto::{self, b64};
use crate::encoding::Enc;
use crate::error::{Error, Result};

pub const CODE_COUNT: usize = 10;
pub const MAX_FAILURES: u32 = 5;
pub const BASE_LOCKOUT_MS: u64 = 60_000;
pub const MAX_LOCKOUT_MS: u64 = 24 * 60 * 60 * 1000;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encodes 16 bytes as 26 Crockford base32 symbols grouped `4-4-4-4-4-4-2`.
pub fn encode_code(bytes: &[u8; 16]) -> String {
    let mut bits: u32 = 0;
    let mut nbits = 0;
    let mut syms = Vec::with_capacity(26);
    for b in bytes {
        bits = (bits << 8) | *b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            syms.push(ALPHABET[((bits >> nbits) & 31) as usize]);
        }
    }
    if nbits > 0 {
        syms.push(ALPHABET[((bits << (5 - nbits)) & 31) as usize]);
    }
    let s = String::from_utf8(syms).expect("ascii");
    s.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("ascii"))
        .collect::<Vec<_>>()
        .join("-")
}

/// Normalizes user input (case, separators, O/I/L confusables) and decodes it.
pub fn decode_code(input: &str) -> Result<[u8; 16]> {
    let mut syms = Vec::with_capacity(26);
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        let v = ALPHABET.iter().position(|a| *a as char == c).ok_or(Error::Decode("invalid character in code"))?;
        syms.push(v as u32);
    }
    if syms.len() != 26 {
        return Err(Error::Decode("recovery codes have 26 characters"));
    }
    let mut out = [0u8; 16];
    let mut bits: u64 = 0;
    let mut nbits = 0;
    let mut i = 0;
    for s in syms {
        bits = (bits << 5) | s as u64;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            if i < 16 {
                out[i] = ((bits >> nbits) & 0xff) as u8;
            }
            i += 1;
        }
    }
    // 26 symbols = 130 bits: 16 bytes plus 2 padding bits that must be zero.
    if nbits != 2 || bits & 0b11 != 0 {
        return Err(Error::Decode("non-canonical code"));
    }
    Ok(out)
}

fn hash_code(salt: &[u8; 32], code: &[u8; 16]) -> [u8; 32] {
    crypto::sha256(&Enc::new("phonegate/v1/recovery").bytes(salt).bytes(code).finish())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeEntry {
    pub hash: String,
    pub used_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingNotice {
    pub kind: String,
    pub at: u64,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverySet {
    pub salt: String,
    pub codes: Vec<CodeEntry>,
    pub confirmed: bool,
    pub failures: u32,
    pub lockouts: u32,
    pub locked_until: u64,
    #[serde(default)]
    pub pending_notices: Vec<PendingNotice>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    Valid { remaining: usize },
    Invalid { locked_ms: u64 },
    Locked { remaining_ms: u64 },
}

impl RecoverySet {
    /// Generates a fresh set. Returns the set and the plaintext codes (shown once).
    pub fn generate() -> Result<(RecoverySet, Vec<String>)> {
        let salt: [u8; 32] = crypto::random()?;
        let mut codes = Vec::with_capacity(CODE_COUNT);
        let mut entries = Vec::with_capacity(CODE_COUNT);
        for _ in 0..CODE_COUNT {
            let c: [u8; 16] = crypto::random()?;
            entries.push(CodeEntry { hash: b64::encode(&hash_code(&salt, &c)), used_at: None });
            codes.push(encode_code(&c));
        }
        Ok((
            RecoverySet {
                salt: b64::encode(&salt),
                codes: entries,
                confirmed: false,
                failures: 0,
                lockouts: 0,
                locked_until: 0,
                pending_notices: vec![],
            },
            codes,
        ))
    }

    pub fn remaining(&self) -> usize {
        self.codes.iter().filter(|c| c.used_at.is_none()).count()
    }

    pub fn lock_remaining_ms(&self, now: u64) -> u64 {
        self.locked_until.saturating_sub(now)
    }

    /// Index of the matching unused code; scans every entry to keep timing independent of the
    /// position of the match.
    fn find(&self, input: &str) -> Result<Option<usize>> {
        let salt: [u8; 32] = b64::decode_fixed(&self.salt)?;
        let Ok(code) = decode_code(input) else {
            return Ok(None);
        };
        let h = hash_code(&salt, &code);
        let mut found = None;
        for (i, e) in self.codes.iter().enumerate() {
            let stored = b64::decode(&e.hash)?;
            if crypto::ct_eq(&stored, &h) && e.used_at.is_none() {
                found = Some(i);
            }
        }
        Ok(found)
    }

    /// Records one failed attempt (recovery or offline code). Returns the new lockout length.
    pub fn record_failure(&mut self, now: u64) -> u64 {
        self.failures += 1;
        if self.failures >= MAX_FAILURES {
            let shift = self.lockouts.min(20);
            let len = (BASE_LOCKOUT_MS << shift).min(MAX_LOCKOUT_MS);
            self.locked_until = now + len;
            self.lockouts = self.lockouts.saturating_add(1);
            self.failures = 0;
            return len;
        }
        0
    }

    pub fn record_success(&mut self) {
        self.failures = 0;
        self.lockouts = 0;
        self.locked_until = 0;
    }

    /// Lock-screen verification: consumes the code on success, counts failures otherwise.
    pub fn verify_and_consume(&mut self, input: &str, now: u64) -> Result<VerifyOutcome> {
        let rem = self.lock_remaining_ms(now);
        if rem > 0 {
            return Ok(VerifyOutcome::Locked { remaining_ms: rem });
        }
        match self.find(input)? {
            Some(i) => {
                self.codes[i].used_at = Some(now);
                self.record_success();
                self.pending_notices.push(PendingNotice {
                    kind: "recovery-code-used".into(),
                    at: now,
                    detail: format!("{} codes left", self.remaining()),
                });
                Ok(VerifyOutcome::Valid { remaining: self.remaining() })
            }
            None => Ok(VerifyOutcome::Invalid { locked_ms: self.record_failure(now) }),
        }
    }

    /// Setup confirmation (FR-023): checks a code without consuming it.
    pub fn confirm(&mut self, input: &str) -> Result<bool> {
        let ok = self.find(input)?.is_some();
        if ok {
            self.confirmed = true;
        }
        Ok(ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        for _ in 0..200 {
            let b: [u8; 16] = crypto::random().unwrap();
            let s = encode_code(&b);
            assert_eq!(s.len(), 26 + 6);
            assert_eq!(decode_code(&s).unwrap(), b);
        }
        assert_eq!(encode_code(&[0; 16]), "0000-0000-0000-0000-0000-0000-00");
        assert_eq!(encode_code(&[0xff; 16]), "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZW");
    }

    #[test]
    fn normalization() {
        let b = [0xff; 16];
        assert_eq!(decode_code("zzzz zzzz-zzzz zzzz zzzz zzzz zw").unwrap(), b);
        let with_o = encode_code(&[0; 16]).replace('0', "o");
        assert_eq!(decode_code(&with_o).unwrap(), [0; 16]);
        assert!(decode_code("ZZZZ").is_err());
        assert!(decode_code("ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZ").is_err(), "non-zero pad bits");
        assert!(decode_code("UUUU-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZW").is_err(), "U is not in the alphabet");
    }

    #[test]
    fn single_use_and_confirm() {
        let (mut set, codes) = RecoverySet::generate().unwrap();
        assert_eq!(codes.len(), CODE_COUNT);
        assert!(!set.confirmed);
        assert!(set.confirm(&codes[3]).unwrap());
        assert!(set.confirmed);
        assert_eq!(set.remaining(), 10, "confirm does not consume");
        assert_eq!(set.verify_and_consume(&codes[3], 1).unwrap(), VerifyOutcome::Valid { remaining: 9 });
        assert!(matches!(set.verify_and_consume(&codes[3], 2).unwrap(), VerifyOutcome::Invalid { .. }));
        assert_eq!(set.pending_notices.len(), 1);
        // Plaintext codes never appear in the stored form.
        let json = serde_json::to_string(&set).unwrap();
        for c in &codes {
            assert!(!json.contains(c.as_str()));
        }
    }

    #[test]
    fn lockout_escalates_and_persists() {
        let (mut set, codes) = RecoverySet::generate().unwrap();
        let mut now = 1_000;
        for _ in 0..4 {
            assert_eq!(set.verify_and_consume("bad", now).unwrap(), VerifyOutcome::Invalid { locked_ms: 0 });
        }
        assert_eq!(set.verify_and_consume("bad", now).unwrap(), VerifyOutcome::Invalid { locked_ms: 60_000 });
        // Even a valid code is refused while locked.
        assert!(matches!(set.verify_and_consume(&codes[0], now + 1).unwrap(), VerifyOutcome::Locked { .. }));
        // Survives serialization (reboot).
        let mut set: RecoverySet = serde_json::from_str(&serde_json::to_string(&set).unwrap()).unwrap();
        now += 60_000;
        for _ in 0..4 {
            set.verify_and_consume("bad", now).unwrap();
        }
        assert_eq!(set.verify_and_consume("bad", now).unwrap(), VerifyOutcome::Invalid { locked_ms: 120_000 });
        now += 120_000;
        assert_eq!(set.verify_and_consume(&codes[0], now).unwrap(), VerifyOutcome::Valid { remaining: 9 });
        assert_eq!(set.lockouts, 0);
    }

    #[test]
    fn lockout_is_capped() {
        let (mut set, _) = RecoverySet::generate().unwrap();
        set.lockouts = 40;
        set.failures = MAX_FAILURES - 1;
        assert_eq!(set.record_failure(0), MAX_LOCKOUT_MS);
    }
}

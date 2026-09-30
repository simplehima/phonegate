//! Offline phone approval (protocol §6, FR-026a): the lock screen shows a PC-signed challenge as
//! a QR code; the phone answers with a 10-digit code derived from `k_offline` after a biometric
//! check. No network is involved.

use crate::crypto::{self, b64, Id, Pub};
use crate::encoding::{decode, Enc};
use crate::error::{Error, Result};
use crate::messages::Scenario;
use crate::signer::Signer;

pub const OFFLINE_LIFETIME_MS: u64 = 60_000;
pub const MAX_ATTEMPTS: u8 = 5;
pub const QR_PREFIX: &str = "PGO1:";
/// Tolerance for phone/PC clock difference when the phone checks a challenge.
pub const CLOCK_SKEW_MS: u64 = 300_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineChallenge {
    pub pc_id: Id,
    pub chal_id: [u8; 16],
    pub issued_at: u64,
    pub expires_at: u64,
    pub scenario: Scenario,
    pub account: String,
}

impl OfflineChallenge {
    pub fn new(pc_id: Id, scenario: Scenario, account: &str, now: u64) -> Result<Self> {
        Ok(OfflineChallenge {
            pc_id,
            chal_id: crypto::random()?,
            issued_at: now,
            expires_at: now + OFFLINE_LIFETIME_MS,
            scenario,
            account: account.to_string(),
        })
    }

    pub fn body(&self) -> Vec<u8> {
        Enc::new("phonegate/v1/offline-challenge")
            .bytes(&self.pc_id)
            .bytes(&self.chal_id)
            .u64(self.issued_at)
            .u64(self.expires_at)
            .str(self.scenario.as_str())
            .str(&self.account)
            .finish()
    }

    pub fn to_qr(&self, signer: &dyn Signer) -> Result<String> {
        let body = self.body();
        let sig = signer.sign(&body)?;
        Ok(format!("{QR_PREFIX}{}", b64::encode(&Enc::new("phonegate/v1/offline-qr").bytes(&body).bytes(&sig).finish())))
    }

    /// Phone side: parse, check it came from the paired PC, and check freshness.
    pub fn parse_qr(qr: &str, pc_pub: &Pub, phone_now: u64) -> Result<Self> {
        let raw = b64::decode(qr.strip_prefix(QR_PREFIX).ok_or(Error::Decode("not an offline challenge"))?)?;
        let outer = decode(&raw, "phonegate/v1/offline-qr", 3)?;
        let body = outer.bytes(1);
        crypto::verify(pc_pub, body, outer.bytes(2))?;
        let f = decode(body, "phonegate/v1/offline-challenge", 7)?;
        let c = OfflineChallenge {
            pc_id: f.fixed(1)?,
            chal_id: f.fixed(2)?,
            issued_at: f.u64(3)?,
            expires_at: f.u64(4)?,
            scenario: Scenario::parse(&f.string(5)?)?,
            account: f.string(6)?,
        };
        if c.pc_id != crypto::id_of(pc_pub) {
            return Err(Error::Verify("challenge is for another PC"));
        }
        if c.expires_at <= c.issued_at || c.expires_at - c.issued_at > OFFLINE_LIFETIME_MS {
            return Err(Error::Decode("invalid challenge lifetime"));
        }
        if c.issued_at > phone_now + CLOCK_SKEW_MS || phone_now > c.expires_at + CLOCK_SKEW_MS {
            return Err(Error::Expired);
        }
        Ok(c)
    }

    pub fn response_code(&self, k_offline: &[u8; 32]) -> String {
        let mac = crypto::hmac(k_offline, &Enc::new("phonegate/v1/offline-response").bytes(&self.body()).finish());
        let v = u64::from_be_bytes(mac[..8].try_into().expect("8 bytes")) % 10_000_000_000;
        format!("{v:010}")
    }

    /// PC side check of a typed code (constant-time comparison).
    pub fn check_code(&self, k_offline: &[u8; 32], typed: &str) -> bool {
        let digits: String = typed.chars().filter(|c| c.is_ascii_digit()).collect();
        digits.len() == 10 && crypto::ct_eq(digits.as_bytes(), self.response_code(k_offline).as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::SoftSigner;

    #[test]
    fn full_flow() {
        let pc = SoftSigner::generate().unwrap();
        let k = [5u8; 32];
        let c = OfflineChallenge::new(crypto::id_of(&pc.public()), Scenario::Unlock, "PC\\me", 1_000).unwrap();
        let qr = c.to_qr(&pc).unwrap();
        let parsed = OfflineChallenge::parse_qr(&qr, &pc.public(), 2_000).unwrap();
        assert_eq!(parsed, c);
        let code = parsed.response_code(&k);
        assert_eq!(code.len(), 10);
        assert!(c.check_code(&k, &code));
        assert!(c.check_code(&k, &format!("{} {}", &code[..5], &code[5..])));
        assert!(!c.check_code(&[6; 32], &code));
        assert!(!c.check_code(&k, "0000000000") || code == "0000000000");
    }

    #[test]
    fn rejects_foreign_or_stale_challenges() {
        let pc = SoftSigner::generate().unwrap();
        let evil = SoftSigner::generate().unwrap();
        let c = OfflineChallenge::new(crypto::id_of(&pc.public()), Scenario::Logon, "u", 1_000).unwrap();
        let qr = c.to_qr(&evil).unwrap();
        assert!(OfflineChallenge::parse_qr(&qr, &pc.public(), 1_000).is_err(), "signed by another key");
        let qr = c.to_qr(&pc).unwrap();
        assert_eq!(
            OfflineChallenge::parse_qr(&qr, &pc.public(), c.expires_at + CLOCK_SKEW_MS + 1).unwrap_err(),
            Error::Expired
        );
        // Challenge for a different PC id, signed by the right key.
        let mut other = c.clone();
        other.pc_id = [0; 32];
        assert!(OfflineChallenge::parse_qr(&other.to_qr(&pc).unwrap(), &pc.public(), 1_000).is_err());
        assert!(OfflineChallenge::parse_qr("PGO1:!!", &pc.public(), 1_000).is_err());
    }
}

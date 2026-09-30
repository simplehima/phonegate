//! Typed protocol messages (protocol §4.1, §5).

use crate::crypto::{self, Id, Pub, Sig};
use crate::encoding::{decode, Enc};
use crate::error::{Error, Result};
use crate::signer::Signer;

/// Maximum request lifetime (FR-005).
pub const MAX_REQUEST_LIFETIME_MS: u64 = 60_000;
pub const MATCH_MIN: u64 = 10;
pub const MATCH_MAX: u64 = 99;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    Unlock,
    Logon,
    Remote,
    DisableProtection,
    /// Weakening a security setting while protection is on (feature 002).
    ChangeSetting,
}

impl Scenario {
    pub fn as_str(self) -> &'static str {
        match self {
            Scenario::Unlock => "unlock",
            Scenario::Logon => "logon",
            Scenario::Remote => "remote",
            Scenario::DisableProtection => "disable-protection",
            Scenario::ChangeSetting => "change-setting",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "unlock" => Scenario::Unlock,
            "logon" => Scenario::Logon,
            "remote" => Scenario::Remote,
            "disable-protection" => Scenario::DisableProtection,
            "change-setting" => Scenario::ChangeSetting,
            _ => return Err(Error::Decode("unknown scenario")),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Deny,
    NotMe,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Approve => "approve",
            Decision::Deny => "deny",
            Decision::NotMe => "not-me",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "approve" => Decision::Approve,
            "deny" => Decision::Deny,
            "not-me" => Decision::NotMe,
            _ => return Err(Error::Decode("unknown decision")),
        })
    }
}

/// Wire kinds (protocol §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    PairOffer,
    PairJoin,
    PairConfirm,
    PairComplete,
    ApprovalRequest,
    ApprovalResponse,
    Cancel,
    Notice,
    Unpair,
    Status,
}

impl Kind {
    pub const ALL: [Kind; 10] = [
        Kind::PairOffer,
        Kind::PairJoin,
        Kind::PairConfirm,
        Kind::PairComplete,
        Kind::ApprovalRequest,
        Kind::ApprovalResponse,
        Kind::Cancel,
        Kind::Notice,
        Kind::Unpair,
        Kind::Status,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::PairOffer => "pair-offer",
            Kind::PairJoin => "pair-join",
            Kind::PairConfirm => "pair-confirm",
            Kind::PairComplete => "pair-complete",
            Kind::ApprovalRequest => "approval-request",
            Kind::ApprovalResponse => "approval-response",
            Kind::Cancel => "cancel",
            Kind::Notice => "notice",
            Kind::Unpair => "unpair",
            Kind::Status => "status",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Kind::ALL
            .iter()
            .copied()
            .find(|k| k.as_str() == s)
            .ok_or(Error::Decode("unknown kind"))
    }

    /// Kinds that travel inside a sealed envelope (post-pairing).
    pub fn is_sealed(self) -> bool {
        matches!(
            self,
            Kind::ApprovalRequest | Kind::ApprovalResponse | Kind::Cancel | Kind::Notice | Kind::Unpair | Kind::Status
        )
    }
}

pub fn wire(kind: Kind, payload: &[u8]) -> Vec<u8> {
    Enc::new("phonegate/v1/wire").str(kind.as_str()).bytes(payload).finish()
}

pub fn unwire(body: &[u8]) -> Result<(Kind, Vec<u8>)> {
    let f = decode(body, "phonegate/v1/wire", 3)?;
    Ok((Kind::parse(&f.string(1)?)?, f.bytes(2).to_vec()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub req_id: [u8; 16],
    pub nonce: [u8; 32],
    pub pc_id: Id,
    pub phone_id: Id,
    pub issued_at: u64,
    pub expires_at: u64,
    pub scenario: Scenario,
    pub account: String,
    pub pc_name: String,
    pub remote_addr: String,
    pub match_number: u64,
}

const REQ_LABEL: &str = "phonegate/v1/approval-request";

impl ApprovalRequest {
    pub fn encode(&self) -> Vec<u8> {
        Enc::new(REQ_LABEL)
            .bytes(&self.req_id)
            .bytes(&self.nonce)
            .bytes(&self.pc_id)
            .bytes(&self.phone_id)
            .u64(self.issued_at)
            .u64(self.expires_at)
            .str(self.scenario.as_str())
            .str(&self.account)
            .str(&self.pc_name)
            .str(&self.remote_addr)
            .u64(self.match_number)
            .finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let f = decode(b, REQ_LABEL, 12)?;
        let r = ApprovalRequest {
            req_id: f.fixed(1)?,
            nonce: f.fixed(2)?,
            pc_id: f.fixed(3)?,
            phone_id: f.fixed(4)?,
            issued_at: f.u64(5)?,
            expires_at: f.u64(6)?,
            scenario: Scenario::parse(&f.string(7)?)?,
            account: f.string(8)?,
            pc_name: f.string(9)?,
            remote_addr: f.string(10)?,
            match_number: f.u64(11)?,
        };
        r.validate()?;
        Ok(r)
    }

    pub fn validate(&self) -> Result<()> {
        if !(MATCH_MIN..=MATCH_MAX).contains(&self.match_number) {
            return Err(Error::Decode("match number out of range"));
        }
        if self.expires_at <= self.issued_at || self.expires_at - self.issued_at > MAX_REQUEST_LIFETIME_MS {
            return Err(Error::Decode("invalid request lifetime"));
        }
        Ok(())
    }

    pub fn digest(&self) -> [u8; 32] {
        crypto::sha256(&self.encode())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalResponse {
    pub request_digest: [u8; 32],
    pub decision: Decision,
    pub typed_number: u64,
    pub responded_at: u64,
    pub decision_sig: Sig,
}

const RESP_LABEL: &str = "phonegate/v1/approval-response";

pub fn decision_signed_bytes(digest: &[u8; 32], decision: Decision, typed_number: u64, at: u64) -> Vec<u8> {
    Enc::new("phonegate/v1/decision")
        .bytes(digest)
        .str(decision.as_str())
        .u64(typed_number)
        .u64(at)
        .finish()
}

impl ApprovalResponse {
    /// Creates a response. `signer` MUST be the approve key for `Approve` and the device key
    /// otherwise; the PC enforces this in [`ApprovalResponse::verify_decision`].
    pub fn create(
        signer: &dyn Signer,
        request_digest: [u8; 32],
        decision: Decision,
        typed_number: u64,
        responded_at: u64,
    ) -> Result<Self> {
        let typed_number = if decision == Decision::Approve { typed_number } else { 0 };
        let decision_sig = signer.sign(&decision_signed_bytes(&request_digest, decision, typed_number, responded_at))?;
        Ok(ApprovalResponse { request_digest, decision, typed_number, responded_at, decision_sig })
    }

    pub fn encode(&self) -> Vec<u8> {
        Enc::new(RESP_LABEL)
            .bytes(&self.request_digest)
            .str(self.decision.as_str())
            .u64(self.typed_number)
            .u64(self.responded_at)
            .bytes(&self.decision_sig)
            .finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let f = decode(b, RESP_LABEL, 6)?;
        Ok(ApprovalResponse {
            request_digest: f.fixed(1)?,
            decision: Decision::parse(&f.string(2)?)?,
            typed_number: f.u64(3)?,
            responded_at: f.u64(4)?,
            decision_sig: f.fixed(5)?,
        })
    }

    /// Verifies `decision_sig` with the key the decision requires: approve key for `Approve`,
    /// device key for `Deny`/`NotMe`.
    pub fn verify_decision(&self, approve_pub: &Pub, device_pub: &Pub) -> Result<()> {
        let key = match self.decision {
            Decision::Approve => approve_pub,
            Decision::Deny | Decision::NotMe => device_pub,
        };
        crypto::verify(
            key,
            &decision_signed_bytes(&self.request_digest, self.decision, self.typed_number, self.responded_at),
            &self.decision_sig,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cancel {
    pub req_id: [u8; 16],
}

impl Cancel {
    pub fn encode(&self) -> Vec<u8> {
        Enc::new("phonegate/v1/cancel").bytes(&self.req_id).finish()
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let f = decode(b, "phonegate/v1/cancel", 2)?;
        Ok(Cancel { req_id: f.fixed(1)? })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    RecoveryCodeUsed,
    OfflineCodeUsed,
    ProtectionEnabled,
    ProtectionDisabled,
    Cooldown,
    AgentStarted,
    AgentStopped,
    Shutdown,
    Sleep,
    Resume,
    Repaired,
    SafeModeBoot,
    SettingChanged,
}

impl NoticeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NoticeKind::RecoveryCodeUsed => "recovery-code-used",
            NoticeKind::OfflineCodeUsed => "offline-code-used",
            NoticeKind::ProtectionEnabled => "protection-enabled",
            NoticeKind::ProtectionDisabled => "protection-disabled",
            NoticeKind::Cooldown => "cooldown",
            NoticeKind::AgentStarted => "agent-started",
            NoticeKind::AgentStopped => "agent-stopped",
            NoticeKind::Shutdown => "shutdown",
            NoticeKind::Sleep => "sleep",
            NoticeKind::Resume => "resume",
            NoticeKind::Repaired => "repaired",
            NoticeKind::SafeModeBoot => "safe-mode-boot",
            NoticeKind::SettingChanged => "setting-changed",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "recovery-code-used" => NoticeKind::RecoveryCodeUsed,
            "offline-code-used" => NoticeKind::OfflineCodeUsed,
            "protection-enabled" => NoticeKind::ProtectionEnabled,
            "protection-disabled" => NoticeKind::ProtectionDisabled,
            "cooldown" => NoticeKind::Cooldown,
            "agent-started" => NoticeKind::AgentStarted,
            "agent-stopped" => NoticeKind::AgentStopped,
            "shutdown" => NoticeKind::Shutdown,
            "sleep" => NoticeKind::Sleep,
            "resume" => NoticeKind::Resume,
            "repaired" => NoticeKind::Repaired,
            "safe-mode-boot" => NoticeKind::SafeModeBoot,
            "setting-changed" => NoticeKind::SettingChanged,
            _ => return Err(Error::Decode("unknown notice kind")),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub kind: NoticeKind,
    pub at: u64,
    pub detail: String,
}

impl Notice {
    pub fn encode(&self) -> Vec<u8> {
        Enc::new("phonegate/v1/notice").str(self.kind.as_str()).u64(self.at).str(&self.detail).finish()
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let f = decode(b, "phonegate/v1/notice", 4)?;
        Ok(Notice { kind: NoticeKind::parse(&f.string(1)?)?, at: f.u64(2)?, detail: f.string(3)? })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitLocker {
    Off,
    OnNoPin,
    OnPin,
    Unknown,
}

impl BitLocker {
    pub fn as_str(self) -> &'static str {
        match self {
            BitLocker::Off => "off",
            BitLocker::OnNoPin => "on-no-pin",
            BitLocker::OnPin => "on-pin",
            BitLocker::Unknown => "unknown",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "off" => BitLocker::Off,
            "on-no-pin" => BitLocker::OnNoPin,
            "on-pin" => BitLocker::OnPin,
            "unknown" => BitLocker::Unknown,
            _ => return Err(Error::Decode("unknown bitlocker state")),
        })
    }
}

/// Periodic signed integrity report, PC to phone (feature 002 contract section 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub seq: u64,
    pub at: u64,
    pub enforce: bool,
    pub cp_registered: bool,
    pub filter_registered: bool,
    pub files_intact: bool,
    pub watchdog_present: bool,
    pub bitlocker: BitLocker,
    pub netlogon_blocked: bool,
    pub safe_mode: bool,
}

fn flag(f: &crate::encoding::Fields<'_>, i: usize) -> Result<bool> {
    match f.u64(i)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::Decode("flag must be 0 or 1")),
    }
}

impl Status {
    /// Integrity is healthy when every protection component is present.
    pub fn integrity_ok(&self) -> bool {
        self.cp_registered && self.filter_registered && self.files_intact
    }

    pub fn encode(&self) -> Vec<u8> {
        Enc::new("phonegate/v1/status")
            .u64(self.seq)
            .u64(self.at)
            .u64(self.enforce as u64)
            .u64(self.cp_registered as u64)
            .u64(self.filter_registered as u64)
            .u64(self.files_intact as u64)
            .u64(self.watchdog_present as u64)
            .str(self.bitlocker.as_str())
            .u64(self.netlogon_blocked as u64)
            .u64(self.safe_mode as u64)
            .finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let f = decode(b, "phonegate/v1/status", 11)?;
        Ok(Status {
            seq: f.u64(1)?,
            at: f.u64(2)?,
            enforce: flag(&f, 3)?,
            cp_registered: flag(&f, 4)?,
            filter_registered: flag(&f, 5)?,
            files_intact: flag(&f, 6)?,
            watchdog_present: flag(&f, 7)?,
            bitlocker: BitLocker::parse(&f.string(8)?)?,
            netlogon_blocked: flag(&f, 9)?,
            safe_mode: flag(&f, 10)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpair {
    pub at: u64,
}

impl Unpair {
    pub fn encode(&self) -> Vec<u8> {
        Enc::new("phonegate/v1/unpair").u64(self.at).finish()
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let f = decode(b, "phonegate/v1/unpair", 2)?;
        Ok(Unpair { at: f.u64(1)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::SoftSigner;

    fn req() -> ApprovalRequest {
        ApprovalRequest {
            req_id: [1; 16],
            nonce: [2; 32],
            pc_id: [3; 32],
            phone_id: [4; 32],
            issued_at: 1_000,
            expires_at: 61_000,
            scenario: Scenario::Unlock,
            account: "PC\\owner".into(),
            pc_name: "Desk".into(),
            remote_addr: String::new(),
            match_number: 42,
        }
    }

    #[test]
    fn request_roundtrip_and_validation() {
        let r = req();
        assert_eq!(ApprovalRequest::decode(&r.encode()).unwrap(), r);
        let mut long = req();
        long.expires_at = long.issued_at + MAX_REQUEST_LIFETIME_MS + 1;
        assert!(ApprovalRequest::decode(&long.encode()).is_err());
        let mut n = req();
        n.match_number = 100;
        assert!(ApprovalRequest::decode(&n.encode()).is_err());
        n.match_number = 9;
        assert!(ApprovalRequest::decode(&n.encode()).is_err());
    }

    #[test]
    fn decision_key_binding() {
        let approve = SoftSigner::generate().unwrap();
        let device = SoftSigner::generate().unwrap();
        let d = req().digest();
        let ok = ApprovalResponse::create(&approve, d, Decision::Approve, 42, 5).unwrap();
        assert!(ok.verify_decision(&approve.public(), &device.public()).is_ok());
        // Approve signed with the device key must be rejected.
        let wrong = ApprovalResponse::create(&device, d, Decision::Approve, 42, 5).unwrap();
        assert!(wrong.verify_decision(&approve.public(), &device.public()).is_err());
        // Deny signed with the device key is fine; with approve key is rejected.
        let deny = ApprovalResponse::create(&device, d, Decision::Deny, 0, 5).unwrap();
        assert!(deny.verify_decision(&approve.public(), &device.public()).is_ok());
        let deny_wrong = ApprovalResponse::create(&approve, d, Decision::Deny, 0, 5).unwrap();
        assert!(deny_wrong.verify_decision(&approve.public(), &device.public()).is_err());
        // Tampering with the decision breaks the signature.
        let mut flipped = deny.clone();
        flipped.decision = Decision::Approve;
        assert!(flipped.verify_decision(&device.public(), &device.public()).is_err());
        assert_eq!(ApprovalResponse::decode(&ok.encode()).unwrap(), ok);
    }

    #[test]
    fn wire_roundtrip() {
        for k in Kind::ALL {
            let (k2, p) = unwire(&wire(k, b"xyz")).unwrap();
            assert_eq!(k, k2);
            assert_eq!(p, b"xyz");
        }
        assert!(unwire(&Enc::new("phonegate/v1/wire").str("bogus").bytes(b"").finish()).is_err());
    }

    #[test]
    fn status_roundtrip_and_strict_flags() {
        let st = Status {
            seq: 7,
            at: 9,
            enforce: true,
            cp_registered: true,
            filter_registered: false,
            files_intact: true,
            watchdog_present: true,
            bitlocker: BitLocker::OnNoPin,
            netlogon_blocked: false,
            safe_mode: false,
        };
        assert_eq!(Status::decode(&st.encode()).unwrap(), st);
        assert!(!st.integrity_ok());
        let bad = Enc::new("phonegate/v1/status").u64(1).u64(1).u64(2).u64(1).u64(1).u64(1).u64(1).str("off").u64(0).u64(0).finish();
        assert!(Status::decode(&bad).is_err(), "flag value 2 rejected");
        let bad = Enc::new("phonegate/v1/status").u64(1).u64(1).u64(1).u64(1).u64(1).u64(1).u64(1).str("maybe").u64(0).u64(0).finish();
        assert!(Status::decode(&bad).is_err(), "unknown bitlocker rejected");
        assert!(Kind::Status.is_sealed());
        assert_eq!(Scenario::parse("change-setting").unwrap(), Scenario::ChangeSetting);
        for k in ["agent-stopped", "shutdown", "sleep", "resume", "repaired", "safe-mode-boot", "setting-changed", "agent-started"] {
            assert_eq!(NoticeKind::parse(k).unwrap().as_str(), k);
        }
    }

    #[test]
    fn small_messages_roundtrip() {
        let c = Cancel { req_id: [9; 16] };
        assert_eq!(Cancel::decode(&c.encode()).unwrap(), c);
        let n = Notice { kind: NoticeKind::RecoveryCodeUsed, at: 3, detail: "x".into() };
        assert_eq!(Notice::decode(&n.encode()).unwrap(), n);
        let u = Unpair { at: 4 };
        assert_eq!(Unpair::decode(&u.encode()).unwrap(), u);
    }
}

//! Phone-side health model and alert rule (feature 002, contract §4). This is the reference
//! implementation; the Android app mirrors it and the simulator uses it directly.
//!
//! Silence is measured on the phone's clock, so neither the PC nor the relay can suppress the
//! "stopped reporting" alarm: withholding reports can only cause an alarm, never hide one.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::messages::{NoticeKind, Status};

/// No report for this long (phone clock) raises the silence alarm.
pub const SILENCE_MS: u64 = 20 * 60_000;
/// A protection-off report is expected only within this long after a `protection-disabled` notice.
pub const DISABLE_GRACE_MS: u64 = 10 * 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "detail", rename_all = "snake_case")]
pub enum Alert {
    AgentStopped,
    Repaired(String),
    SafeModeBoot(String),
    IntegrityBroken(String),
    ProtectionOffWithoutApproval,
    StoppedReporting,
}

impl Alert {
    /// Owner-facing sentence (the app localizes; this is the reference wording).
    pub fn message(&self, pc: &str) -> String {
        match self {
            Alert::AgentStopped => format!("PhoneGate on {pc} was stopped. If you didn't do this, someone may be tampering with the PC."),
            Alert::Repaired(what) => format!("PhoneGate on {pc} had to repair itself: {what}."),
            Alert::SafeModeBoot(when) => format!("{pc} was started in Safe Mode ({when}). Safe Mode skips the phone check."),
            Alert::IntegrityBroken(what) => format!("PhoneGate protection on {pc} is damaged: {what}."),
            Alert::ProtectionOffWithoutApproval => format!("Protection on {pc} was turned off without your approval."),
            Alert::StoppedReporting => format!("{pc} stopped reporting. It may be offline, or PhoneGate may have been removed."),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcState {
    Ok,
    Asleep,
    Off,
    StoppedReporting,
    TamperAlert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Lifecycle {
    Running,
    Shutdown,
    Sleep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    last_seq: Option<u64>,
    last_seen_at: u64,
    last_enforce: Option<bool>,
    lifecycle: Lifecycle,
    last_disable_notice_at: Option<u64>,
    in_alert: bool,
    silence_alerted: bool,
    pub bitlocker_off: bool,
    pub netlogon_blocked: bool,
}

impl Health {
    /// Starts tracking at `now` (e.g. pairing time) so a PC that never reports still alarms.
    pub fn new(now: u64) -> Self {
        Health {
            last_seq: None,
            last_seen_at: now,
            last_enforce: None,
            lifecycle: Lifecycle::Running,
            last_disable_notice_at: None,
            in_alert: false,
            silence_alerted: false,
            bitlocker_off: false,
            netlogon_blocked: false,
        }
    }

    fn raise(&mut self, a: Alert) -> Option<Alert> {
        if self.in_alert {
            return None; // one alert per episode
        }
        self.in_alert = true;
        Some(a)
    }

    /// A verified `status` report. Errors with `Replay` if its sequence is not newer.
    pub fn on_status(&mut self, st: &Status, now: u64) -> Result<Option<Alert>> {
        if self.last_seq.is_some_and(|s| st.seq <= s) {
            return Err(Error::Replay);
        }
        self.last_seq = Some(st.seq);
        self.last_seen_at = now;
        self.silence_alerted = false;
        self.lifecycle = Lifecycle::Running;
        self.bitlocker_off = st.bitlocker == crate::messages::BitLocker::Off;
        self.netlogon_blocked = st.netlogon_blocked;
        let prev_enforce = self.last_enforce.replace(st.enforce);

        if st.enforce && !st.integrity_ok() {
            let mut missing = Vec::new();
            if !st.cp_registered {
                missing.push("sign-in tile unregistered");
            }
            if !st.filter_registered {
                missing.push("tile filter unregistered");
            }
            if !st.files_intact {
                missing.push("program files changed");
            }
            return Ok(self.raise(Alert::IntegrityBroken(missing.join(", "))));
        }
        if prev_enforce == Some(true) && !st.enforce {
            let approved = self.last_disable_notice_at.is_some_and(|t| now.saturating_sub(t) <= DISABLE_GRACE_MS);
            if !approved {
                return Ok(self.raise(Alert::ProtectionOffWithoutApproval));
            }
        }
        // A fully healthy report ends the episode.
        self.in_alert = false;
        Ok(None)
    }

    /// A verified lifecycle / setting notice.
    pub fn on_notice(&mut self, kind: NoticeKind, detail: &str, now: u64) -> Option<Alert> {
        match kind {
            NoticeKind::Shutdown => {
                self.lifecycle = Lifecycle::Shutdown;
                None
            }
            NoticeKind::Sleep => {
                self.lifecycle = Lifecycle::Sleep;
                None
            }
            NoticeKind::Resume | NoticeKind::AgentStarted => {
                self.lifecycle = Lifecycle::Running;
                None
            }
            NoticeKind::ProtectionDisabled => {
                self.last_disable_notice_at = Some(now);
                None
            }
            NoticeKind::AgentStopped => self.raise(Alert::AgentStopped),
            NoticeKind::Repaired => self.raise(Alert::Repaired(detail.to_string())),
            NoticeKind::SafeModeBoot => self.raise(Alert::SafeModeBoot(detail.to_string())),
            _ => None,
        }
    }

    /// Periodic check (e.g. every minute) for the silence alarm.
    pub fn tick(&mut self, now: u64) -> Option<Alert> {
        let asleep = matches!(self.lifecycle, Lifecycle::Shutdown | Lifecycle::Sleep);
        if !asleep && !self.silence_alerted && now.saturating_sub(self.last_seen_at) > SILENCE_MS {
            self.silence_alerted = true;
            return self.raise(Alert::StoppedReporting);
        }
        None
    }

    pub fn state(&self, now: u64) -> PcState {
        if self.in_alert {
            return PcState::TamperAlert;
        }
        match self.lifecycle {
            Lifecycle::Shutdown => PcState::Off,
            Lifecycle::Sleep => PcState::Asleep,
            Lifecycle::Running if now.saturating_sub(self.last_seen_at) > SILENCE_MS => PcState::StoppedReporting,
            Lifecycle::Running => PcState::Ok,
        }
    }

    pub fn last_seen_at(&self) -> u64 {
        self.last_seen_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::BitLocker;

    const MIN: u64 = 60_000;

    fn st(seq: u64, enforce: bool) -> Status {
        Status {
            seq,
            at: seq,
            enforce,
            cp_registered: true,
            filter_registered: true,
            files_intact: true,
            watchdog_present: true,
            bitlocker: BitLocker::OnPin,
            netlogon_blocked: false,
            safe_mode: false,
        }
    }

    #[test]
    fn healthy_reports_never_alarm() {
        let mut h = Health::new(0);
        for i in 1..=10 {
            assert_eq!(h.on_status(&st(i, true), i * 5 * MIN).unwrap(), None);
            assert_eq!(h.tick(i * 5 * MIN + MIN), None);
        }
        assert_eq!(h.state(50 * MIN + MIN), PcState::Ok);
    }

    #[test]
    fn replayed_or_old_sequence_rejected() {
        let mut h = Health::new(0);
        h.on_status(&st(5, true), 1).unwrap();
        assert_eq!(h.on_status(&st(5, true), 2).unwrap_err(), Error::Replay);
        assert_eq!(h.on_status(&st(4, true), 3).unwrap_err(), Error::Replay);
        assert!(h.on_status(&st(6, true), 4).is_ok());
    }

    #[test]
    fn silence_alarms_once_but_not_after_sleep_or_shutdown() {
        let mut h = Health::new(0);
        h.on_status(&st(1, true), 0).unwrap();
        assert_eq!(h.tick(SILENCE_MS), None, "exactly at the window is not yet silent");
        assert_eq!(h.tick(SILENCE_MS + 1), Some(Alert::StoppedReporting));
        assert_eq!(h.tick(SILENCE_MS + 10 * MIN), None, "one alert per episode");
        assert_eq!(h.state(SILENCE_MS + 10 * MIN), PcState::TamperAlert);
        // Report resumes: episode ends.
        h.on_status(&st(2, true), SILENCE_MS + 11 * MIN).unwrap();
        assert_eq!(h.state(SILENCE_MS + 11 * MIN), PcState::Ok);

        for kind in [NoticeKind::Sleep, NoticeKind::Shutdown] {
            let mut h = Health::new(0);
            h.on_status(&st(1, true), 0).unwrap();
            h.on_notice(kind, "", MIN);
            assert_eq!(h.tick(10 * SILENCE_MS), None, "{kind:?} suppresses the silence alarm");
            assert_eq!(h.state(10 * SILENCE_MS), if kind == NoticeKind::Sleep { PcState::Asleep } else { PcState::Off });
            h.on_notice(NoticeKind::Resume, "", 10 * SILENCE_MS);
            assert_eq!(h.tick(10 * SILENCE_MS + SILENCE_MS + 1), Some(Alert::StoppedReporting), "silence after resume alarms again");
        }
    }

    #[test]
    fn never_reporting_pc_alarms() {
        let mut h = Health::new(1_000);
        assert_eq!(h.tick(1_000 + SILENCE_MS + 1), Some(Alert::StoppedReporting));
    }

    #[test]
    fn stop_repair_and_safe_mode_alert() {
        let mut h = Health::new(0);
        assert_eq!(h.on_notice(NoticeKind::AgentStopped, "", 1), Some(Alert::AgentStopped));
        let mut h = Health::new(0);
        assert_eq!(h.on_notice(NoticeKind::Repaired, "service", 1), Some(Alert::Repaired("service".into())));
        let mut h = Health::new(0);
        assert!(matches!(h.on_notice(NoticeKind::SafeModeBoot, "03:12", 1), Some(Alert::SafeModeBoot(_))));
        assert_eq!(h.on_notice(NoticeKind::RecoveryCodeUsed, "", 2), None);
    }

    #[test]
    fn integrity_break_while_enforcing_alarms() {
        let mut h = Health::new(0);
        h.on_status(&st(1, true), 0).unwrap();
        let mut bad = st(2, true);
        bad.cp_registered = false;
        match h.on_status(&bad, 1).unwrap() {
            Some(Alert::IntegrityBroken(m)) => assert!(m.contains("sign-in tile")),
            other => panic!("{other:?}"),
        }
        // Not enforcing: an unregistered tile is expected (protection off), no alarm.
        let mut h = Health::new(0);
        let mut off = st(1, false);
        off.cp_registered = false;
        assert_eq!(h.on_status(&off, 0).unwrap(), None);
    }

    #[test]
    fn protection_off_requires_recent_disable_notice() {
        let mut h = Health::new(0);
        h.on_status(&st(1, true), 0).unwrap();
        assert_eq!(h.on_status(&st(2, false), MIN).unwrap(), Some(Alert::ProtectionOffWithoutApproval));

        let mut h = Health::new(0);
        h.on_status(&st(1, true), 0).unwrap();
        h.on_notice(NoticeKind::ProtectionDisabled, "protection_disabled_by_phone", MIN);
        assert_eq!(h.on_status(&st(2, false), 2 * MIN).unwrap(), None);

        let mut h = Health::new(0);
        h.on_status(&st(1, true), 0).unwrap();
        h.on_notice(NoticeKind::ProtectionDisabled, "", MIN);
        assert_eq!(h.on_status(&st(2, false), MIN + DISABLE_GRACE_MS + 1).unwrap(), Some(Alert::ProtectionOffWithoutApproval), "stale notice doesn't count");
    }

    #[test]
    fn warnings_tracked_and_serializable() {
        let mut h = Health::new(0);
        let mut s = st(1, true);
        s.bitlocker = BitLocker::Off;
        s.netlogon_blocked = true;
        h.on_status(&s, 0).unwrap();
        assert!(h.bitlocker_off && h.netlogon_blocked);
        let j = serde_json::to_string(&h).unwrap();
        assert_eq!(serde_json::from_str::<Health>(&j).unwrap(), h);
    }
}

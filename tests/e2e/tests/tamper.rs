//! Feature 002: tamper alarm, end to end through a real relay. The phone side is the simulator,
//! which uses the same `pg_core::health` alert rule the Android app mirrors.

use std::time::Duration;

use pg_core::crypto;
use pg_core::envelope::{self, Dir, SealParams};
use pg_core::health::{Alert, SILENCE_MS};
use pg_core::messages::{self, Decision, Kind, NoticeKind, Scenario, Status};
use pg_core::signer::SoftSigner;
use pg_e2e::{req_bytes, Harness};

/// Delivers everything queued for the phone to the simulator (statuses, notices, requests).
async fn drain(h: &mut Harness) -> Vec<Kind> {
    let mut kinds = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_millis(500), h.phone_rx.recv()).await {
            Ok(Some(pg_core::relay_client::Incoming::Msg { from, body, .. })) => {
                if let Ok((k, _)) = messages::unwire(&body) {
                    kinds.push(k);
                }
                let now = h.now();
                let _ = h.phone.receive(&from, &body, now);
            }
            Ok(Some(_)) => continue,
            _ => break,
        }
    }
    kinds
}

/// Receives the next message of a kind and hands it to the simulator.
async fn deliver_next(h: &mut Harness, kind: Kind) {
    let (from, body) = h.phone_next_kind(kind).await;
    let now = h.now();
    h.phone.receive(&from, &body, now).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn status_reports_are_verified_and_ordered() {
    let mut h = Harness::new("st-ok").await;
    h.pair_and_enable().await;
    h.engine.send_status().unwrap();
    h.engine.send_status().unwrap();
    let mut seen = 0;
    while seen < 2 {
        deliver_next(&mut h, Kind::Status).await;
        seen = h.phone.pcs[0].statuses.len();
    }
    let st = &h.phone.pcs[0].statuses;
    assert!(st[st.len() - 1].seq > st[st.len() - 2].seq);
    assert!(st.last().unwrap().enforce && st.last().unwrap().integrity_ok());
    assert!(h.phone.alerts.is_empty(), "healthy reports never alarm: {:?}", h.phone.alerts);
}

#[tokio::test(flavor = "multi_thread")]
async fn malicious_relay_replayed_or_forged_status_is_rejected() {
    let mut h = Harness::new("st-mal").await;
    h.pair_and_enable().await;
    h.engine.send_status().unwrap();
    h.engine.send_status().unwrap();
    let (from1, old) = h.phone_next_kind(Kind::Status).await;
    let (from2, newer) = h.phone_next_kind(Kind::Status).await;
    let now = h.now();
    h.phone.receive(&from2, &newer, now).unwrap();
    // Replaying the older (seq-1) report after the newer one is refused by the sequence check.
    assert_eq!(h.phone.receive(&from1, &old, now).unwrap_err(), pg_core::Error::Replay);
    // Replaying the exact same bytes is refused by the message-id check.
    assert!(h.phone.receive(&from2, &newer, now).is_err());
    // A forged "all is well" report (attacker key, even with k_pair) is refused.
    let attacker = SoftSigner::generate().unwrap();
    let pc = &h.phone.pcs[0];
    let forged = Status {
        seq: 9_999,
        at: now,
        enforce: true,
        cp_registered: true,
        filter_registered: true,
        files_intact: true,
        watchdog_present: true,
        bitlocker: messages::BitLocker::OnPin,
        netlogon_blocked: false,
        safe_mode: false,
    };
    let sp = SealParams { k_pair: &pc.k_pair, dir: Dir::PcToPhone, kind: Kind::Status, from: pc.pc_id(), to: h.phone.id(), signer: &attacker };
    let (env, _) = envelope::seal(&sp, &forged.encode()).unwrap();
    let pc_id = pc.pc_id();
    assert!(h.phone.receive(&pc_id, &messages::wire(Kind::Status, &env), now).is_err());
    assert!(h.phone.pcs[0].statuses.iter().all(|s| s.seq != 9_999));
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_the_agent_alerts_the_phone() {
    let mut h = Harness::new("st-stop").await;
    h.pair_and_enable().await;
    h.engine.lifecycle(NoticeKind::AgentStopped, "the PhoneGate service was stopped");
    let kinds = drain(&mut h).await;
    assert!(kinds.contains(&Kind::Notice));
    assert!(h.phone.alerts.contains(&Alert::AgentStopped), "{:?}", h.phone.alerts);
}

#[tokio::test(flavor = "multi_thread")]
async fn sleep_then_silence_does_not_alarm_but_silent_kill_does() {
    let mut h = Harness::new("st-sleep").await;
    h.pair_and_enable().await;
    h.engine.send_status().unwrap();
    h.engine.lifecycle(NoticeKind::Sleep, "");
    drain(&mut h).await;
    h.phone.tick(h.now() + 10 * SILENCE_MS);
    assert!(h.phone.alerts.is_empty(), "sleeping PC must not alarm: {:?}", h.phone.alerts);

    // Resume, then the agent disappears without a word.
    h.engine.lifecycle(NoticeKind::Resume, "");
    h.engine.send_status().unwrap();
    drain(&mut h).await;
    let last = h.now();
    h.phone.tick(last + SILENCE_MS / 2);
    assert!(h.phone.alerts.is_empty());
    h.phone.tick(last + SILENCE_MS + 60_000);
    assert_eq!(h.phone.alerts, vec![Alert::StoppedReporting]);
}

#[tokio::test(flavor = "multi_thread")]
async fn integrity_break_while_enforcing_alarms() {
    let mut h = Harness::new("st-integ").await;
    h.pair_and_enable().await;
    h.engine.send_status().unwrap();
    drain(&mut h).await;
    h.fakes.probe.0.lock().unwrap().cp_registered = false; // someone unregistered the tile
    h.engine.maybe_send_status(); // change detection sends immediately
    drain(&mut h).await;
    assert!(matches!(h.phone.alerts.last(), Some(Alert::IntegrityBroken(m)) if m.contains("sign-in tile")), "{:?}", h.phone.alerts);
}

#[tokio::test(flavor = "multi_thread")]
async fn protection_off_by_file_tampering_alarms_but_approved_disable_does_not() {
    // Approved path: a recovery code turns protection off -> notice then status -> no alarm.
    let mut h = Harness::new("st-off-ok").await;
    let codes = h.pair_and_enable().await;
    h.engine.send_status().unwrap();
    drain(&mut h).await;
    assert!(h.engine.disable_recovery(&codes[3]).unwrap().valid);
    drain(&mut h).await;
    assert!(h.phone.alerts.is_empty(), "approved disable must not alarm: {:?}", h.phone.alerts);

    // Tamper path: an administrator edits state.json and restarts the service.
    let mut h = Harness::new("st-off-bad").await;
    h.pair_and_enable().await;
    h.engine.send_status().unwrap();
    drain(&mut h).await;
    let state = h.dir.join("state.json");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    v["enforce"] = serde_json::json!(false);
    std::fs::write(&state, serde_json::to_vec(&v).unwrap()).unwrap();
    h.restart_engine().await; // reconnect sends a fresh status (seq continues from disk)
    drain(&mut h).await;
    assert!(h.phone.alerts.contains(&Alert::ProtectionOffWithoutApproval), "{:?}", h.phone.alerts);
}

#[tokio::test(flavor = "multi_thread")]
async fn status_sequence_survives_restart() {
    let mut h = Harness::new("st-seq").await;
    h.pair_and_enable().await;
    for _ in 0..3 {
        h.engine.send_status().unwrap();
    }
    drain(&mut h).await;
    let before = h.phone.pcs[0].statuses.last().unwrap().seq;
    h.restart_engine().await;
    drain(&mut h).await;
    let after = h.phone.pcs[0].statuses.last().unwrap().seq;
    assert!(after > before, "restart must not reuse sequence numbers ({before} -> {after})");
    assert!(h.phone.alerts.is_empty(), "{:?}", h.phone.alerts);
}

#[tokio::test(flavor = "multi_thread")]
async fn watchdog_repair_and_safe_mode_notices_alarm() {
    let mut h = Harness::new("st-repair").await;
    h.pair_and_enable().await;
    h.engine.lifecycle(NoticeKind::Repaired, "the PhoneGate service was not running and was restarted");
    drain(&mut h).await;
    assert!(matches!(h.phone.alerts.last(), Some(Alert::Repaired(m)) if m.contains("restarted")));

    let mut h = Harness::new("st-safe").await;
    h.pair_and_enable().await;
    h.engine.lifecycle(NoticeKind::SafeModeBoot, "this start");
    drain(&mut h).await;
    assert!(matches!(h.phone.alerts.last(), Some(Alert::SafeModeBoot(_))));
}

#[tokio::test(flavor = "multi_thread")]
async fn unblocking_network_sign_ins_requires_phone_while_protected() {
    let mut h = Harness::new("st-netlogon").await;
    h.pair_and_enable().await;
    h.engine.netlogon_set(true).unwrap();
    assert!(h.engine.netlogon_status().unwrap());
    assert_eq!(h.engine.netlogon_set(false).unwrap_err(), pg_core::Error::State("approval_required"));
    assert!(h.engine.netlogon_status().unwrap(), "still blocked");

    let b = h.engine.netlogon_unblock_begin().unwrap();
    let (from, body) = h.phone_next_kind(Kind::ApprovalRequest).await;
    let now = h.now();
    let shown = h.phone.receive(&from, &body, now).unwrap().unwrap();
    assert_eq!(shown.request.scenario, Scenario::ChangeSetting);
    assert_eq!(shown.request.account, "Allow network sign-ins");
    let resp = h.phone.respond(&shown, Decision::Approve, b.number, h.now()).unwrap();
    h.phone_tx.send(&crypto::id_of(&h.engine.pc_public()), &resp, 60, "r").unwrap();
    let s = h.engine.netlogon_unblock_wait(&req_bytes(&b.req), Duration::from_secs(5)).await.unwrap();
    assert_eq!(s.as_str(), "approved");
    assert!(!h.engine.netlogon_status().unwrap(), "unblocked after approval");

    // An unrelated approval (e.g. an unlock) cannot be used to unblock.
    h.engine.netlogon_set(true).unwrap();
    let unlock = h.engine.begin(Scenario::Unlock, "x", "").unwrap();
    assert_eq!(h.engine.netlogon_unblock_wait(&req_bytes(&unlock.req), Duration::from_millis(50)).await.unwrap().as_str(), "expired");
    assert!(h.engine.netlogon_status().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn bitlocker_helper_requires_recovery_confirmation() {
    let h = Harness::new("st-bl").await;
    assert_eq!(h.engine.bitlocker_enable("123456", "123456").unwrap_err(), pg_core::Error::State("not_prepared"));
    let (pw, _) = h.engine.bitlocker_prepare().unwrap();
    let last6: String = pw.chars().filter(|c| c.is_ascii_digit()).rev().take(6).collect::<Vec<_>>().into_iter().rev().collect();
    assert_eq!(h.engine.bitlocker_enable("12345", &last6).unwrap_err(), pg_core::Error::State("bad_pin"));
    assert_eq!(h.engine.bitlocker_enable("246810", "000000").unwrap_err(), pg_core::Error::State("recovery_mismatch"));
    assert!(h.fakes.bitlocker.last_pin.lock().unwrap().is_none(), "nothing enabled before confirmation");
    assert!(h.engine.bitlocker_enable("246810", &last6).unwrap());
    assert_eq!(h.fakes.bitlocker.last_pin.lock().unwrap().as_deref(), Some("246810"));
    assert_eq!(h.engine.bitlocker_status().unwrap().state, "on-pin");
    // The session is single-use.
    assert_eq!(h.engine.bitlocker_enable("246810", &last6).unwrap_err(), pg_core::Error::State("not_prepared"));
}

//! US1: approve / deny an unlock (T033).

use std::time::Duration;

use pg_core::messages::{Decision, Kind, Scenario};
use pg_e2e::{req_bytes, Harness};

async fn request(h: &mut Harness) -> (pg_agent::engine::BeginOk, pg_sim::ShownRequest) {
    let b = h.engine.begin(Scenario::Unlock, "DESK\\owner", "").unwrap();
    let (from, body) = h.phone_next_kind(Kind::ApprovalRequest).await;
    let now = h.now();
    let shown = h.phone.receive(&from, &body, now).unwrap().expect("request shown");
    (b, shown)
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_approve_with_matching_number_unlocks_once() {
    let mut h = Harness::new("approve").await;
    h.pair_and_enable().await;
    let (b, shown) = request(&mut h).await;
    assert_eq!(shown.request.match_number, b.number);
    assert_eq!(shown.request.account, "DESK\\owner");
    assert_eq!(shown.request.pc_name, "Test PC");
    let resp = h.phone.respond(&shown, Decision::Approve, b.number, h.now()).unwrap();
    h.phone_tx.send(&h.phone.pcs[0].pc_id(), &resp, 60, "r").unwrap();
    let id = req_bytes(&b.req);
    assert_eq!(h.engine.wait(&id, Duration::from_secs(5)).await.as_str(), "approved");
    assert_eq!(h.engine.wait(&id, Duration::from_millis(50)).await.as_str(), "expired", "approval is single-use");
    assert_eq!(h.engine.history_items(1)[0].outcome, "approved");
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_deny_keeps_pc_locked() {
    let mut h = Harness::new("deny").await;
    h.pair_and_enable().await;
    let (b, shown) = request(&mut h).await;
    let resp = h.phone.respond(&shown, Decision::Deny, 0, h.now()).unwrap();
    h.phone_tx.send(&h.phone.pcs[0].pc_id(), &resp, 60, "r").unwrap();
    assert_eq!(h.engine.wait(&req_bytes(&b.req), Duration::from_secs(5)).await.as_str(), "denied");
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_not_me_is_recorded_as_suspicious() {
    let mut h = Harness::new("notme").await;
    h.pair_and_enable().await;
    let (b, shown) = request(&mut h).await;
    let resp = h.phone.respond(&shown, Decision::NotMe, 0, h.now()).unwrap();
    h.phone_tx.send(&h.phone.pcs[0].pc_id(), &resp, 60, "r").unwrap();
    assert_eq!(h.engine.wait(&req_bytes(&b.req), Duration::from_secs(5)).await.as_str(), "not_me");
    assert_eq!(h.engine.history_items(1)[0].outcome, "not_me");
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_wrong_typed_number_is_rejected() {
    let mut h = Harness::new("wrongnum").await;
    h.pair_and_enable().await;
    let (b, shown) = request(&mut h).await;
    let wrong = if b.number == 99 { 10 } else { b.number + 1 };
    let resp = h.phone.respond(&shown, Decision::Approve, wrong, h.now()).unwrap();
    h.phone_tx.send(&h.phone.pcs[0].pc_id(), &resp, 60, "r").unwrap();
    assert_ne!(h.engine.wait(&req_bytes(&b.req), Duration::from_secs(5)).await.as_str(), "approved");
    assert_eq!(h.engine.history_items(1)[0].outcome, "wrong_number");
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_approve_signed_with_device_key_is_rejected() {
    // An approval must come from the biometric-bound approve key, never the device key.
    let mut h = Harness::new("wrongkey").await;
    h.pair_and_enable().await;
    let (b, shown) = request(&mut h).await;
    let resp = h.phone.respond_with(&shown, &h.phone.device, Decision::Approve, b.number, h.now()).unwrap();
    h.phone_tx.send(&h.phone.pcs[0].pc_id(), &resp, 60, "r").unwrap();
    let s = h.engine.wait(&req_bytes(&b.req), Duration::from_secs(5)).await;
    assert_eq!(s.as_str(), "error");
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_expired_request_cannot_be_approved() {
    let mut h = Harness::new("expiry").await;
    h.pair_and_enable().await;
    let (b, shown) = request(&mut h).await;
    h.advance(60_001);
    let resp = h.phone.respond(&shown, Decision::Approve, b.number, h.now()).unwrap();
    h.phone_tx.send(&h.phone.pcs[0].pc_id(), &resp, 60, "r").unwrap();
    assert_eq!(h.engine.wait(&req_bytes(&b.req), Duration::from_secs(2)).await.as_str(), "expired");
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_replayed_approval_does_not_unlock_a_new_request() {
    let mut h = Harness::new("replay").await;
    h.pair_and_enable().await;
    let (b1, shown1) = request(&mut h).await;
    let resp1 = h.phone.respond(&shown1, Decision::Approve, b1.number, h.now()).unwrap();
    let pc = h.phone.pcs[0].pc_id();
    h.phone_tx.send(&pc, &resp1, 60, "r1").unwrap();
    assert_eq!(h.engine.wait(&req_bytes(&b1.req), Duration::from_secs(5)).await.as_str(), "approved");
    // New attempt; attacker replays the old approval bytes.
    let (b2, _shown2) = request(&mut h).await;
    h.phone_tx.send(&pc, &resp1, 60, "r2").unwrap();
    assert_eq!(h.engine.wait(&req_bytes(&b2.req), Duration::from_millis(700)).await.as_str(), "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn newer_request_supersedes_older() {
    let mut h = Harness::new("supersede").await;
    h.pair_and_enable().await;
    let (b1, shown1) = request(&mut h).await;
    let (b2, _) = request(&mut h).await;
    let resp1 = h.phone.respond(&shown1, Decision::Approve, b1.number, h.now()).unwrap();
    h.phone_tx.send(&h.phone.pcs[0].pc_id(), &resp1, 60, "r").unwrap();
    assert_eq!(h.engine.wait(&req_bytes(&b1.req), Duration::from_secs(1)).await.as_str(), "expired", "superseded request is dead");
    assert_eq!(h.engine.wait(&req_bytes(&b2.req), Duration::from_millis(300)).await.as_str(), "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_denials_trigger_cooldown() {
    let mut h = Harness::new("cooldown").await;
    h.pair_and_enable().await;
    for _ in 0..3 {
        let (b, shown) = request(&mut h).await;
        let resp = h.phone.respond(&shown, Decision::Deny, 0, h.now()).unwrap();
        h.phone_tx.send(&h.phone.pcs[0].pc_id(), &resp, 60, "r").unwrap();
        assert_eq!(h.engine.wait(&req_bytes(&b.req), Duration::from_secs(5)).await.as_str(), "denied");
    }
    let e = h.engine.begin(Scenario::Unlock, "x", "").unwrap_err();
    assert_eq!(e.code(), "cooldown");
    assert!(h.engine.gate_status().cooldown_s > 0);
    h.advance(61_000);
    assert!(h.engine.begin(Scenario::Unlock, "x", "").is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn unpaired_pc_cannot_request_and_phone_unpair_keeps_enforcement() {
    let mut h = Harness::new("unpair").await;
    assert_eq!(h.engine.begin(Scenario::Unlock, "x", "").unwrap_err().code(), "not_paired");
    h.pair_and_enable().await;
    // Phone unpairs this PC.
    let unpair = h.phone.seal_to_pc(0, Kind::Unpair, &pg_core::messages::Unpair { at: h.now() }.encode()).unwrap();
    h.phone_tx.send(&h.phone.pcs[0].pc_id(), &unpair, 60, "u").unwrap();
    for _ in 0..200 {
        if !h.engine.gate_status().paired {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let st = h.engine.gate_status();
    assert!(!st.paired);
    assert!(st.enforce, "enforcement stays on: recovery codes only (fail-secure)");
    assert_eq!(h.engine.begin(Scenario::Unlock, "x", "").unwrap_err().code(), "not_paired");
}

#[tokio::test(flavor = "multi_thread")]
async fn disabling_protection_requires_phone_approval() {
    let mut h = Harness::new("disable").await;
    h.pair_and_enable().await;
    let b = h.engine.disable_begin().unwrap().expect("approval needed");
    let (from, body) = h.phone_next_kind(Kind::ApprovalRequest).await;
    let now = h.now();
    let shown = h.phone.receive(&from, &body, now).unwrap().unwrap();
    assert_eq!(shown.request.scenario, Scenario::DisableProtection);
    let resp = h.phone.respond(&shown, Decision::Deny, 0, h.now()).unwrap();
    h.phone_tx.send(&h.phone.pcs[0].pc_id(), &resp, 60, "r").unwrap();
    assert_eq!(h.engine.disable_wait(&req_bytes(&b.req), Duration::from_secs(5)).await.unwrap().as_str(), "denied");
    assert!(h.engine.is_enforcing());
    let b = h.engine.disable_begin().unwrap().unwrap();
    let (from, body) = h.phone_next_kind(Kind::ApprovalRequest).await;
    let now = h.now();
    let shown = h.phone.receive(&from, &body, now).unwrap().unwrap();
    let resp = h.phone.respond(&shown, Decision::Approve, b.number, h.now()).unwrap();
    h.phone_tx.send(&h.phone.pcs[0].pc_id(), &resp, 60, "r").unwrap();
    assert_eq!(h.engine.disable_wait(&req_bytes(&b.req), Duration::from_secs(5)).await.unwrap().as_str(), "approved");
    assert!(!h.engine.is_enforcing());
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_outage_is_reported_never_bypassed() {
    let relay = pg_e2e::start_relay().await;
    let (proxy, cut) = pg_e2e::start_cuttable_proxy(&relay).await;
    let phone = pg_sim::SimPhone::new("P");
    let mut h = Harness::with_phone("relaydown", proxy, phone).await;
    h.pair_and_enable().await;
    cut.send(true).unwrap();
    for _ in 0..300 {
        if h.engine.gate_status().relay == "down" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let st = h.engine.gate_status();
    assert_eq!(st.relay, "down");
    assert!(st.enforce, "an outage never switches protection off");
    assert_eq!(h.engine.begin(Scenario::Unlock, "x", "").unwrap_err().code(), "relay_down");
}

//! Feature 004: phone-initiated disable and passwordless credential release, end to end through a
//! real relay. The security invariants (nothing released without a verified approval; only the
//! pinned approve key can disable) are what these prove; the Windows logon submit itself is a
//! hardware-only step (gate G11).

use std::time::Duration;

use pg_core::messages::{Decision, Kind};
use pg_e2e::{req_bytes, Harness};

// -- Phone-initiated disable (US2) ------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn phone_command_disables_protection() {
    let mut h = Harness::new("cmd-disable").await;
    h.pair_and_enable().await;
    assert!(h.engine.is_enforcing());
    let cmd = h.phone.disable_command(0, h.now(), true).unwrap();
    h.engine.handle_incoming(&h.phone.id(), &crate_pc(&h), &cmd);
    for _ in 0..200 {
        if !h.engine.is_enforcing() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!h.engine.is_enforcing(), "a valid phone command turns protection off");
    assert!(h.engine.history_items(5).iter().any(|r| r.outcome.contains("phone_command")));
}

#[tokio::test(flavor = "multi_thread")]
async fn replayed_disable_command_is_ignored() {
    let mut h = Harness::new("cmd-replay").await;
    h.pair_and_enable().await;
    let cmd = h.phone.disable_command(0, h.now(), true).unwrap();
    let pc = crate_pc(&h);
    h.engine.handle_incoming(&h.phone.id(), &pc, &cmd);
    for _ in 0..200 {
        if !h.engine.is_enforcing() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!h.engine.is_enforcing());
    // Re-arm and replay the exact same command bytes: must be rejected (msg-id + cmd-id seen).
    h.engine.enable().unwrap();
    h.engine.handle_incoming(&h.phone.id(), &pc, &cmd);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(h.engine.is_enforcing(), "a replayed command must not disable again");
}

#[tokio::test(flavor = "multi_thread")]
async fn disable_command_with_wrong_authority_is_ignored() {
    let mut h = Harness::new("cmd-wrongkey").await;
    h.pair_and_enable().await;
    // Authority signed by the device key, not the approve key.
    let cmd = h.phone.disable_command(0, h.now(), false).unwrap();
    h.engine.handle_incoming(&h.phone.id(), &crate_pc(&h), &cmd);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(h.engine.is_enforcing(), "only the pinned approve key may disable");
}

// -- Passwordless credential release (US1) ----------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn passwordless_releases_only_after_a_matching_approval() {
    let mut h = Harness::new("pwless").await;
    h.pair_and_enable().await;
    // Opt in: store the password, approve on the phone to arm.
    let b = h.engine.passwordless_enable("DESK\\owner", "s3cret").unwrap();
    approve_req(&mut h, &b.req, b.number).await;
    assert_eq!(h.engine.passwordless_enable_wait(&req_bytes(&b.req), Duration::from_secs(5)).await.unwrap().as_str(), "approved");
    assert!(h.engine.passwordless_status().0, "armed");

    // A sign-in: begin, approve, then the tile may release exactly once.
    let s = h.engine.begin(pg_core::messages::Scenario::Logon, "DESK\\owner", "").unwrap();
    assert!(h.engine.release(&req_bytes(&s.req)).is_err(), "no release before approval");
    approve_req(&mut h, &s.req, s.number).await;
    assert_eq!(h.engine.wait(&req_bytes(&s.req), Duration::from_secs(5)).await.as_str(), "approved");
    let cred = h.engine.release(&req_bytes(&s.req)).expect("released after approval");
    // The released buffer carries the stored password as UTF-16 (it is a logon serialization).
    let pw16: Vec<u8> = "s3cret".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(cred.windows(pw16.len()).any(|w| w == pw16));
    assert!(h.engine.release(&req_bytes(&s.req)).is_err(), "release is one-shot");
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_passwordless_optin_stores_nothing() {
    let mut h = Harness::new("pwless-deny").await;
    h.pair_and_enable().await;
    let b = h.engine.passwordless_enable("DESK\\owner", "s3cret").unwrap();
    let (from, body) = h.phone_next_kind(Kind::ApprovalRequest).await;
    let now = h.now();
    let shown = h.phone.receive(&from, &body, now).unwrap().unwrap();
    let resp = h.phone.respond(&shown, Decision::Deny, 0, h.now()).unwrap();
    h.phone_tx.send(&pc_id(&h), &resp, 60, "r").unwrap();
    assert_eq!(h.engine.passwordless_enable_wait(&req_bytes(&b.req), Duration::from_secs(5)).await.unwrap().as_str(), "denied");
    assert!(!h.engine.passwordless_status().0, "denied opt-in must arm nothing");
    // And no release is possible on a fresh approved request when not armed.
    let s = h.engine.begin(pg_core::messages::Scenario::Logon, "x", "").unwrap();
    approve_req(&mut h, &s.req, s.number).await;
    h.engine.wait(&req_bytes(&s.req), Duration::from_secs(5)).await;
    assert!(h.engine.release(&req_bytes(&s.req)).is_err(), "not_passwordless");
}

#[tokio::test(flavor = "multi_thread")]
async fn turning_passwordless_off_wipes_it() {
    let mut h = Harness::new("pwless-off").await;
    h.pair_and_enable().await;
    let b = h.engine.passwordless_enable("DESK\\owner", "s3cret").unwrap();
    approve_req(&mut h, &b.req, b.number).await;
    h.engine.passwordless_enable_wait(&req_bytes(&b.req), Duration::from_secs(5)).await.unwrap();
    assert!(h.engine.passwordless_status().0);
    h.engine.passwordless_disable().unwrap();
    assert!(!h.engine.passwordless_status().0);
    // Reloading from disk stays off (wiped, not just forgotten).
    h.restart_engine().await;
    assert!(!h.engine.passwordless_status().0);
}

// -- helpers ----------------------------------------------------------------------------------

fn pc_id(h: &Harness) -> pg_core::crypto::Id {
    pg_core::crypto::id_of(&h.engine.pc_public())
}
fn crate_pc(h: &Harness) -> pg_core::crypto::Id {
    pc_id(h)
}

/// Approves the next pending approval request for `req` with the matching number.
async fn approve_req(h: &mut Harness, req: &str, number: u64) {
    let (from, body) = h.phone_next_kind(Kind::ApprovalRequest).await;
    let now = h.now();
    let shown = h.phone.receive(&from, &body, now).unwrap().unwrap();
    assert_eq!(shown.request.match_number, number);
    assert_eq!(pg_core::crypto::b64::encode(&shown.request.req_id), req);
    let resp = h.phone.respond(&shown, Decision::Approve, number, h.now()).unwrap();
    h.phone_tx.send(&pc_id(h), &resp, 60, "r").unwrap();
}

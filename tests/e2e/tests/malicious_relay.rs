//! Adversarial suite: the relay (or network) is controlled by an attacker who has the full
//! source code. It can deliver arbitrary bytes, claim any sender id, replay, drop, reorder, and
//! substitute pairing messages. None of this may produce an accepted approval or pairing
//! (Constitution II, FR-019, SC-003).

use std::time::Duration;

use pg_core::crypto::{self, Id};
use pg_core::envelope::{self, Dir, SealParams};
use pg_core::messages::{self, ApprovalRequest, ApprovalResponse, Decision, Kind, Scenario};
use pg_core::pairing::PcPairing;
use pg_core::signer::{Signer, SoftSigner};
use pg_e2e::{req_bytes, Harness};

async fn pending_request(h: &mut Harness) -> (pg_agent::engine::BeginOk, pg_sim::ShownRequest, Vec<u8>) {
    let b = h.engine.begin(Scenario::Unlock, "DESK\\owner", "").unwrap();
    let (from, body) = h.phone_next_kind(Kind::ApprovalRequest).await;
    let now = h.now();
    let shown = h.phone.receive(&from, &body, now).unwrap().unwrap();
    (b, shown, body)
}

fn ids(h: &Harness) -> (Id, Id) {
    (h.phone.id(), h.phone.pcs[0].pc_id())
}

#[tokio::test(flavor = "multi_thread")]
async fn malicious_relay_bit_flips_never_approve_and_never_consume() {
    let mut h = Harness::new("mal-flip").await;
    h.pair_and_enable().await;
    let (b, shown, _) = pending_request(&mut h).await;
    let genuine = h.phone.respond(&shown, Decision::Approve, b.number, h.now()).unwrap();
    let (phone_id, pc_id) = ids(&h);
    let id = req_bytes(&b.req);
    // Flip one bit at a spread of positions covering labels, ids, nonce, ciphertext and signature.
    let step = (genuine.len() / 97).max(1);
    for pos in (0..genuine.len()).step_by(step) {
        let mut t = genuine.clone();
        t[pos] ^= 0x01;
        h.engine.handle_incoming(&phone_id, &pc_id, &t);
        assert_eq!(h.engine.poll_peek(&id), "pending", "tampered byte {pos} changed the request state");
    }
    // Truncations and extensions.
    for cut in [1usize, 10, 64, genuine.len() / 2] {
        h.engine.handle_incoming(&phone_id, &pc_id, &genuine[..genuine.len() - cut]);
    }
    let mut ext = genuine.clone();
    ext.push(0);
    h.engine.handle_incoming(&phone_id, &pc_id, &ext);
    assert_eq!(h.engine.poll_peek(&id), "pending");
    // The genuine response still works afterwards: tampering did not burn the request.
    h.engine.handle_incoming(&phone_id, &pc_id, &genuine);
    assert_eq!(h.engine.wait(&id, Duration::from_secs(2)).await.as_str(), "approved");
}

#[tokio::test(flavor = "multi_thread")]
async fn malicious_relay_forged_sender_id_is_ignored() {
    let mut h = Harness::new("mal-from").await;
    h.pair_and_enable().await;
    let (b, shown, _) = pending_request(&mut h).await;
    let genuine = h.phone.respond(&shown, Decision::Approve, b.number, h.now()).unwrap();
    let (_, pc_id) = ids(&h);
    h.engine.handle_incoming(&[0xAB; 32], &pc_id, &genuine);
    assert_eq!(h.engine.poll_peek(&req_bytes(&b.req)), "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn malicious_relay_cannot_mint_an_approval_even_knowing_k_pair() {
    // Worst case: the attacker somehow learned k_pair (e.g. read a phone backup) and the exact
    // request. Approvals still require the phone's hardware approve key, so nothing is accepted.
    let mut h = Harness::new("mal-mint").await;
    h.pair_and_enable().await;
    let (b, shown, _) = pending_request(&mut h).await;
    let (phone_id, pc_id) = ids(&h);
    let attacker = SoftSigner::generate().unwrap();
    let resp = ApprovalResponse::create(&attacker, shown.request.digest(), Decision::Approve, b.number, h.now()).unwrap();
    for sealer in [&attacker as &dyn Signer, &h.phone.device as &dyn Signer] {
        // Sealed with the attacker's key (envelope check fails) and, worse, with the genuine
        // device key (envelope passes, decision signature fails).
        let sp = SealParams { k_pair: &h.phone.pcs[0].k_pair, dir: Dir::PhoneToPc, kind: Kind::ApprovalResponse, from: phone_id, to: pc_id, signer: sealer };
        let (env, _) = envelope::seal(&sp, &resp.encode()).unwrap();
        h.engine.handle_incoming(&phone_id, &pc_id, &messages::wire(Kind::ApprovalResponse, &env));
    }
    let s = h.engine.wait(&req_bytes(&b.req), Duration::from_millis(300)).await;
    assert_ne!(s.as_str(), "approved");
}

#[tokio::test(flavor = "multi_thread")]
async fn malicious_relay_replay_of_consumed_approval_is_ignored() {
    let mut h = Harness::new("mal-replay").await;
    h.pair_and_enable().await;
    let (b, shown, _) = pending_request(&mut h).await;
    let genuine = h.phone.respond(&shown, Decision::Approve, b.number, h.now()).unwrap();
    let (phone_id, pc_id) = ids(&h);
    h.engine.handle_incoming(&phone_id, &pc_id, &genuine);
    let id = req_bytes(&b.req);
    assert_eq!(h.engine.wait(&id, Duration::from_secs(2)).await.as_str(), "approved");
    for _ in 0..3 {
        h.engine.handle_incoming(&phone_id, &pc_id, &genuine);
    }
    assert_eq!(h.engine.wait(&id, Duration::from_millis(100)).await.as_str(), "expired", "approval cannot be reused");
    // And a fresh attempt is not unlocked by the old bytes.
    let (b2, _, _) = pending_request(&mut h).await;
    h.engine.handle_incoming(&phone_id, &pc_id, &genuine);
    assert_eq!(h.engine.poll_peek(&req_bytes(&b2.req)), "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn malicious_relay_cannot_read_request_contents() {
    let mut h = Harness::new("mal-read").await;
    h.pair_and_enable().await;
    let (b, _, wire) = pending_request(&mut h).await;
    let hay = String::from_utf8_lossy(&wire).to_string();
    assert!(!hay.contains("DESK"), "account name visible to relay");
    assert!(!hay.contains("Test PC"), "pc name visible to relay");
    // The match number is not recoverable from the wire either (only inside AEAD).
    let (_, payload) = messages::unwire(&wire).unwrap();
    let env = envelope::Envelope::parse(&payload).unwrap();
    assert!(!env.ct.windows(8).any(|w| w == b.number.to_be_bytes()));
}

#[tokio::test(flavor = "multi_thread")]
async fn malicious_relay_tampered_or_forged_requests_are_not_shown_on_phone() {
    let mut h = Harness::new("mal-req").await;
    h.pair_and_enable().await;
    let _ = h.engine.begin(Scenario::Unlock, "DESK\\owner", "").unwrap();
    let (from, body) = h.phone_next_kind(Kind::ApprovalRequest).await;
    let now = h.now();
    let mut t = body.clone();
    let n = t.len();
    t[n - 70] ^= 0x80;
    assert!(h.phone.receive(&from, &t, now).is_err(), "tampered request shown");
    // Attacker-made request with its own key, claiming to be the PC.
    let attacker = SoftSigner::generate().unwrap();
    let pc = &h.phone.pcs[0];
    let req = ApprovalRequest {
        req_id: [1; 16],
        nonce: [2; 32],
        pc_id: pc.pc_id(),
        phone_id: h.phone.id(),
        issued_at: now,
        expires_at: now + 60_000,
        scenario: Scenario::Unlock,
        account: "evil".into(),
        pc_name: "Test PC".into(),
        remote_addr: String::new(),
        match_number: 42,
    };
    let sp = SealParams { k_pair: &pc.k_pair, dir: Dir::PcToPhone, kind: Kind::ApprovalRequest, from: pc.pc_id(), to: h.phone.id(), signer: &attacker };
    let (env, _) = envelope::seal(&sp, &req.encode()).unwrap();
    let pc_id = pc.pc_id();
    assert!(h.phone.receive(&pc_id, &messages::wire(Kind::ApprovalRequest, &env), now).is_err());
    // Replay of the genuine request to the phone is also rejected.
    assert!(h.phone.receive(&from, &body, now).is_ok());
    assert!(h.phone.receive(&from, &body, now).is_err(), "replayed request shown twice");
}

#[tokio::test(flavor = "multi_thread")]
async fn malicious_relay_offer_substitution_is_detected_by_phone() {
    let mut h = Harness::new("mal-offer").await;
    let (uri, _) = h.engine.pair_start().unwrap();
    let attacker = SoftSigner::generate().unwrap();
    let (_, evil_offer) = PcPairing::start(&attacker, &h.relay_url, "Test PC", h.now()).unwrap();
    let p = h.phone.begin_pairing(&uri).unwrap();
    let now = h.now();
    let r = h.phone.answer_offer(p, &messages::wire(Kind::PairOffer, &evil_offer), now);
    assert!(r.is_err(), "phone accepted an offer whose key does not match the QR");
}

#[tokio::test(flavor = "multi_thread")]
async fn malicious_relay_join_substitution_fails_pairing() {
    let mut h = Harness::new("mal-join").await;
    let (uri, _) = h.engine.pair_start().unwrap();
    // The relay saw the offer but never the QR (psk). It forges a join with a guessed psk.
    let mut fake_qr = pg_core::pairing::PairingQr::parse(&uri).unwrap();
    fake_qr.psk = [0x55; 32];
    let mut evil_phone = pg_sim::SimPhone::new("Evil");
    let p = evil_phone.begin_pairing(&fake_qr.to_uri()).unwrap();
    h.phone_tx.subscribe(&p.slot()).unwrap();
    let (_, _, offer) = h.phone_next().await;
    let now = h.now();
    let (join, _) = evil_phone.answer_offer(p, &offer, now).unwrap();
    let slot = pg_core::pairing::slot(&fake_qr.pairing_id);
    h.engine.handle_incoming(&evil_phone.id(), &slot, &join);
    let poll = h.wait_pair_state("failed").await;
    assert!(poll.error.is_some());
    assert_eq!(h.engine.status_json()["paired"], false);
    // The burned pairing cannot be completed by the genuine phone either.
    let p = h.phone.begin_pairing(&uri).unwrap();
    let (join2, _) = h.phone.answer_offer(p, &offer, now).unwrap();
    h.engine.handle_incoming(&h.phone.id(), &slot, &join2);
    assert_eq!(h.engine.pair_poll().state, "failed");
    assert_eq!(h.engine.status_json()["paired"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn malicious_relay_confirm_forgery_cannot_complete_pairing() {
    let mut h = Harness::new("mal-confirm").await;
    let (uri, _) = h.engine.pair_start().unwrap();
    let p = h.phone.begin_pairing(&uri).unwrap();
    h.phone_tx.subscribe(&p.slot()).unwrap();
    let (_, _, offer) = h.phone_next().await;
    let now = h.now();
    let (join, _) = h.phone.answer_offer(p, &offer, now).unwrap();
    let slot = h.phone.pending_slot().unwrap();
    h.phone_tx.send_slot(&slot, &join, 300, "join").unwrap();
    h.wait_pair_state("confirm").await;
    // Relay forges the phone's confirmation MAC.
    let forged = messages::wire(Kind::PairConfirm, &pg_core::pairing::encode_confirm(pg_core::pairing::CONFIRM_LABEL, &[0; 32]));
    h.engine.handle_incoming(&h.phone.id(), &slot, &forged);
    let _ = h.engine.pair_decide(true, false);
    assert_eq!(h.engine.status_json()["paired"], false);
    assert_eq!(h.engine.pair_poll().state, "failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn malicious_relay_cross_pc_response_is_rejected() {
    // A response legitimately produced for PC A is redirected to PC B (same phone).
    let relay = pg_e2e::start_relay().await;
    let mut a = Harness::with_phone("mal-xa", relay.clone(), pg_sim::SimPhone::new("P")).await;
    a.pair_and_enable().await;
    let mut b = Harness::new("mal-xb").await;
    b.pair_and_enable().await;
    let (ba, shown_a, _) = pending_request(&mut a).await;
    let (bb, _, _) = pending_request(&mut b).await;
    let resp_for_a = a.phone.respond(&shown_a, Decision::Approve, ba.number, a.now()).unwrap();
    let b_pc = crypto::id_of(&b.engine.pc_public());
    b.engine.handle_incoming(&a.phone.id(), &b_pc, &resp_for_a);
    b.engine.handle_incoming(&b.phone.id(), &b_pc, &resp_for_a);
    assert_eq!(b.engine.poll_peek(&req_bytes(&bb.req)), "pending");
}

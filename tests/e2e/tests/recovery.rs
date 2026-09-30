//! US3: recovery codes and offline phone codes (T039-T043).

use pg_core::messages::{Kind, NoticeKind, Scenario};
use pg_e2e::{req_bytes, Harness};

#[tokio::test(flavor = "multi_thread")]
async fn recovery_code_is_single_use_and_reported_to_phone() {
    let mut h = Harness::new("recovery").await;
    let codes = h.pair_and_enable().await;
    // Drain the protection-enabled notice.
    let (from, body) = h.phone_next_kind(Kind::Notice).await;
    let now = h.now();
    h.phone.receive(&from, &body, now).unwrap();
    let c = h.engine.recovery_verify(&codes[1], "DESK\\owner").unwrap();
    assert!(c.valid);
    assert_eq!(c.remaining, 9);
    assert!(!h.engine.recovery_verify(&codes[1], "DESK\\owner").unwrap().valid, "single use");
    let (from, body) = h.phone_next_kind(Kind::Notice).await;
    let now = h.now();
    h.phone.receive(&from, &body, now).unwrap();
    assert!(h.phone.notices.iter().any(|n| n.kind == NoticeKind::RecoveryCodeUsed));
    assert_eq!(h.engine.history_items(10).iter().filter(|r| r.outcome == "recovery_code").count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_lockout_after_five_failures() {
    let mut h = Harness::new("lockout").await;
    let codes = h.pair_and_enable().await;
    for i in 0..5 {
        let c = h.engine.recovery_verify("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-A0", "x").unwrap();
        assert!(!c.valid);
        assert_eq!(c.locked_s > 0, i == 4);
    }
    let c = h.engine.recovery_verify(&codes[2], "x").unwrap();
    assert!(!c.valid, "valid code refused while locked");
    assert!(c.locked_s > 0);
    h.advance(61_000);
    assert!(h.engine.recovery_verify(&codes[2], "x").unwrap().valid);
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_code_unlocks_without_network_path() {
    let mut h = Harness::new("offline").await;
    h.pair_and_enable().await;
    let (chal, qr, exp) = h.engine.offline_begin(Scenario::Unlock, "DESK\\owner").unwrap();
    assert_eq!(exp, 60);
    let code = h.phone.offline_code(&qr, 0, h.now()).unwrap();
    let id = req_bytes(&chal);
    let bad = h.engine.offline_verify(&id, "0000000000").unwrap();
    assert!(!bad.valid || code == "0000000000");
    assert_eq!(bad.attempts_left, 4);
    assert!(h.engine.offline_verify(&id, &code).unwrap().valid);
    assert!(!h.engine.offline_verify(&id, &code).unwrap().valid, "challenge is single-use");
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_challenge_expires_and_limits_attempts() {
    let mut h = Harness::new("offline-exp").await;
    h.pair_and_enable().await;
    let (chal, qr, _) = h.engine.offline_begin(Scenario::Unlock, "u").unwrap();
    let code = h.phone.offline_code(&qr, 0, h.now()).unwrap();
    h.advance(60_001);
    assert!(!h.engine.offline_verify(&req_bytes(&chal), &code).unwrap().valid, "expired");

    let (chal, qr, _) = h.engine.offline_begin(Scenario::Unlock, "u").unwrap();
    let code = h.phone.offline_code(&qr, 0, h.now()).unwrap();
    let id = req_bytes(&chal);
    let wrong = if code == "1111111111" { "2222222222" } else { "1111111111" };
    for _ in 0..5 {
        h.engine.offline_verify(&id, wrong).unwrap();
    }
    assert!(!h.engine.offline_verify(&id, &code).unwrap().valid, "attempts exhausted / locked out");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_code_can_disable_protection() {
    let mut h = Harness::new("disable-rec").await;
    let codes = h.pair_and_enable().await;
    assert!(!h.engine.disable_recovery("bad").unwrap().valid);
    assert!(h.engine.is_enforcing());
    assert!(h.engine.disable_recovery(&codes[7]).unwrap().valid);
    assert!(!h.engine.is_enforcing());
}

#[test]
fn recovery_file_is_shared_with_credential_provider_path() {
    // The CP verifies codes directly from recovery.json when the agent is down, using the same
    // function; prove it consumes codes in the same store.
    let dir = std::env::temp_dir().join(format!("pg-e2e-shared-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let paths = pg_agent::state::Paths::new(&dir);
    let (set, codes) = pg_core::recovery::RecoverySet::generate().unwrap();
    pg_core::store::write_json_atomic(&paths.recovery(), &set).unwrap();
    assert!(pg_agent::engine::verify_recovery_file(&paths, &codes[0], 1).unwrap().valid);
    assert!(!pg_agent::engine::verify_recovery_file(&paths, &codes[0], 2).unwrap().valid);
    let _ = std::fs::remove_dir_all(&dir);
}

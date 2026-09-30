//! US2: pairing through a real relay (T026).

use pg_e2e::Harness;

#[tokio::test(flavor = "multi_thread")]
async fn e2e_pairing_completes_and_pins_keys() {
    let mut h = Harness::new("pair").await;
    let sas = h.pair().await;
    assert_eq!(sas.len(), 6);
    let st = h.engine.status_json();
    assert_eq!(st["paired"], true);
    assert_eq!(st["phone_name"], "Pixel Test");
    assert_eq!(st["attestation"]["status"], "verified");
    assert_eq!(h.phone.pcs.len(), 1);
    assert_eq!(h.phone.pcs[0].pc_pub, h.engine.pc_public());
}

#[tokio::test(flavor = "multi_thread")]
async fn enable_requires_pairing_and_confirmed_recovery_code() {
    let mut h = Harness::new("enable").await;
    assert!(h.engine.enable().is_err(), "cannot enable before pairing");
    h.pair().await;
    assert!(h.engine.enable().is_err(), "cannot enable before recovery codes exist");
    let codes = h.engine.recovery_generate().unwrap();
    assert_eq!(codes.len(), 10);
    assert!(h.engine.enable().is_err(), "cannot enable before a code is typed back");
    assert!(!h.engine.recovery_confirm("0000-0000-0000-0000-0000-0000-00").unwrap());
    assert!(h.engine.recovery_confirm(&codes[4]).unwrap());
    h.engine.enable().unwrap();
    assert!(h.engine.is_enforcing());
    // While enforcing, pairing/unpairing/settings changes are refused.
    assert!(h.engine.pair_start().is_err());
    assert!(h.engine.unpair().is_err());
    assert!(h.engine.settings_set(None, Some("New name"), None).is_err());
    assert!(h.engine.recovery_generate().is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn unverified_attestation_requires_explicit_acceptance() {
    // Engine trusts only Google's roots here, so the simulator's chains are "unverified".
    let relay = pg_e2e::start_relay().await;
    let phone = pg_sim::SimPhone::new("NoAttest");
    let mut h = Harness::with_phone("unverified", relay, phone).await;
    let engine_cfg_root_is_sim = h.engine.status_json(); // sanity: engine is up
    assert_eq!(engine_cfg_root_is_sim["paired"], false);
    // Re-open an engine with Google roots only over the same relay.
    use pg_agent::engine::{Engine, EngineConfig};
    use pg_agent::keys::MemoryBackend;
    use pg_agent::state::Paths;
    use std::sync::Arc;
    let dir = std::env::temp_dir().join(format!("pg-e2e-google-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut cfg = EngineConfig::production(Paths::new(&dir), "Strict PC".into(), pg_agent::probe::Platform::fake().0);
    let c = h.clock.clone();
    cfg.clock = Arc::new(move || c.load(std::sync::atomic::Ordering::SeqCst));
    let strict = Engine::open(Arc::new(MemoryBackend::generate().unwrap()), cfg).unwrap();
    strict.settings_set(Some(&h.relay_url), None, None).unwrap();
    tokio::spawn(strict.clone().run_relay());
    for _ in 0..200 {
        if strict.gate_status().relay == "up" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let (uri, _) = strict.pair_start().unwrap();
    let p = h.phone.begin_pairing(&uri).unwrap();
    h.phone_tx.subscribe(&p.slot()).unwrap();
    let (_, _, offer) = h.phone_next().await;
    let now = h.now();
    let (join, _) = h.phone.answer_offer(p, &offer, now).unwrap();
    let slot = h.phone.pending_slot().unwrap();
    h.phone_tx.send_slot(&slot, &join, 300, "join").unwrap();
    let mut poll = strict.pair_poll();
    for _ in 0..300 {
        poll = strict.pair_poll();
        if poll.state == "confirm" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(poll.state, "confirm");
    assert!(!poll.attestation.unwrap().is_verified());
    assert!(strict.pair_decide(true, false).is_err(), "must refuse without explicit acceptance");
    h.phone_tx.send_slot(&slot, &h.phone.confirm_pairing().unwrap(), 300, "confirm").unwrap();
    for _ in 0..200 {
        if strict.pair_poll().phone_confirmed {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    strict.pair_decide(true, true).unwrap();
    let st = strict.status_json();
    assert_eq!(st["paired"], true);
    assert_eq!(st["attestation"]["status"], "unverified");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn owner_rejecting_sas_aborts_pairing() {
    let mut h = Harness::new("reject").await;
    let (uri, _) = h.engine.pair_start().unwrap();
    let p = h.phone.begin_pairing(&uri).unwrap();
    h.phone_tx.subscribe(&p.slot()).unwrap();
    let (_, _, offer) = h.phone_next().await;
    let now = h.now();
    let (join, _) = h.phone.answer_offer(p, &offer, now).unwrap();
    let slot = h.phone.pending_slot().unwrap();
    h.phone_tx.send_slot(&slot, &join, 300, "join").unwrap();
    h.wait_pair_state("confirm").await;
    h.engine.pair_decide(false, false).unwrap();
    assert_eq!(h.engine.pair_poll().state, "failed");
    assert_eq!(h.engine.status_json()["paired"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_qr_cannot_be_used() {
    let mut h = Harness::new("expired-qr").await;
    let (uri, _) = h.engine.pair_start().unwrap();
    h.advance(pg_core::pairing::PAIRING_LIFETIME_MS + 1);
    assert_eq!(h.engine.pair_poll().state, "failed");
    let p = h.phone.begin_pairing(&uri).unwrap();
    h.phone_tx.subscribe(&p.slot()).unwrap();
    let (_, _, offer) = h.phone_next().await;
    let now = h.now();
    assert!(h.phone.answer_offer(p, &offer, now).is_err(), "phone refuses an expired offer");
}

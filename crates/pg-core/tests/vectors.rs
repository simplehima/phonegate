//! Shared protocol test vectors (`protocol/vectors/v1.json`), consumed by the Android test suite.
//!
//! `PG_WRITE_VECTORS=1 cargo test -p pg-core --test vectors` regenerates the file; otherwise the
//! test fails if the Rust implementation no longer reproduces it byte for byte.

use std::path::PathBuf;

use pg_core::crypto::{self, b64, EphemeralKey};
use pg_core::encoding::Enc;
use pg_core::envelope::{self, Dir, SealParams};
use pg_core::messages::{self, ApprovalRequest, ApprovalResponse, BitLocker, Decision, Kind, Notice, NoticeKind, Scenario, Status};
use pg_core::offline::OfflineChallenge;
use pg_core::pairing::{self, PairJoin, PairOffer, PairingQr, TranscriptInput};
use pg_core::recovery;
use pg_core::signer::{Signer, SoftSigner};
use serde_json::{json, Value};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn key(seed: u8) -> SoftSigner {
    let mut s = [seed; 32];
    s[0] = 0x01; // keep well below the curve order
    SoftSigner::from_bytes(&s).unwrap()
}

fn build() -> Value {
    let pc = key(0x11);
    let dev = key(0x22);
    let app = key(0x33);
    let pc_eph = EphemeralKey::from_bytes(&[0x44; 32]).unwrap();
    let ph_eph = EphemeralKey::from_bytes(&[0x55; 32]).unwrap();

    // --- encoding & primitives ---
    let enc_sample = Enc::new("phonegate/v1/test").bytes(&[1, 2, 3]).str("hé").u64(0x0102030405060708).list(&[b"a".to_vec(), vec![]]).finish();
    let hk = crypto::hkdf(b"input key", b"salt", b"info");
    let mac = crypto::hmac(b"key", b"message");

    // --- pairing ---
    let qr = PairingQr {
        relay_url: "https://relay.example.com".into(),
        pairing_id: [0xA1; 16],
        psk: [0xB2; 32],
        pc_pub_hash: crypto::id_of(&pc.public()),
        pc_name: "Desk PC".into(),
    };
    let offer = PairOffer {
        pairing_id: qr.pairing_id,
        pc_pub: pc.public(),
        pc_eph_pub: pc_eph.public(),
        pc_name: qr.pc_name.clone(),
        expires_at: 1_700_000_300_000,
    };
    let offer_payload = offer.encode_signed(&pc).unwrap();
    let th = pairing::transcript(&TranscriptInput {
        pairing_id: &qr.pairing_id,
        pc_pub: &pc.public(),
        pc_eph_pub: &pc_eph.public(),
        pc_name: &qr.pc_name,
        phone_device_pub: &dev.public(),
        phone_approve_pub: &app.public(),
        phone_eph_pub: &ph_eph.public(),
        phone_name: "Pixel 9",
    });
    let shared = ph_eph.agree(&pc_eph.public()).unwrap();
    assert_eq!(*shared, *pc_eph.agree(&ph_eph.public()).unwrap());
    let k_pair = pairing::k_pair(&shared, &qr.psk, &th);
    let sb = pairing::join_sig_bytes(&th);
    let join = PairJoin {
        pairing_id: qr.pairing_id,
        phone_device_pub: dev.public(),
        phone_approve_pub: app.public(),
        phone_eph_pub: ph_eph.public(),
        phone_name: "Pixel 9".into(),
        device_chain: vec![vec![0x30, 0x00]],
        approve_chain: vec![],
        sig_device: dev.sign(&sb).unwrap(),
        sig_approve: app.sign(&sb).unwrap(),
    };
    let join_nonce = [0xC3; 12];
    let join_payload = join.seal(&qr.psk, join_nonce).unwrap();

    // --- approval ---
    let pc_id = crypto::id_of(&pc.public());
    let phone_id = crypto::id_of(&dev.public());
    let req = ApprovalRequest {
        req_id: [0xD4; 16],
        nonce: [0xE5; 32],
        pc_id,
        phone_id,
        issued_at: 1_700_000_000_000,
        expires_at: 1_700_000_060_000,
        scenario: Scenario::Unlock,
        account: "DESK\\owner".into(),
        pc_name: "Desk PC".into(),
        remote_addr: String::new(),
        match_number: 42,
    };
    let req_plain = req.encode();
    let env_req = envelope::seal_with(
        &SealParams { k_pair: &k_pair, dir: Dir::PcToPhone, kind: Kind::ApprovalRequest, from: pc_id, to: phone_id, signer: &pc },
        &req_plain,
        [0xF6; 16],
        [0x07; 12],
    )
    .unwrap();
    let resp = ApprovalResponse::create(&app, req.digest(), Decision::Approve, 42, 1_700_000_010_000).unwrap();
    let resp_plain = resp.encode();
    let env_resp = envelope::seal_with(
        &SealParams { k_pair: &k_pair, dir: Dir::PhoneToPc, kind: Kind::ApprovalResponse, from: phone_id, to: pc_id, signer: &dev },
        &resp_plain,
        [0x18; 16],
        [0x29; 12],
    )
    .unwrap();

    // --- offline ---
    let chal = OfflineChallenge {
        pc_id,
        chal_id: [0x3A; 16],
        issued_at: 1_700_000_000_000,
        expires_at: 1_700_000_060_000,
        scenario: Scenario::Logon,
        account: "DESK\\owner".into(),
    };
    let k_off = pairing::k_offline(&k_pair);

    // --- feature 002: status, notices, change-setting ---
    let status = Status {
        seq: 42,
        at: 1_700_000_300_000,
        enforce: true,
        cp_registered: true,
        filter_registered: true,
        files_intact: true,
        watchdog_present: true,
        bitlocker: BitLocker::OnPin,
        netlogon_blocked: false,
        safe_mode: false,
    };
    let status_plain = status.encode();
    let status_env = envelope::seal_with(
        &SealParams { k_pair: &k_pair, dir: Dir::PcToPhone, kind: Kind::Status, from: pc_id, to: phone_id, signer: &pc },
        &status_plain,
        [0x4B; 16],
        [0x5C; 12],
    )
    .unwrap();
    let notice_stopped = Notice { kind: NoticeKind::AgentStopped, at: 1_700_000_400_000, detail: "service stop".into() }.encode();
    let mut change_req = req.clone();
    change_req.scenario = Scenario::ChangeSetting;
    change_req.account = "Allow network sign-ins".into();

    // --- recovery ---
    let code_bytes = [0x5Bu8; 16];
    let rec_salt = [0x6C; 32];
    let rec_hash = crypto::sha256(&Enc::new("phonegate/v1/recovery").bytes(&rec_salt).bytes(&code_bytes).finish());

    json!({
        "version": 1,
        "note": "Generated by crates/pg-core/tests/vectors.rs. Hex unless stated. Signatures are RFC 6979 deterministic; verifiers must accept any valid signature.",
        "encoding": { "sample_hex": hex(&enc_sample) },
        "hkdf": { "ikm": hex(b"input key"), "salt": hex(b"salt"), "info": hex(b"info"), "okm": hex(hk.as_slice()) },
        "hmac": { "key": hex(b"key"), "msg": hex(b"message"), "tag": hex(&mac) },
        "keys": {
            "pc_priv": hex(pc.to_bytes().as_slice()), "pc_pub": hex(&pc.public()), "pc_id": hex(&pc_id),
            "device_priv": hex(dev.to_bytes().as_slice()), "device_pub": hex(&dev.public()), "phone_id": hex(&phone_id),
            "approve_priv": hex(app.to_bytes().as_slice()), "approve_pub": hex(&app.public()),
            "pc_eph_priv": hex(&[0x44; 32]), "pc_eph_pub": hex(&pc_eph.public()),
            "phone_eph_priv": hex(&[0x55; 32]), "phone_eph_pub": hex(&ph_eph.public())
        },
        "pairing": {
            "qr_uri": qr.to_uri(),
            "pairing_id": hex(&qr.pairing_id), "psk": hex(&qr.psk),
            "phone_name": "Pixel 9",
            "slot": hex(&pairing::slot(&qr.pairing_id)),
            "k_join": hex(pairing::k_join(&qr.psk, &qr.pairing_id).as_slice()),
            "attest_challenge": hex(&pairing::attest_challenge(&qr.psk, &qr.pairing_id)),
            "offer_payload": hex(&offer_payload),
            "offer_now": 1_700_000_000_000u64,
            "transcript": hex(&th),
            "ecdh_shared": hex(shared.as_slice()),
            "k_pair": hex(k_pair.as_slice()),
            "sas": pairing::sas(&k_pair),
            "join_sig_bytes": hex(&sb),
            "join_nonce": hex(&join_nonce),
            "join_inner": hex(&join.encode_inner()),
            "join_payload": hex(&join_payload),
            "confirm_phone_payload": hex(&pairing::encode_confirm(pairing::CONFIRM_LABEL, &pairing::confirm_mac(&k_pair, "phone", &th))),
            "complete_pc_payload": hex(&pairing::encode_confirm(pairing::COMPLETE_LABEL, &pairing::confirm_mac(&k_pair, "pc", &th))),
            "k_offline": hex(k_off.as_slice())
        },
        "approval": {
            "request_plain": hex(&req_plain),
            "request_digest": hex(&req.digest()),
            "request_envelope": hex(&env_req),
            "request_wire": hex(&messages::wire(Kind::ApprovalRequest, &env_req)),
            "response_decision_bytes": hex(&messages::decision_signed_bytes(&req.digest(), Decision::Approve, 42, 1_700_000_010_000)),
            "response_plain": hex(&resp_plain),
            "response_envelope": hex(&env_resp)
        },
        "offline": {
            "challenge_body": hex(&chal.body()),
            "qr": chal.to_qr(&pc).unwrap(),
            "code": chal.response_code(&k_off)
        },
        "status": {
            "plain": hex(&status_plain),
            "envelope": hex(&status_env),
            "wire": hex(&messages::wire(Kind::Status, &status_env)),
            "seq": 42u64,
            "notice_agent_stopped": hex(&notice_stopped),
            "request_change_setting": hex(&change_req.encode())
        },
        "recovery": {
            "code_bytes": hex(&code_bytes),
            "code_text": recovery::encode_code(&code_bytes),
            "salt": hex(&rec_salt),
            "salt_b64": b64::encode(&rec_salt),
            "hash": hex(&rec_hash)
        },
        "relay_auth": { "challenge": hex(&[0x7D; 32]), "signed_bytes": hex(&Enc::new("phonegate/v1/relay-auth").bytes(&[0x7D; 32]).finish()) }
    })
}

#[test]
fn vectors_are_current() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../protocol/vectors/v1.json");
    let fresh = serde_json::to_string_pretty(&build()).unwrap() + "\n";
    if std::env::var("PG_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &fresh).unwrap();
    }
    let on_disk = std::fs::read_to_string(&path).expect("vectors missing: run with PG_WRITE_VECTORS=1");
    assert_eq!(on_disk.replace("\r\n", "\n"), fresh, "protocol/vectors/v1.json is stale or the protocol changed");
}

#[test]
fn vectors_self_consistent() {
    // The generated artifacts must also parse/verify through the public API (guards against a
    // vector that encodes a mistake).
    let v = build();
    let unhex = |s: &Value| -> Vec<u8> {
        let s = s.as_str().unwrap();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    };
    let qr = PairingQr::parse(v["pairing"]["qr_uri"].as_str().unwrap()).unwrap();
    let offer = PairOffer::verify(&unhex(&v["pairing"]["offer_payload"]), &qr, 1_700_000_000_000).unwrap();
    assert_eq!(offer.pc_name, "Desk PC");
    let join = PairJoin::open(&unhex(&v["pairing"]["join_payload"]), &qr.psk, &qr.pairing_id).unwrap();
    assert_eq!(join.phone_name, "Pixel 9");
    let pc_pub: [u8; 65] = unhex(&v["keys"]["pc_pub"]).try_into().unwrap();
    let k: [u8; 32] = unhex(&v["pairing"]["k_pair"]).try_into().unwrap();
    let pc_id: [u8; 32] = unhex(&v["keys"]["pc_id"]).try_into().unwrap();
    let phone_id: [u8; 32] = unhex(&v["keys"]["phone_id"]).try_into().unwrap();
    let e = envelope::Envelope::parse(&unhex(&v["approval"]["request_envelope"])).unwrap();
    let plain = e.open(&pc_pub, &k, Dir::PcToPhone, &pc_id, &phone_id).unwrap();
    assert_eq!(ApprovalRequest::decode(&plain).unwrap().match_number, 42);
    assert_eq!(recovery::decode_code(v["recovery"]["code_text"].as_str().unwrap()).unwrap(), [0x5B; 16]);
    let e = envelope::Envelope::parse(&unhex(&v["status"]["envelope"])).unwrap();
    let st = Status::decode(&e.open(&pc_pub, &k, Dir::PcToPhone, &pc_id, &phone_id).unwrap()).unwrap();
    assert_eq!(st.seq, 42);
    assert_eq!(ApprovalRequest::decode(&unhex(&v["status"]["request_change_setting"])).unwrap().scenario, Scenario::ChangeSetting);
}

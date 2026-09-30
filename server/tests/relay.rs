//! Relay integration tests (T012) against a real server on a loopback port.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use pg_core::crypto::{self, b64};
use pg_core::relay_client::{self, Incoming};
use pg_core::signer::{Signer, SoftSigner};
use phonegate_relay::Config;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

async fn start(cfg: Config) -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(phonegate_relay::serve(l, cfg));
    format!("http://{addr}")
}

fn signer() -> Arc<dyn Signer> {
    Arc::new(SoftSigner::generate().unwrap())
}

async fn next_msg(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Incoming>) -> Incoming {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("timed out").expect("closed");
        if !matches!(m, Incoming::Ack { .. }) {
            return m;
        }
    }
}

async fn raw_connect(url: &str) -> (impl SinkExt<Message> + Unpin, impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin, [u8; 32]) {
    let (ws, _) = tokio_tungstenite::connect_async(relay_client::ws_url(url).unwrap()).await.unwrap();
    let (sink, mut stream) = ws.split();
    let hello = stream.next().await.unwrap().unwrap().into_text().unwrap();
    let v: Value = serde_json::from_str(&hello).unwrap();
    let ch = b64::decode_fixed::<32>(v["challenge"].as_str().unwrap()).unwrap();
    (sink, stream, ch)
}

#[tokio::test]
async fn healthz_and_auth_success() {
    let url = start(Config::default()).await;
    let s = signer();
    let (_tx, _rx, id) = relay_client::connect(&url, s.clone()).await.unwrap();
    assert_eq!(id, crypto::id_of(&s.public()));
}

#[tokio::test]
async fn auth_with_wrong_signature_is_refused() {
    let url = start(Config::default()).await;
    let (mut sink, mut stream, ch) = raw_connect(&url).await;
    let a = SoftSigner::generate().unwrap();
    let b = SoftSigner::generate().unwrap();
    // Claims a's key, signs with b's key.
    let sig = b.sign(&relay_client::auth_bytes(&ch)).unwrap();
    let f = json!({"t":"auth","pub":b64::encode(&a.public()),"sig":b64::encode(&sig)});
    let _ = sink.send(Message::Text(f.to_string())).await;
    let reply = stream.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(reply.contains("auth_failed"), "{reply}");
}

#[tokio::test]
async fn auth_replay_of_old_challenge_is_refused() {
    let url = start(Config::default()).await;
    let a = SoftSigner::generate().unwrap();
    let (_s1, _st1, ch1) = raw_connect(&url).await;
    let old_sig = a.sign(&relay_client::auth_bytes(&ch1)).unwrap();
    let (mut sink, mut stream, _ch2) = raw_connect(&url).await;
    let f = json!({"t":"auth","pub":b64::encode(&a.public()),"sig":b64::encode(&old_sig)});
    let _ = sink.send(Message::Text(f.to_string())).await;
    let reply = stream.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(reply.contains("auth_failed"), "{reply}");
}

#[tokio::test]
async fn live_and_queued_delivery() {
    let url = start(Config::default()).await;
    let a = signer();
    let b = signer();
    let b_id = crypto::id_of(&b.public());
    let (atx, _arx, a_id) = relay_client::connect(&url, a).await.unwrap();
    // b offline: message is queued.
    atx.send(&b_id, b"queued-1", 60, "r1").unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (_btx, mut brx, _) = relay_client::connect(&url, b).await.unwrap();
    assert_eq!(next_msg(&mut brx).await, Incoming::Msg { from: a_id, to: b_id, body: b"queued-1".to_vec() });
    // b online: live.
    atx.send(&b_id, b"live-2", 60, "r2").unwrap();
    assert_eq!(next_msg(&mut brx).await, Incoming::Msg { from: a_id, to: b_id, body: b"live-2".to_vec() });
}

#[tokio::test]
async fn sender_identity_is_authenticated_not_claimed() {
    let url = start(Config::default()).await;
    let a = signer();
    let b = signer();
    let b_id = crypto::id_of(&b.public());
    let (atx, _arx, a_id) = relay_client::connect(&url, a).await.unwrap();
    let (_btx, mut brx, _) = relay_client::connect(&url, b).await.unwrap();
    atx.send(&b_id, b"x", 60, "r").unwrap();
    match next_msg(&mut brx).await {
        Incoming::Msg { from, .. } => assert_eq!(from, a_id),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn slot_delivery_is_retained_for_late_subscribers() {
    let url = start(Config::default()).await;
    let pc = signer();
    let phone = signer();
    let slot = [0x42u8; 32];
    let (pctx, mut pcrx, pc_id) = relay_client::connect(&url, pc).await.unwrap();
    pctx.subscribe(&slot).unwrap();
    pctx.send_slot(&slot, b"offer", 300, "o").unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Phone subscribes later and still gets the offer.
    let (phtx, mut phrx, ph_id) = relay_client::connect(&url, phone).await.unwrap();
    phtx.subscribe(&slot).unwrap();
    assert_eq!(next_msg(&mut phrx).await, Incoming::Msg { from: pc_id, to: slot, body: b"offer".to_vec() });
    phtx.send_slot(&slot, b"join", 300, "j").unwrap();
    // PC receives the join but never an echo of its own offer.
    assert_eq!(next_msg(&mut pcrx).await, Incoming::Msg { from: ph_id, to: slot, body: b"join".to_vec() });
}

#[tokio::test]
async fn too_many_slots_refused() {
    let url = start(Config::default()).await;
    let (tx, mut rx, _) = relay_client::connect(&url, signer()).await.unwrap();
    tx.subscribe(&[1; 32]).unwrap();
    tx.subscribe(&[2; 32]).unwrap();
    tx.subscribe(&[3; 32]).unwrap();
    assert_eq!(next_msg(&mut rx).await, Incoming::Error { r#ref: None, code: "too_many_slots".into() });
}

#[tokio::test]
async fn oversize_body_refused() {
    let url = start(Config { max_body: 1024, ..Config::default() }).await;
    let (tx, mut rx, _) = relay_client::connect(&url, signer()).await.unwrap();
    tx.send(&[9; 32], &vec![0u8; 1025], 60, "big").unwrap();
    assert_eq!(next_msg(&mut rx).await, Incoming::Error { r#ref: Some("big".into()), code: "too_large".into() });
}

#[tokio::test]
async fn queue_cap_enforced() {
    let url = start(Config { max_queue: 3, ..Config::default() }).await;
    let (tx, mut rx, _) = relay_client::connect(&url, signer()).await.unwrap();
    for i in 0..4 {
        tx.send(&[7; 32], b"m", 60, &format!("q{i}")).unwrap();
    }
    assert_eq!(next_msg(&mut rx).await, Incoming::Error { r#ref: Some("q3".into()), code: "queue_full".into() });
}

#[tokio::test]
async fn send_rate_limited() {
    let url = start(Config { send_per_min: 2, ..Config::default() }).await;
    let (tx, mut rx, _) = relay_client::connect(&url, signer()).await.unwrap();
    for i in 0..3 {
        tx.send(&[8; 32], b"m", 60, &format!("s{i}")).unwrap();
    }
    assert_eq!(next_msg(&mut rx).await, Incoming::Error { r#ref: Some("s2".into()), code: "rate_limited".into() });
}

#[tokio::test]
async fn connection_limit_per_ip() {
    let url = start(Config { conn_per_ip: 2, ..Config::default() }).await;
    let _a = relay_client::connect(&url, signer()).await.unwrap();
    let _b = relay_client::connect(&url, signer()).await.unwrap();
    assert!(relay_client::connect(&url, signer()).await.is_err());
}

#[tokio::test]
async fn expired_queued_messages_are_dropped() {
    let url = start(Config::default()).await;
    let b = signer();
    let b_id = crypto::id_of(&b.public());
    let (atx, _arx, _) = relay_client::connect(&url, signer()).await.unwrap();
    atx.send(&b_id, b"short", 1, "t").unwrap();
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let (_btx, mut brx, _) = relay_client::connect(&url, b).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(500), brx.recv()).await.is_err());
}

#[tokio::test]
async fn global_mailbox_cap_enforced() {
    let url = start(Config { max_mailboxes: 2, ..Config::default() }).await;
    let (tx, mut rx, _) = relay_client::connect(&url, signer()).await.unwrap();
    tx.send(&[1; 32], b"m", 60, "a").unwrap();
    tx.send(&[2; 32], b"m", 60, "b").unwrap();
    tx.send(&[3; 32], b"m", 60, "c").unwrap();
    assert_eq!(next_msg(&mut rx).await, Incoming::Error { r#ref: Some("c".into()), code: "queue_full".into() });
    // Existing mailboxes still accept messages.
    tx.send(&[1; 32], b"m2", 60, "d").unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(300), next_msg(&mut rx)).await.is_err());
}

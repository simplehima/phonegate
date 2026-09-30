//! PhoneGate relay server (contracts/relay-api.md).
//!
//! The relay is deliberately powerless: devices authenticate by proving possession of a key, the
//! relay routes opaque end-to-end encrypted bodies between mailbox ids, and nothing is persisted.
//! A fully compromised relay can drop or delay messages but cannot approve anything.

pub mod hub;
pub mod limits;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use pg_core::crypto::{self, b64, Id};
use pg_core::encoding::Enc;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

pub use limits::Config;

#[derive(Clone)]
pub struct AppState {
    hub: Arc<Mutex<hub::Hub>>,
    cfg: Arc<Config>,
}

pub fn router(cfg: Config) -> Router {
    let state = AppState { hub: Arc::new(Mutex::new(hub::Hub::default())), cfg: Arc::new(cfg) };
    let sweeper = state.hub.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(10));
        loop {
            t.tick().await;
            sweeper.lock().expect("hub lock").sweep();
        }
    });
    Router::new()
        .route("/", get(landing))
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/ws", get(ws_handler))
        .with_state(state)
}

/// Static "nothing to see here" page for people who open the relay address in a browser. It has
/// no scripts and loads nothing, and the headers forbid both.
const LANDING_HTML: &str = include_str!("landing.html");
const LANDING_CSP: &str =
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

async fn landing() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, LANDING_CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        LANDING_HTML,
    )
}

pub async fn serve(listener: TcpListener, cfg: Config) -> std::io::Result<()> {
    axum::serve(listener, router(cfg).into_make_service_with_connect_info::<SocketAddr>()).await
}

fn client_ip(peer: SocketAddr, headers: &HeaderMap, trust_proxy: bool) -> IpAddr {
    if trust_proxy {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let ip = client_ip(peer, &headers, state.cfg.trust_proxy);
    let max = state.cfg.max_body * 4 / 3 + 1024;
    ws.max_message_size(max).max_frame_size(max).on_upgrade(move |socket| async move {
        handle(socket, ip, state).await;
    })
}

fn err(code: &str, r: Option<&str>) -> String {
    match r {
        Some(r) => json!({"t":"error","ref":r,"code":code}).to_string(),
        None => json!({"t":"error","code":code}).to_string(),
    }
}

/// Validates the auth frame; returns the device id on success.
fn check_auth(v: &Value, challenge: &[u8; 32]) -> Option<Id> {
    if v["t"] != "auth" {
        return None;
    }
    let pubk = b64::decode(v["pub"].as_str()?).ok()?;
    let sig = b64::decode(v["sig"].as_str()?).ok()?;
    let msg = Enc::new("phonegate/v1/relay-auth").bytes(challenge).finish();
    crypto::verify(&pubk, &msg, &sig).ok()?;
    Some(crypto::id_of(&pubk))
}

async fn handle(socket: WebSocket, ip: IpAddr, state: AppState) {
    let cfg = state.cfg.clone();
    let Some(conn) = state.hub.lock().expect("hub lock").new_conn(ip, &cfg) else {
        let (mut sink, _) = socket.split();
        let _ = sink.send(Message::Text(err("rate_limited", None))).await;
        let _ = sink.close().await;
        return;
    };
    let (mut sink, mut stream) = socket.split();
    let mut id: Option<Id> = None;

    let result: Result<(), ()> = async {
        let challenge: [u8; 32] = crypto::random().map_err(|_| ())?;
        sink.send(Message::Text(json!({"t":"hello","challenge":b64::encode(&challenge)}).to_string()))
            .await
            .map_err(|_| ())?;

        // ---- authentication ----
        let auth = tokio::time::timeout(Duration::from_secs(cfg.auth_timeout_s), async {
            while let Some(Ok(m)) = stream.next().await {
                if let Message::Text(t) = m {
                    return Some(t);
                }
            }
            None
        })
        .await;
        let text = match auth {
            Ok(Some(t)) => t,
            Ok(None) => return Err(()),
            Err(_) => {
                let _ = sink.send(Message::Text(err("auth_timeout", None))).await;
                return Err(());
            }
        };
        if !state.hub.lock().expect("hub lock").allow_auth(ip, &cfg) {
            let _ = sink.send(Message::Text(err("rate_limited", None))).await;
            return Err(());
        }
        let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let Some(dev) = check_auth(&parsed, &challenge) else {
            let _ = sink.send(Message::Text(err("auth_failed", None))).await;
            return Err(());
        };
        id = Some(dev);

        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let queued = state.hub.lock().expect("hub lock").register(dev, conn, tx.clone());
        sink.send(Message::Text(json!({"t":"ready","id":b64::encode(&dev)}).to_string())).await.map_err(|_| ())?;
        for f in queued {
            sink.send(Message::Text(f)).await.map_err(|_| ())?;
        }
        tracing::debug!(id = %hub::short(&dev), "device connected");

        // ---- main loop ----
        let mut bucket = limits::TokenBucket::per_minute(cfg.send_per_min);
        let mut ping = tokio::time::interval(Duration::from_secs(cfg.ping_interval_s));
        ping.tick().await;
        let mut last_seen = tokio::time::Instant::now();
        loop {
            tokio::select! {
                out = rx.recv() => {
                    let Some(f) = out else { return Ok(()) };
                    sink.send(Message::Text(f)).await.map_err(|_| ())?;
                }
                _ = ping.tick() => {
                    if last_seen.elapsed() > Duration::from_secs(cfg.idle_timeout_s) {
                        return Ok(());
                    }
                    sink.send(Message::Ping(Vec::new())).await.map_err(|_| ())?;
                }
                incoming = stream.next() => {
                    let Some(Ok(m)) = incoming else { return Ok(()) };
                    last_seen = tokio::time::Instant::now();
                    let text = match m {
                        Message::Text(t) => t,
                        Message::Close(_) => return Ok(()),
                        _ => continue,
                    };
                    let reply = handle_frame(&text, dev, conn, &tx, &mut bucket, &state);
                    if let Some(r) = reply {
                        sink.send(Message::Text(r)).await.map_err(|_| ())?;
                    }
                }
            }
        }
    }
    .await;
    let _ = result;
    state.hub.lock().expect("hub lock").unregister(id, conn, ip);
    let _ = sink.close().await;
}

fn handle_frame(
    text: &str,
    dev: Id,
    conn: hub::ConnId,
    tx: &mpsc::UnboundedSender<String>,
    bucket: &mut limits::TokenBucket,
    state: &AppState,
) -> Option<String> {
    let cfg = &state.cfg;
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return Some(err("bad_frame", None));
    };
    let r = v["ref"].as_str().filter(|s| s.len() <= 32);
    match v["t"].as_str() {
        Some("send") => {
            if !bucket.try_take() {
                return Some(err("rate_limited", r));
            }
            let Some(to) = v["to"].as_str().and_then(|s| b64::decode_fixed::<32>(s).ok()) else {
                return Some(err("bad_frame", r));
            };
            let Some(body) = v["body"].as_str() else {
                return Some(err("bad_frame", r));
            };
            // Decode only to enforce the size limit; the body stays opaque.
            match b64::decode(body) {
                Ok(b) if b.len() <= cfg.max_body => {}
                Ok(_) => return Some(err("too_large", r)),
                Err(_) => return Some(err("bad_frame", r)),
            }
            let ttl = Duration::from_secs(v["ttl"].as_u64().unwrap_or(60).clamp(1, cfg.max_ttl_s));
            let is_slot = v["slot"].as_bool().unwrap_or(false);
            let mut hub = state.hub.lock().expect("hub lock");
            let res = if is_slot {
                hub.send_slot(dev, conn, to, body.to_string(), ttl)
            } else {
                hub.send(dev, to, body.to_string(), ttl, cfg)
            };
            match res {
                Ok(()) => Some(json!({"t":"ack","ref":r.unwrap_or("")}).to_string()),
                Err(hub::SendError::QueueFull) => Some(err("queue_full", r)),
            }
        }
        Some("sub") => {
            let Some(slot) = v["slot"].as_str().and_then(|s| b64::decode_fixed::<32>(s).ok()) else {
                return Some(err("bad_frame", r));
            };
            let mut hub = state.hub.lock().expect("hub lock");
            if hub.slot_count(conn) >= 2 {
                return Some(err("too_many_slots", r));
            }
            for f in hub.subscribe(slot, conn, tx.clone()) {
                let _ = tx.send(f);
            }
            Some(json!({"t":"ack","ref":r.unwrap_or("")}).to_string())
        }
        _ => Some(err("bad_frame", r)),
    }
}

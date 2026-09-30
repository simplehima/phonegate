//! Async relay client (contracts/relay-api.md). The relay is untrusted: this client only moves
//! opaque bodies; all verification happens in the protocol layer.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::crypto::{b64, Id};
use crate::encoding::Enc;
use crate::error::{Error, Result};
use crate::signer::Signer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    Msg { from: Id, to: Id, body: Vec<u8> },
    Ack { r#ref: String },
    Error { r#ref: Option<String>, code: String },
    Closed,
}

#[derive(Clone)]
pub struct RelaySender {
    tx: mpsc::UnboundedSender<Message>,
}

impl RelaySender {
    pub fn send(&self, to: &Id, body: &[u8], ttl_s: u32, r#ref: &str) -> Result<()> {
        let f = json!({"t":"send","ref":r#ref,"to":b64::encode(to),"body":b64::encode(body),"ttl":ttl_s});
        self.tx.send(Message::Text(f.to_string())).map_err(|_| Error::Io("relay connection closed".into()))
    }

    /// Sends to a pairing slot (retained by the relay until the TTL for late subscribers).
    pub fn send_slot(&self, slot: &Id, body: &[u8], ttl_s: u32, r#ref: &str) -> Result<()> {
        let f = json!({"t":"send","ref":r#ref,"to":b64::encode(slot),"body":b64::encode(body),"ttl":ttl_s,"slot":true});
        self.tx.send(Message::Text(f.to_string())).map_err(|_| Error::Io("relay connection closed".into()))
    }

    pub fn subscribe(&self, slot: &Id) -> Result<()> {
        let f = json!({"t":"sub","slot":b64::encode(slot)});
        self.tx.send(Message::Text(f.to_string())).map_err(|_| Error::Io("relay connection closed".into()))
    }

    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// `https://host[/prefix]` → `wss://host[/prefix]/v1/ws`.
pub fn ws_url(relay_url: &str) -> Result<String> {
    let base = relay_url.trim_end_matches('/');
    if let Some(rest) = base.strip_prefix("https://") {
        Ok(format!("wss://{rest}/v1/ws"))
    } else if let Some(rest) = base.strip_prefix("http://") {
        Ok(format!("ws://{rest}/v1/ws"))
    } else {
        Err(Error::Decode("relay url must start with https:// or http://"))
    }
}

pub fn auth_bytes(challenge: &[u8]) -> Vec<u8> {
    Enc::new("phonegate/v1/relay-auth").bytes(challenge).finish()
}

fn text(m: Message) -> Option<String> {
    match m {
        Message::Text(t) => Some(t),
        _ => None,
    }
}

/// Connects, authenticates with `signer`, and returns a sender plus the stream of incoming
/// frames. The returned id is the relay-assigned mailbox id (= `ID(signer.public())`).
pub async fn connect(relay_url: &str, signer: Arc<dyn Signer>) -> Result<(RelaySender, mpsc::UnboundedReceiver<Incoming>, Id)> {
    let url = ws_url(relay_url)?;
    let (ws, _) = tokio::time::timeout(Duration::from_secs(15), tokio_tungstenite::connect_async(url.as_str()))
        .await
        .map_err(|_| Error::Io("relay connect timeout".into()))?
        .map_err(|e| Error::Io(format!("relay connect failed: {e}")))?;
    let (mut sink, mut stream) = ws.split();

    let hello = loop {
        let m = tokio::time::timeout(Duration::from_secs(10), stream.next())
            .await
            .map_err(|_| Error::Io("relay hello timeout".into()))?
            .ok_or(Error::Io("relay closed".into()))?
            .map_err(|e| Error::Io(e.to_string()))?;
        if let Some(t) = text(m) {
            break t;
        }
    };
    let hello: Value = serde_json::from_str(&hello).map_err(|_| Error::Decode("bad hello"))?;
    if hello["t"] != "hello" {
        return Err(Error::Decode("expected hello"));
    }
    let challenge = b64::decode_fixed::<32>(hello["challenge"].as_str().unwrap_or(""))?;
    let pubk = signer.public();
    let sig = signer.sign(&auth_bytes(&challenge))?;
    let auth = json!({"t":"auth","pub":b64::encode(&pubk),"sig":b64::encode(&sig)});
    sink.send(Message::Text(auth.to_string())).await.map_err(|e| Error::Io(e.to_string()))?;

    let ready = loop {
        let m = tokio::time::timeout(Duration::from_secs(10), stream.next())
            .await
            .map_err(|_| Error::Io("relay auth timeout".into()))?
            .ok_or(Error::Io("relay closed during auth".into()))?
            .map_err(|e| Error::Io(e.to_string()))?;
        if let Some(t) = text(m) {
            break t;
        }
    };
    let ready: Value = serde_json::from_str(&ready).map_err(|_| Error::Decode("bad ready"))?;
    if ready["t"] != "ready" {
        return Err(Error::Verify("relay rejected authentication"));
    }
    let id = b64::decode_fixed::<32>(ready["id"].as_str().unwrap_or(""))?;
    if id != crate::crypto::id_of(&pubk) {
        return Err(Error::Verify("relay assigned an unexpected id"));
    }

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();
    let (in_tx, in_rx) = mpsc::unbounded_channel::<Incoming>();

    tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if sink.send(m).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    tokio::spawn(async move {
        while let Some(Ok(m)) = stream.next().await {
            let Some(t) = text(m) else { continue };
            let Ok(v) = serde_json::from_str::<Value>(&t) else { continue };
            let item = match v["t"].as_str() {
                Some("msg") => {
                    let from = b64::decode_fixed::<32>(v["from"].as_str().unwrap_or(""));
                    let to = b64::decode_fixed::<32>(v["to"].as_str().unwrap_or(""));
                    let body = b64::decode(v["body"].as_str().unwrap_or(""));
                    match (from, to, body) {
                        (Ok(from), Ok(to), Ok(body)) => Incoming::Msg { from, to, body },
                        _ => continue,
                    }
                }
                Some("ack") => Incoming::Ack { r#ref: v["ref"].as_str().unwrap_or("").to_string() },
                Some("error") => Incoming::Error {
                    r#ref: v["ref"].as_str().map(str::to_string),
                    code: v["code"].as_str().unwrap_or("").to_string(),
                },
                _ => continue,
            };
            if in_tx.send(item).is_err() {
                return;
            }
        }
        let _ = in_tx.send(Incoming::Closed);
    });

    Ok((RelaySender { tx: out_tx }, in_rx, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_mapping() {
        assert_eq!(ws_url("https://r.example").unwrap(), "wss://r.example/v1/ws");
        assert_eq!(ws_url("https://r.example/pg/").unwrap(), "wss://r.example/pg/v1/ws");
        assert_eq!(ws_url("http://127.0.0.1:8080").unwrap(), "ws://127.0.0.1:8080/v1/ws");
        assert!(ws_url("ftp://x").is_err());
    }
}

//! In-memory routing state. Nothing is persisted; bodies are opaque and never logged.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pg_core::crypto::Id;
use tokio::sync::mpsc::UnboundedSender;

use crate::limits::{Config, TokenBucket};

pub type ConnId = u64;

#[derive(Debug, Clone)]
struct Queued {
    from: Id,
    to: Id,
    body_b64: String,
    expires: Instant,
}

#[derive(Default)]
pub struct Hub {
    next_conn: ConnId,
    mailboxes: HashMap<Id, Vec<(ConnId, UnboundedSender<String>)>>,
    slots: HashMap<Id, Vec<(ConnId, UnboundedSender<String>, Instant)>>,
    queues: HashMap<Id, VecDeque<Queued>>,
    slot_queues: HashMap<Id, VecDeque<Queued>>,
    ip_conns: HashMap<IpAddr, usize>,
    auth_buckets: HashMap<IpAddr, TokenBucket>,
}

pub const SLOT_TTL: Duration = Duration::from_secs(300);
pub const MAX_SLOT_QUEUE: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    QueueFull,
}

pub fn short(id: &Id) -> String {
    id[..4].iter().map(|b| format!("{b:02x}")).collect()
}

fn frame(q: &Queued) -> String {
    serde_json::json!({
        "t": "msg",
        "from": pg_core::crypto::b64::encode(&q.from),
        "to": pg_core::crypto::b64::encode(&q.to),
        "body": q.body_b64,
    })
    .to_string()
}

impl Hub {
    pub fn new_conn(&mut self, ip: IpAddr, cfg: &Config) -> Option<ConnId> {
        let n = self.ip_conns.entry(ip).or_insert(0);
        if *n >= cfg.conn_per_ip {
            return None;
        }
        *n += 1;
        self.next_conn += 1;
        Some(self.next_conn)
    }

    pub fn allow_auth(&mut self, ip: IpAddr, cfg: &Config) -> bool {
        self.auth_buckets.entry(ip).or_insert_with(|| TokenBucket::per_minute(cfg.auth_per_min)).try_take()
    }

    /// Registers an authenticated connection and returns queued messages to deliver.
    pub fn register(&mut self, id: Id, conn: ConnId, tx: UnboundedSender<String>) -> Vec<String> {
        self.mailboxes.entry(id).or_default().push((conn, tx));
        let now = Instant::now();
        self.queues
            .remove(&id)
            .map(|q| q.into_iter().filter(|m| m.expires > now).map(|m| frame(&m)).collect())
            .unwrap_or_default()
    }

    /// Subscribes to a pairing slot; returns retained (non-expired) slot messages.
    pub fn subscribe(&mut self, slot: Id, conn: ConnId, tx: UnboundedSender<String>) -> Vec<String> {
        let now = Instant::now();
        self.slots.entry(slot).or_default().push((conn, tx, now + SLOT_TTL));
        self.slot_queues
            .get(&slot)
            .map(|q| q.iter().filter(|m| m.expires > now).map(frame).collect())
            .unwrap_or_default()
    }

    pub fn unregister(&mut self, id: Option<Id>, conn: ConnId, ip: IpAddr) {
        if let Some(id) = id {
            if let Some(v) = self.mailboxes.get_mut(&id) {
                v.retain(|(c, _)| *c != conn);
                if v.is_empty() {
                    self.mailboxes.remove(&id);
                }
            }
        }
        for v in self.slots.values_mut() {
            v.retain(|(c, _, _)| *c != conn);
        }
        self.slots.retain(|_, v| !v.is_empty());
        if let Some(n) = self.ip_conns.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.ip_conns.remove(&ip);
            }
        }
    }

    /// Mailbox delivery: live to every connection of `to`, otherwise queued (drained on connect).
    pub fn send(&mut self, from: Id, to: Id, body_b64: String, ttl: Duration, cfg: &Config) -> Result<(), SendError> {
        let q = Queued { from, to, body_b64, expires: Instant::now() + ttl };
        let f = frame(&q);
        let mut delivered = false;
        if let Some(v) = self.mailboxes.get_mut(&to) {
            v.retain(|(_, tx)| tx.send(f.clone()).is_ok());
            delivered = !v.is_empty();
        }
        if delivered {
            return Ok(());
        }
        let now = Instant::now();
        if !self.queues.contains_key(&to) && self.queues.len() >= cfg.max_mailboxes {
            // Bound memory: sweep expired queues once, then refuse new offline mailboxes.
            self.queues.retain(|_, q| {
                q.retain(|m| m.expires > now);
                !q.is_empty()
            });
            if self.queues.len() >= cfg.max_mailboxes {
                return Err(SendError::QueueFull);
            }
        }
        let queue = self.queues.entry(to).or_default();
        queue.retain(|m| m.expires > now);
        if queue.len() >= cfg.max_queue {
            return Err(SendError::QueueFull);
        }
        queue.push_back(q);
        Ok(())
    }

    /// Slot delivery: live to subscribers except the sender connection, and retained until TTL
    /// so a late subscriber (the phone scanning the QR) still receives the offer.
    pub fn send_slot(&mut self, from: Id, sender: ConnId, slot: Id, body_b64: String, ttl: Duration) -> Result<(), SendError> {
        let q = Queued { from, to: slot, body_b64, expires: Instant::now() + ttl.min(SLOT_TTL) };
        let f = frame(&q);
        if let Some(v) = self.slots.get_mut(&slot) {
            v.retain(|(c, tx, _)| *c == sender || tx.send(f.clone()).is_ok());
        }
        let queue = self.slot_queues.entry(slot).or_default();
        let now = Instant::now();
        queue.retain(|m| m.expires > now);
        if queue.len() >= MAX_SLOT_QUEUE {
            return Err(SendError::QueueFull);
        }
        queue.push_back(q);
        Ok(())
    }

    pub fn slot_count(&self, conn: ConnId) -> usize {
        self.slots.values().flatten().filter(|(c, _, _)| *c == conn).count()
    }

    /// Periodic cleanup of expired queues, slots and idle rate-limit buckets.
    pub fn sweep(&mut self) {
        let now = Instant::now();
        for q in self.queues.values_mut() {
            q.retain(|m| m.expires > now);
        }
        self.queues.retain(|_, q| !q.is_empty());
        for q in self.slot_queues.values_mut() {
            q.retain(|m| m.expires > now);
        }
        self.slot_queues.retain(|_, q| !q.is_empty());
        for v in self.slots.values_mut() {
            v.retain(|(_, tx, exp)| *exp > now && !tx.is_closed());
        }
        self.slots.retain(|_, v| !v.is_empty());
        if self.auth_buckets.len() > 10_000 {
            self.auth_buckets.clear();
        }
    }

    pub fn stats(&self) -> (usize, usize) {
        (self.mailboxes.values().map(Vec::len).sum(), self.queues.values().map(VecDeque::len).sum())
    }
}

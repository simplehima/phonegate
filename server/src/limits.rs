//! Rate limiting primitives and relay configuration.

use std::time::Instant;

/// Classic token bucket: `capacity` tokens, refilled continuously at `per_minute / 60` per second.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn per_minute(n: u32) -> Self {
        let cap = n.max(1) as f64;
        TokenBucket { capacity: cap, tokens: cap, refill_per_sec: cap / 60.0, last: Instant::now() }
    }

    pub fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub max_body: usize,
    pub max_queue: usize,
    /// Global cap on distinct offline mailboxes holding queued messages (memory bound).
    pub max_mailboxes: usize,
    pub max_ttl_s: u64,
    pub send_per_min: u32,
    pub conn_per_ip: usize,
    pub auth_per_min: u32,
    pub trust_proxy: bool,
    pub auth_timeout_s: u64,
    pub ping_interval_s: u64,
    pub idle_timeout_s: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_body: 64 * 1024,
            max_queue: 64,
            max_mailboxes: 10_000,
            max_ttl_s: 300,
            send_per_min: 60,
            conn_per_ip: 20,
            auth_per_min: 30,
            trust_proxy: false,
            auth_timeout_s: 10,
            ping_interval_s: 30,
            idle_timeout_s: 75,
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        fn get<T: std::str::FromStr>(k: &str, d: T) -> T {
            std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
        }
        let d = Config::default();
        Config {
            max_body: get("PG_MAX_BODY", d.max_body),
            max_queue: get("PG_MAX_QUEUE", d.max_queue),
            max_mailboxes: get("PG_MAX_MAILBOXES", d.max_mailboxes),
            max_ttl_s: get("PG_MAX_TTL", d.max_ttl_s),
            send_per_min: get("PG_SEND_RATE", d.send_per_min),
            conn_per_ip: get("PG_CONN_PER_IP", d.conn_per_ip),
            auth_per_min: get("PG_AUTH_RATE", d.auth_per_min),
            trust_proxy: get("PG_TRUST_PROXY", d.trust_proxy),
            ..d
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_limits() {
        let mut b = TokenBucket::per_minute(3);
        assert!(b.try_take());
        assert!(b.try_take());
        assert!(b.try_take());
        assert!(!b.try_take());
    }
}

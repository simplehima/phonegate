# Contract: Relay Server API v1

The relay is untrusted: it only routes opaque bodies (see [protocol.md](./protocol.md) §5). It
keeps **no persistent state**.

## HTTP

| Method | Path | Response |
|--------|------|----------|
| GET | `/healthz` | `200 ok` |
| GET | `/v1/ws` | WebSocket upgrade |

## WebSocket frames (text, JSON, UTF-8, ≤ 96 KiB)

All binary values are b64 (base64url, no padding).

| Dir | Frame | Notes |
|-----|-------|-------|
| S→C | `{"t":"hello","challenge":b64(32)}` | sent immediately on connect |
| C→S | `{"t":"auth","pub":b64(65),"sig":b64(64)}` | sig per protocol §8; must arrive within 10 s |
| S→C | `{"t":"ready","id":b64(32)}` | then any queued messages for `id` are delivered |
| C→S | `{"t":"send","ref":str≤32,"to":b64(32),"body":b64(≤64KiB),"ttl":int,"slot"?:bool}` | `ttl` seconds, clamped to [1, 300]. `slot:true` addresses a pairing slot: delivered live to other subscribers and retained (≤16 msgs) until TTL for late subscribers |
| S→C | `{"t":"ack","ref":str}` | accepted: delivered live or queued |
| C→S | `{"t":"sub","slot":b64(32)}` | receive messages sent to a pairing slot; ≤ 2 slots per connection, subscription lasts ≤ 300 s |
| S→C | `{"t":"msg","from":b64(32),"to":b64(32),"body":b64}` | `from` = sender's authenticated id |
| S→C | `{"t":"error","ref":str?,"code":str}` | codes below |

WebSocket ping/pong keep-alive: the server pings every 30 s and closes after 75 s of silence.

### Error codes

`bad_frame`, `auth_required`, `auth_failed`, `auth_timeout`, `too_large`, `rate_limited`,
`queue_full`, `too_many_slots`.

## Limits (defaults, configurable via env)

| Limit | Default | Env |
|-------|---------|-----|
| Body size | 64 KiB | `PG_MAX_BODY` |
| Queue per mailbox | 64 | `PG_MAX_QUEUE` |
| Distinct offline mailboxes (global) | 10 000 | `PG_MAX_MAILBOXES` |
| Message TTL cap | 300 s | `PG_MAX_TTL` |
| Sends per connection | 60 / min | `PG_SEND_RATE` |
| Connections per IP | 20 | `PG_CONN_PER_IP` |
| Auth attempts per IP | 30 / min | `PG_AUTH_RATE` |

## Behavior guarantees

- A message goes to every live connection authenticated as `to`, or subscribed to slot `to`. If
  none is live, it is queued until its TTL expires.
- Several connections for the same id are allowed (for example, a phone reconnecting). Queued
  messages go to the first one.
- Logs contain ids truncated to 8 hex chars, sizes, and error codes. They never contain bodies.
- Config: `PG_BIND` (default `0.0.0.0:8080`) and `PG_TRUST_PROXY` (use `X-Forwarded-For` for IP
  limits, default `false`).

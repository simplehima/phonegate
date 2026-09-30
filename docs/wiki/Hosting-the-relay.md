# Hosting the relay

The relay is a tiny message router that your PC and phone both connect to. It is
**untrusted by design**: it only ever sees end-to-end encrypted, signed messages. It can't
approve anything, read requests, or replay old approvals. The worst a hostile relay can do is
drop messages, and offline approval and recovery codes still work when that happens.

**Requirements:** any Linux VPS with a public IPv4 address and a domain or subdomain pointing at it.
It needs about 20 MB of RAM (512 MB servers are fine) and ports 80/443 reachable for the HTTPS
certificate. Shared web hosting (PHP-only plans) can't run it.

## Option A: Dokploy (recommended if you use Dokploy)

1. In Dokploy: **Projects → Create Project**, then **Create Service → Application**.
2. **Provider:** GitHub → `simplehima/phonegate`, branch `main` (or *Git* with
   `https://github.com/simplehima/phonegate.git`).
3. **Build Type:** Dockerfile.
   - Docker File: `deploy/dokploy/Dockerfile`
   - Docker Context Path: `deploy/dokploy`

   This Dockerfile downloads the release's relay binary and **checks its SHA-256** before
   using it, so your server never compiles Rust.
4. **Domains → Add Domain:**
   - Host: `relay.example.com`
   - Container port: `8080`
   - HTTPS: on, Certificate: Let's Encrypt

   To share a host with another app, you can instead set **Path** `/relay` and turn on
   **Strip Path**. Your relay address is then `https://example.com/relay`.
5. **Deploy**, then open `https://relay.example.com/healthz`. It should say `ok`.
6. In the PhoneGate app on your PC, enter `https://relay.example.com` as the relay address.

The *Compose* service type also works: set the compose path to `./deploy/dokploy/docker-compose.yml`,
service `relay`, port `8080`.

**Upgrading:** after a new release, change `RELAY_VERSION` and `RELAY_SHA256` in
`deploy/dokploy/Dockerfile` (the values are in the release's `SHA256SUMS.txt`), then redeploy.

## Option B: plain Docker + Caddy (automatic HTTPS)

```bash
git clone https://github.com/simplehima/phonegate && cd phonegate/deploy
cp .env.example .env        # set PG_DOMAIN=relay.example.com
docker compose up -d        # Caddy obtains the Let's Encrypt certificate
curl https://relay.example.com/healthz   # -> ok
```

This option builds the relay from source, which needs roughly 1–2 GB of RAM while compiling.

## Option C: just the binary

Download `phonegate-relay-linux-x86_64` from the
[latest release](https://github.com/simplehima/phonegate/releases/latest) and check it against
`SHA256SUMS.txt`. Then run it behind any HTTPS reverse proxy with WebSocket support:

```bash
PG_BIND=127.0.0.1:8080 PG_TRUST_PROXY=true ./phonegate-relay-linux-x86_64
```

## NAT VPS (shared IPv4, only a few forwarded ports)

Let's Encrypt needs ports 80/443. On a NAT VPS, run a Cloudflare Tunnel (`cloudflared`) to the
relay's port instead, and use the tunnel's hostname as your relay address.

## Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `PG_BIND` | `0.0.0.0:8080` | listen address |
| `PG_TRUST_PROXY` | `false` (`true` in the Dokploy image) | use `X-Forwarded-For` for rate limits |
| `PG_MAX_BODY` | 65536 | max message size (bytes) |
| `PG_MAX_QUEUE` | 64 | queued messages per offline device |
| `PG_MAX_MAILBOXES` | 10000 | offline devices with queued messages |
| `PG_SEND_RATE` | 60 | messages per minute per connection |
| `PG_CONN_PER_IP` | 20 | connections per client address |

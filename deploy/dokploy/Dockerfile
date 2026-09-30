# PhoneGate relay for Dokploy (and any Docker host): a tiny image built from the published,
# checksum-pinned release binary, so the server never has to compile Rust.
#
# Dokploy: Create Application → Provider: GitHub (simplehima/phonegate) → Build Type: Dockerfile
#          Docker File: deploy/dokploy/Dockerfile · Docker Context Path: deploy/dokploy
#          Domains: your host, container port 8080, HTTPS on (see the "Hosting the relay" wiki page).
#
# To upgrade, change RELAY_VERSION and RELAY_SHA256 together (values from the release's SHA256SUMS.txt).
ARG RELAY_VERSION=relay-v0.1.1
ARG RELAY_SHA256=65a2245469394d406a57410b54131706e1f8b6145ec5f648bbee6aa7ca13e734

FROM debian:bookworm-slim AS fetch
ARG RELAY_VERSION
ARG RELAY_SHA256
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /phonegate-relay \
      "https://github.com/simplehima/phonegate/releases/download/${RELAY_VERSION}/phonegate-relay-linux-x86_64" \
 && echo "${RELAY_SHA256}  /phonegate-relay" | sha256sum -c - \
 && chmod 0755 /phonegate-relay

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=fetch /phonegate-relay /usr/local/bin/phonegate-relay
# Behind Dokploy's Traefik: trust X-Forwarded-For for per-client rate limits.
ENV PG_BIND=0.0.0.0:8080 PG_TRUST_PROXY=true
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/phonegate-relay"]

# PhoneGate relay: stateless, untrusted message router. Build from the repository root:
#   docker build -f deploy/Dockerfile -t phonegate-relay .
FROM rust:1-slim-bookworm AS build
# Optional: trust extra root CAs during the build (networks with TLS inspection). Empty by default.
COPY deploy/extra-ca/ /usr/local/share/ca-certificates/extra/
RUN update-ca-certificates >/dev/null 2>&1 || true
ENV CARGO_HTTP_CAINFO=/etc/ssl/certs/ca-certificates.crt
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY server ./server
COPY windows/agent ./windows/agent
COPY windows/credprov ./windows/credprov
COPY tests ./tests
RUN cargo build --release --locked -p phonegate-relay \
 && strip target/release/phonegate-relay

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/phonegate-relay /usr/local/bin/phonegate-relay
ENV PG_BIND=0.0.0.0:8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/phonegate-relay"]

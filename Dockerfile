FROM rust:1.88-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./

# Create dummy sources to cache dependency compilation
RUN mkdir src && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs
RUN cargo build --release
RUN rm -rf src

# Build actual source
COPY src/ src/
RUN touch src/main.rs src/lib.rs && cargo build --release

# Optional init-container image which installs the recommended iptables rules.
# Build with:
#   docker build --target iptables-init -t botbox-iptables-init:test .
FROM alpine:3.19 AS iptables-init
RUN apk add --no-cache iptables
COPY scripts/iptables-init.sh /iptables-init.sh
ENTRYPOINT ["/bin/sh", "/iptables-init.sh"]

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /app/target/release/botbox /botbox
COPY config.yaml /etc/botbox/config.yaml

EXPOSE 8080 8443 9090

# Kubernetes health probes:
#   readinessProbe:
#     httpGet: { path: /healthz, port: 9090 }
#   # Note: /healthz is readiness-gated on required secrets; avoid using it for liveness.
#   livenessProbe:
#     tcpSocket: { port: 9090 }

ENTRYPOINT ["/botbox"]
CMD ["--config", "/etc/botbox/config.yaml"]

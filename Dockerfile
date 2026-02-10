FROM rust:1.85-bookworm AS builder

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

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /app/target/release/botbox /botbox
COPY config.yaml /etc/botbox/config.yaml

EXPOSE 8080 9090

# Kubernetes health probes:
#   livenessProbe:
#     httpGet: { path: /healthz, port: 9090 }
#   readinessProbe:
#     httpGet: { path: /healthz, port: 9090 }

ENTRYPOINT ["/botbox"]
CMD ["--config", "/etc/botbox/config.yaml"]

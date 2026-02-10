# Architecture

## Request Flow

```
app container                    botbox sidecar                         upstream
     |                                  |                                  |
     |  GET /v1/models                  |                                  |
     |  Host: api.openai.com            |                                  |
     |--- (iptables REDIRECT :80→:8080) |                                  |
     |                                  |                                  |
     |  allowlist check ───────────── allow                                |
     |  header rewrite ──────────── Authorization: Bearer sk-...           |
     |  TLS origination ────────── HTTPS                                   |
     |                                  |                                  |
     |                                  |  GET /v1/models                  |
     |                                  |  Authorization: Bearer sk-...    |
     |                                  |──────────────────────────────────>|
     |                                  |                           200 OK |
     |                           200 OK |<─────────────────────────────────|
     |<─────────────────────────────────|                                  |
```

The proxy handler executes these steps for each request:

1. **Extract host** — from URI authority (explicit proxy) or Host header (transparent proxy)
2. **Allowlist check** — O(1) HashMap lookup + port check; deny → 403
3. **Strip hop-by-hop headers** — `Connection`, `Proxy-Authorization`, etc.
4. **Set Host header** — for the upstream TLS handshake (SNI)
5. **Header rewrite** — delete existing header first (prevents smuggling), then add with injected secret
6. **TLS origination** — rewrite `http://` → `https://`, connect via rustls
7. **Stream response** — forward upstream response body without buffering

## Module Structure

```
src/
├── allowlist.rs       # O(1) HashMap host lookup, IPv6-aware port stripping
├── config.rs          # YAML config parsing with serde validation
├── error.rs           # ProxyError: SecretNotFound, InvalidHeaderName, InvalidHeaderValue
├── header_rewrite.rs  # Delete-then-add pattern to prevent header smuggling
├── lib.rs             # Module re-exports
├── logging.rs         # tracing JSON subscriber setup
├── main.rs            # Server startup, signal handling, graceful shutdown
├── metrics.rs         # Prometheus counters/histograms on separate port
├── proxy.rs           # Core handler: allowlist → rewrite → TLS → forward
├── secrets.rs         # K8s directory secret store with inotify hot-reload (notify + ArcSwap)
└── tls.rs             # rustls HTTPS-only connector (ring backend, webpki roots)
```

## iptables Transparent Redirect

An init container runs before BotBox to install NAT + filter rules.

This repo provides an optional init image (Docker target `iptables-init`) which runs `scripts/iptables-init.sh` to apply the rules below:

```bash
docker build --target iptables-init -t botbox-iptables-init:test .
```

Example init container:

```yaml
- name: iptables-init
  image: botbox-iptables-init:test
  securityContext:
    runAsUser: 0
    runAsNonRoot: false
    capabilities:
      add: [NET_ADMIN]
  # If you change the BotBox UID/port, set these to match.
  # env:
  #   - name: BOTBOX_UID
  #     value: "1337"
  #   - name: BOTBOX_PROXY_PORT
  #     value: "8080"
```

The init script supports overrides via environment variables:
- `BOTBOX_UID` (default `1337`)
- `BOTBOX_PROXY_PORT` (default `8080`)
- `BOTBOX_REDIRECT_FROM_PORT` (default `80`)
- `BOTBOX_NAT_CHAIN` (default `EGRESS_REDIRECT`)
- `BOTBOX_FILTER_CHAIN` (default `EGRESS_FILTER`)
- `BOTBOX_IPTABLES_WAIT_SECONDS` (default `5`)

```
iptables -t nat -N EGRESS_REDIRECT
iptables -t nat -A EGRESS_REDIRECT -o lo -j RETURN
iptables -t nat -A EGRESS_REDIRECT -m owner --uid-owner 1337 -j RETURN
iptables -t nat -A EGRESS_REDIRECT -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -I OUTPUT 1 -p tcp -j EGRESS_REDIRECT

iptables -N EGRESS_FILTER
iptables -A EGRESS_FILTER -o lo -j RETURN
iptables -A EGRESS_FILTER -m owner --uid-owner 1337 -j RETURN
iptables -A EGRESS_FILTER -p udp --dport 53 -j RETURN
iptables -A EGRESS_FILTER -p tcp --dport 53 -j RETURN
iptables -A EGRESS_FILTER -p tcp -j DROP
iptables -A EGRESS_FILTER -p udp -j DROP
iptables -I OUTPUT 1 -j EGRESS_FILTER
```

| Rule | Purpose |
|---|---|
| NAT: `-o lo -j RETURN` | Skip loopback traffic (healthz probes, metrics scraping) |
| NAT: `--uid-owner 1337 -j RETURN` | Skip proxy's own outbound connections (prevents redirect loops) |
| NAT: `--dport 80 -j REDIRECT --to-port 8080` | Redirect HTTP to the proxy |
| NAT: `-I OUTPUT 1 -j EGRESS_REDIRECT` | Insert the NAT redirect chain at the top of OUTPUT (ensures priority over existing rules) |
| Filter: `-o lo -j RETURN` | Allow loopback traffic |
| Filter: `--uid-owner 1337 -j RETURN` | Allow proxy's upstream HTTPS connections |
| Filter: `-p udp --dport 53 -j RETURN` | Allow DNS resolution |
| Filter: `-p tcp --dport 53 -j RETURN` | Allow DNS over TCP |
| Filter: `-p tcp -j DROP` | Block all other direct outbound TCP from app containers |
| Filter: `-p udp -j DROP` | Block all other direct outbound UDP from app containers (prevents QUIC bypass) |
| Filter: `-I OUTPUT 1 -j EGRESS_FILTER` | Insert the filter chain at the top of OUTPUT (ensures priority over existing rules) |

BotBox runs as UID 1337 (Istio convention). This ensures its upstream HTTPS connections are not redirected back to itself.
Ensure application containers do NOT run as UID 1337, or they can bypass the owner-match rules.

### Transparent vs Explicit Proxy Mode

The proxy supports both modes via `extract_host()`:

- **Explicit** — client sends `GET http://host/path`; host is extracted from URI authority
- **Transparent** — client sends `GET /path` with `Host: host`; host is extracted from the Host header

After iptables redirect, applications send standard HTTP requests and BotBox transparently handles them.

## Pod Container Ordering

```yaml
initContainers:
  - name: iptables-init      # 1. Regular init: installs iptables rules, exits
  - name: botbox              # 2. Sidecar init (restartPolicy: Always): runs for pod lifetime
containers:
  - name: app                 # 3. Main container: your application
```

Kubernetes runs init containers sequentially, so iptables rules are in place before the proxy starts accepting connections.

## Configuration Reference

```yaml
listen_addr: "127.0.0.1"        # Proxy listen address (loopback only)
listen_port: 8080                # Proxy listen port
metrics_port: 9090               # Metrics/healthz port
secrets_dir: "/var/run/secrets/botbox"  # K8s Secret mount path
max_connections: 1024            # Connection limit (semaphore)
allow_non_loopback: false        # Must be true to bind non-loopback addresses

egress_policy:
  default_action: deny           # deny | allow
  rules:
    - host: api.openai.com       # Exact host match (port-aware, default: 443 only)
      action: allow
      header_rewrites:
        - name: Authorization    # Header to inject
          value: "Bearer {value}" # {value} is replaced with secret contents
          secret_ref: openai-api-key  # Filename in secrets_dir

    - host: api.anthropic.com
      action: allow
      header_rewrites:
        - name: x-api-key
          value: "{value}"
          secret_ref: anthropic-api-key
        - name: anthropic-version
          value: "2023-06-01"    # Static value (no secret_ref needed)

    - host: custom-api.example.com
      action: allow
      allowed_ports: [443, 8443]  # Allow non-standard port
```

### Header Rewrite Behavior

For each rewrite rule, the proxy:

1. **Deletes** any existing header with the same name (prevents clients from smuggling their own credentials)
2. **Adds** the header with the configured value

If `secret_ref` is specified, `{value}` is replaced with the file contents from the secrets directory. If the secret file is missing, the request fails with 500.

### Secret Hot-Reload

The secrets directory is watched via `inotify` (Linux) using the `notify` crate. When a file changes, the entire secret store is reloaded atomically via `ArcSwap`. This means:

- Key rotation takes effect without restarting the proxy
- Kubernetes Secret updates (via kubelet sync) are picked up automatically

## Endpoints

| Port | Path | Description |
|------|------|-------------|
| 8080 | — | Proxy listener (loopback only) |
| 9090 | `/healthz` | Returns 200 when ready, 503 otherwise |
| 9090 | `/metrics` | Prometheus exposition format |
| 9090 | other | Returns 404 |

## Metrics

All metrics are exposed in Prometheus text format on the metrics port.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `botbox_requests_total` | Counter | `host`, `decision` | Total requests by host and allow/deny decision |
| `botbox_request_duration_seconds` | Histogram | `host` | Upstream request duration |
| `botbox_upstream_errors_total` | Counter | `host`, `error_type` | Upstream errors (connection failures, timeouts, HTTP errors) |
| `botbox_header_rewrites_total` | Counter | `host` | Header rewrite operations |

## Graceful Shutdown

On SIGINT or SIGTERM:

1. Stop accepting new connections
2. Drain in-flight connections (up to 30 seconds)
3. Abort remaining connections after timeout
4. Shut down metrics server (5-second drain)

## Test Structure

- **71 unit tests** — allowlist (13), config (14), header_rewrite (6), secrets (9), proxy (29)
- **11 integration tests** — denied 403, CONNECT 405, missing host 400, metrics, healthz (ready/not-ready), 404, header injection, allowed forward, missing secret 500, timeout 504
- **E2E** — `k8s/egress-test.yaml` runs on a kind cluster with a real OpenAI API call (dummy key → 401)

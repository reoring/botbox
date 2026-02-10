# Security Considerations

This document describes BotBox security goals, implemented controls, and deployment guidance.

## Security Goals

- Keep API credentials out of application code, environment variables, and logs.
- Enforce outbound egress policy at the sidecar boundary.
- Prevent common proxy abuse patterns (header smuggling, tunnel bypass, open-proxy exposure).
- Fail closed when policy or secret resolution is invalid.

## Threat Model

### In Scope

- A compromised or buggy application container in the same Pod sending arbitrary HTTP requests.
- Attempts to reach non-approved upstream hosts.
- Attempts to inject or smuggle authentication headers.
- Attempts to bypass policy with case/port variations in hostnames.
- Attempts to abuse the sidecar as a network-accessible proxy.

### Out of Scope

- Full trust compromise of the Kubernetes node or control plane.
- Kernel-level compromise in the same host.
- Upstream provider compromise.

## Implemented Controls

### 1. Listener Exposure Control

- `listen_addr` defaults to `127.0.0.1`.
- `listen_addr` must be an IP literal (hostname values are rejected at config validation).
- Non-loopback bind is blocked unless explicitly enabled with `allow_non_loopback: true`.

Security impact:
- Prevents accidental open-proxy exposure and unauthorized use of secret-injecting routes.

Warning: Setting `allow_non_loopback: true` without compensating controls (authentication, NetworkPolicy) can expose the proxy to other workloads, allowing unauthorized use of injected credentials.

### 2. Egress Policy Enforcement

- Policy is host-based with exact match semantics.
- Recommended mode is `default_action: deny`.
- Host normalization is applied consistently in both validation and runtime lookup:
  - trim whitespace
  - lowercase
  - strip port for matching
- Duplicate rules after normalization are rejected (for example, `example.com` and `EXAMPLE.COM:443`).
- Policy is port-aware: requests default to port 443 only unless `allowed_ports` is explicitly configured per rule.
- Non-443 ports are denied by default, even if the host matches.

Security impact:
- Reduces bypass and policy-shadowing risk from representation differences.

### 3. Request Hardening

- `CONNECT` is explicitly rejected (`405`) to prevent generic TCP tunnel behavior.
- Hop-by-hop headers are stripped before forwarding:
  - standard set (`Connection`, `Keep-Alive`, `Transfer-Encoding`, and others)
  - `Proxy-Connection`
  - dynamic headers listed in `Connection` tokens
- Upstream `Host` header is rewritten deterministically.
- Outbound traffic is upgraded to HTTPS and sent through rustls with web PKI roots.

Security impact:
- Reduces proxy parsing ambiguity and smuggling surface.
- Blocks plaintext forward and enforces TLS origination.

### 4. Header Rewrite Safety

- Rewrite header names are validated at config load time.
- Rewrites use delete-then-add behavior to remove all prior values first.
- Secret-backed values are resolved via `secret_ref` and injected via templates.
- Missing secrets fail closed for that request (`500`) instead of forwarding without credentials.
- Reserved/hop-by-hop headers (Host, Connection, Transfer-Encoding, etc.) are blocked from rewrite at config validation time.

Security impact:
- Prevents attacker-supplied duplicate headers from surviving rewrite.
- Avoids accidental credential omission forwarding.

### 5. Secret Storage and Reload Safety

- Secret values are wrapped in a zeroizing, redacting type for `Debug` and `Display`.
- Secret loader follows symlinks only if the resolved path stays within `secrets_dir` (prevents directory traversal).
- Individual secret files are size-capped (1 MiB) to limit memory usage.
- Dotfiles and non-regular files are skipped.
- Secret reload uses atomic `ArcSwap` replacement.
- Reload failure keeps last known-good in-memory values.
- Required secrets (referenced by `secret_ref` in config) are tracked; `/healthz` returns 503 until all are available.

Security impact:
- Reduces accidental secret disclosure in logs.
- Secret memory is zeroized on drop to limit exposure in core dumps.
- Safely supports Kubernetes Secret volume layouts (symlink-based atomic updates).
- Avoids partial reload states.

## Secure Baseline Configuration

```yaml
listen_addr: "127.0.0.1"
listen_port: 8080
metrics_port: 9090
secrets_dir: "/var/run/secrets/botbox"
max_connections: 1024
allow_non_loopback: false

egress_policy:
  default_action: deny
  rules:
    - host: api.openai.com
      action: allow
      header_rewrites:
        - name: Authorization
          value: "Bearer {value}"
          secret_ref: openai-api-key
```

## Deployment Hardening Checklist

- Keep `allow_non_loopback: false` unless there is a strong, reviewed requirement.
- Keep `default_action: deny`.
- Restrict Pod-level network paths with Kubernetes `NetworkPolicy`.
- Mount secrets read-only and with least-privilege file permissions.
- Do not co-locate untrusted workloads in the same Pod as BotBox.
- Restrict access to metrics endpoint (`9090`) to trusted scrapers only.
- Rotate upstream API keys and monitor reload/error logs.
- Keep dependencies and base images updated with security patches.
- Never expose the BotBox proxy listener via a Kubernetes Service or Ingress.
- Use NetworkPolicy to restrict pod-level egress to only DNS and the proxy's upstream targets.
- If `allow_non_loopback` must be enabled, deploy compensating controls (mTLS or shared-secret authentication) and document the justification.
- Ensure app containers do NOT run as UID 1337 (BotBox's UID); otherwise they can bypass iptables owner-match rules.

## Residual Risks and Limitations

- Policy is hostname-based; DNS trust remains part of the security boundary.
- If `default_action: allow` is used, unknown hosts are reachable by design.
- BotBox does not provide upstream certificate pinning (uses system/web PKI roots).
- BotBox does not inspect payload content for exfiltration.

## Validation and Testing

- Unit tests cover allowlist behavior, header rewrite safety, secret reload logic, and proxy normalization paths.
- Run integration tests in an environment that permits local socket bind operations.


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
- Deployments must prevent direct outbound connections from application containers (iptables OUTPUT filter rules and/or NetworkPolicy). NAT redirect alone is bypassable for HTTPS and QUIC.
- Host normalization is applied consistently in both validation and runtime lookup:
  - trim whitespace
  - lowercase
  - strip port for host matching (port is validated separately)
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

### 6. HTTPS Interception Security Considerations

When HTTPS interception is enabled, BotBox terminates and re-originates TLS for outbound HTTPS traffic. This introduces additional security surface that must be carefully managed.

#### CA Key Protection

The CA private key is the root of trust for all dynamically issued leaf certificates. If compromised, an attacker could issue certificates for arbitrary hosts.

- The CA private key (`ca_key_path`) must be stored in a **separate volume** that is mounted only into the BotBox sidecar container.
- The CA private key must **never** be mounted into app containers. Only the CA certificate (public key) should be shared with app containers for trust configuration.
- Use Kubernetes Secret volumes with restrictive file permissions (e.g., `defaultMode: 0400`).
- Consider using a dedicated Kubernetes Secret (separate from the API key secrets) for CA material.

#### Short-lived Certificates

BotBox issues leaf certificates dynamically for each intercepted hostname. The `cert_ttl_seconds` configuration controls the validity period.

- Use the shortest practical TTL for your workload. The default is 86400 seconds (24 hours).
- Shorter TTLs limit the window of exposure if a leaf certificate's private key is extracted from memory.
- The `cert_cache_ttl_seconds` must not exceed `cert_ttl_seconds` to prevent serving expired certificates from cache.
- Valid range: 60 seconds to 604800 seconds (7 days).

#### deny_handshake_on_disallowed_sni

When `deny_handshake_on_disallowed_sni` is set to `true`, BotBox refuses to complete the TLS handshake for hostnames that are not in the allowlist. The connection is dropped before any certificate is issued.

- **Default:** `false` (the TLS handshake completes and the request is denied at the HTTP layer with 403).
- **When enabled:** Non-allowlisted hosts never receive a leaf certificate, providing defense-in-depth and reducing unnecessary cert issuance.
- Trade-off: with this enabled, the app container receives a TLS error instead of a clear 403 HTTP response for denied hosts, which may complicate debugging.

#### enforce_sni_host_match

When `enforce_sni_host_match` is `true` (the default), BotBox validates that the `Host` header in the decrypted HTTP request matches the SNI hostname from the TLS handshake.

- This prevents an attacker from establishing a TLS connection to an allowed host and then sending HTTP requests with a different `Host` header to bypass allowlist checks.
- Mismatches are logged and tracked via the `botbox_https_interception_host_mismatch_total` metric.
- The request is rejected with HTTP 400.

#### Absolute-form Request Rejection

HTTPS interception connections are transparently redirected, so the app container believes it is talking directly to the upstream server. Requests must use origin-form (`GET /path`). Absolute-form requests (`GET http://host/path`) are rejected because the URI authority could override the Host header and bypass security checks.

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
- Apply the recommended iptables NAT+filter rules via an init container (this repo provides an optional init image target `iptables-init`); avoid hand-maintained one-liner commands drifting over time.
- If you change the BotBox `runAsUser` from 1337, set `BOTBOX_UID` in the init container to match.
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
- Use `/healthz` for readiness only (it is gated on required secrets). For liveness, prefer a TCP socket probe on port 9090, or add a separate always-200 endpoint.
- **HTTPS Interception:** Mount the CA private key in a separate Kubernetes Secret volume accessible only to the BotBox sidecar (`readOnly: true`, `defaultMode: 0400`). Never mount the CA private key into the app container.
- **HTTPS Interception:** Only share the CA certificate (public) with app containers for trust configuration.
- **HTTPS Interception:** Enable `enforce_sni_host_match: true` (default) to prevent Host header spoofing after TLS termination.
- **HTTPS Interception:** Consider enabling `deny_handshake_on_disallowed_sni: true` for defense-in-depth (blocks TLS handshake for non-allowlisted hosts).
- **HTTPS Interception:** Set `cert_ttl_seconds` to the shortest practical value for your workload to limit exposure from compromised leaf keys.

## Residual Risks and Limitations

- Policy is hostname-based; DNS trust remains part of the security boundary.
- If `default_action: allow` is used, unknown hosts are reachable by design.
- BotBox does not provide upstream certificate pinning (uses system/web PKI roots).
- **IPv6 bypass:** iptables rules only cover IPv4. `BOTBOX_ENABLE_IPV6=1` mirrors rules via ip6tables, but requires kernel ip6table_nat support. When `BOTBOX_ENABLE_IPV6=0`, IPv6 traffic bypasses the proxy entirely — disable IPv6 at the node level (`net.ipv6.conf.all.disable_ipv6=1`) or block it with NetworkPolicy.
- BotBox does not inspect payload content for exfiltration.
- **HTTPS Interception — dynamic cert issuance:** Leaf certificates are generated at runtime and their private keys exist in BotBox process memory. A compromised BotBox process or memory-dump attack could expose them. Mitigate with short `cert_ttl_seconds`, restrictive container security context, and file system access controls.
- **HTTPS Interception — CA key compromise:** If the CA private key is extracted (e.g., via container escape or volume misconfiguration), an attacker can issue trusted certificates for any host within the Pod. Mitigate by strict volume mount isolation, short CA key lifetimes, monitoring `botbox_https_interception_cert_issued_total` for unexpected issuance, and rotating the CA immediately if compromise is suspected.
- **HTTPS Interception — in-memory plaintext:** After TLS termination, request/response data exists in plaintext in BotBox's process memory. This is inherent to the interception design and equivalent to the HTTP-only mode's threat surface.

## Validation and Testing

- Unit tests cover allowlist behavior, header rewrite safety, secret reload logic, and proxy normalization paths.
- Run integration tests in an environment that permits local socket bind operations.

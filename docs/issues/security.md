# Security Issues and Remediation TODOs

This document tracks security-relevant gaps found during a repo review and turns them into actionable engineering TODOs.

Scope:
- Runtime: BotBox sidecar egress proxy (HTTP/1.1 inbound, HTTPS outbound)
- Deployment: iptables-based transparent redirect (example manifests)
- Dependencies: Rust crates in `Cargo.lock`

Severity guide (rough):
- Critical: breaks the core security guarantee in normal deployments
- High: enables meaningful abuse or key misuse with realistic preconditions
- Medium: availability or defense-in-depth gaps; misconfig turns into security issues
- Low: hardening, hygiene, or edge-case bugs

## Top-Priority TODO (Suggested Order)

- [x] SEC-001: Make "all egress is enforced" true (TCP+UDP blocked; identity bypass + E2E proof pending).
- [x] SEC-004: Fix Kubernetes Secret volume compatibility and readiness (symlinks/size fixed; readiness gating implemented).
- [x] SEC-003: Prevent open-proxy exposure when binding non-loopback (docs + config validation warnings added).
- [x] SEC-002: Make allowlist port-aware / default-deny non-443.
- [x] SEC-005: Address RustSec advisory in dependency tree.
- [x] SEC-012: Fix IPv6 literal upstream authority formatting (brackets) to avoid invalid URIs/Host headers.

## Findings

### SEC-001 (Critical): Egress policy is trivially bypassable (HTTPS and non-80 traffic)

What happens today:
- The example iptables rules only `REDIRECT` outbound TCP traffic destined for `--dport 80` to BotBox (`:8080`).
- If the deployment only uses the NAT redirect (no OUTPUT filter rules / no NetworkPolicy), an application process can open connections to `:443` (HTTPS) or any other port directly, bypassing BotBox entirely.

Impact:
- The "deny-by-default allowlist" is not actually enforced for the majority of real-world outbound traffic.
- A compromised app can exfiltrate data to arbitrary destinations over HTTPS without going through BotBox.
- BotBox's secret-injection boundary becomes optional, not mandatory.

Where this shows up:
- `README.md` (initContainer iptables example)
- `docs/architecture.md` (transparent redirect explanation)
- `tests/e2e/manifests/egress-test.yaml` (iptables rules used in E2E)
- `scripts/iptables-init.sh` (idempotent init script)
- `Dockerfile` (Docker target `iptables-init` builds the init image)

Current status in this repository:
- Example manifests/docs now include an OUTPUT filter chain that drops direct outbound TCP **and** UDP from non-UID 1337 processes (blocks HTTPS and QUIC bypass). Only DNS (UDP/TCP 53) is exempted.
- The rules are applied by the optional init image (Docker target `iptables-init`) which runs `scripts/iptables-init.sh`.
- Remaining bypass: any workload running as UID 1337 can bypass `-m owner --uid-owner 1337`.

Why this is hard:
- BotBox intentionally rejects `CONNECT` (no generic tunnel).
- BotBox does not accept inbound TLS from the app container(s) (no transparent TLS interception).
- Therefore, enforcing "all outbound traffic goes through BotBox" cannot be achieved by naively redirecting `:443` to `:8080` (that would break, because inbound would be TLS, not HTTP).

Recommended direction (pick and codify one):

Option A (Recommended if keeping current design): Enforce "apps must speak HTTP to BotBox, BotBox speaks HTTPS upstream".
- Keep the `:80 -> :8080` redirect.
- Add *explicit* egress blocking so app containers cannot open direct outbound TCP (especially `:443`).
- Allow only BotBox's own process (by UID/GID/cgroup) to open `:443` to the outside world.
- Allow DNS (and any other required cluster services) explicitly.

Option B: Turn BotBox into a real egress proxy for arbitrary TLS by implementing CONNECT (and authenticate it).
- Requires a policy model for CONNECT destinations and stronger abuse protections.
- Changes the project's threat model substantially.

Option C: Use an external egress gateway / service mesh that already enforces L7 egress policy.
- BotBox becomes a credential-injection component behind that gateway.

TODO:
- [x] Decide and document the supported enforcement model (Option A) and what is *out of scope*.
- [x] Update `README.md` and `tests/e2e/manifests/egress-test.yaml` to include egress-blocking filter rules (Option A).
- [x] Tighten the filter rules to also block non-DNS UDP (QUIC/UDP 443 bypass); allowlist only what the pod actually needs.
- [x] Ensure examples/docs set application containers to a UID != 1337 (BotBox UID).
- [ ] Consider `-m cgroup` (where available) instead of UID matching for stronger separation.
- [ ] Add an automated test (kind/E2E) that proves bypass is blocked for direct TCP 443 and direct UDP 443, while HTTP via BotBox still succeeds.


### SEC-002 (High): Allowlist is port-insensitive, enabling "allowed host on any port" (Fixed)

What happened before:
- Policy matching normalized hostnames by stripping ports and did not enforce a port policy.

Current status in this repository:
- Allowlist is port-aware.
- Default behavior is conservative: if a request specifies no port, BotBox treats it as 443; if a request specifies a port, it must be explicitly allowed via `allowed_ports`.

Impact:
- The policy boundary is weaker than "host + standard TLS port".
- If the allowed hostname exposes services on alternate ports (or if infrastructure changes later), BotBox could be used to reach unintended services.

Where this shows up:
- `src/config.rs` (`normalize_policy_host` strips port)
- `src/allowlist.rs` (lookup uses normalized host)
- `src/proxy.rs` (`build_upstream_uri` uses client-supplied port when non-443)

Recommended fix:
- Make policy explicitly port-aware.
- Default behavior should be conservative: only allow `443` upstream unless a rule explicitly lists other ports.
- Alternatively: reject any request that specifies a non-443 port unless the rule explicitly opts in.

TODO:
- [x] Extend config schema to support ports (`allowed_ports: [443, 8443]`).
- [x] Enforce port policy in allowlist (default 443-only; non-443 requires explicit allowance).
- [x] Add tests for non-443 port attempts (deny by default).
- [x] Update docs to describe the port model (`docs/architecture.md`, `docs/security.md`) and update config examples.


### SEC-003 (High): Non-loopback bind can turn BotBox into a secret-injecting open proxy

What happens today:
- `listen_addr` can be set to a non-loopback IP if `allow_non_loopback: true` is set.

Impact:
- If the Pod/network exposes the listener (accidentally or intentionally), other workloads could send requests through BotBox and obtain access to upstream APIs using injected credentials.
- This is especially dangerous because BotBox is designed to add API keys automatically.

Where this shows up:
- `src/config.rs` (validation gate)
- `README.md` and `docs/security.md` (deployment guidance)

Recommended fix:
- Keep loopback binding as the only supported mode by default.
- If non-loopback must be supported, require explicit compensating controls (authn/z, mTLS, or strict NetworkPolicy) and fail fast if absent.

TODO:
- [ ] Add a "hard fail" mode (or default) that disallows non-loopback binding in production builds.
- [ ] If non-loopback is a requirement: implement request authentication/authorization (at minimum a shared secret or mTLS) and document how to deploy it safely.
- [x] Add a deployment hardening section that states: no Service/Ingress should expose the proxy listener.
- [x] Add config validation warnings when allow_non_loopback or default_action: allow are used.


### SEC-004 (Medium): Kubernetes Secret volumes likely do not load due to symlink skipping (Partially fixed)

What happened before:
- Secret loader skipped symlinks, which is incompatible with common Kubernetes Secret/ConfigMap volume layouts.

Current status in this repository:
- Secret loader follows symlinks only if the resolved path stays under `secrets_dir` (prevents traversal).
- Secret files are size-capped (1 MiB per file) to reduce memory abuse.
- Tests cover K8s-style `..data` layouts and escaping symlinks.

Impact:
- If required secrets are missing, requests that require secret injection fail with 500 (`secret not available`).

Where this shows up:
- `src/secrets.rs` (symlink + size-cap handling, `check_required_secrets()`)
- `src/config.rs` (`required_secret_refs()` extracts all `secret_ref` names from config)
- `src/main.rs` (readiness gated on required secrets; periodic re-check updates `/healthz`)
- `tests/e2e/manifests/egress-test.yaml` (uses a Secret volume mount)

Recommended fix:
- Allow symlinks **only when they resolve within** `secrets_dir` (prevent traversal) so K8s mounts work.
- Add validation/readiness around *required* secrets referenced by config.

TODO:
- [x] Update secret loader to safely follow symlinks (prefix-check resolved paths; reject escapes).
- [x] Add maximum secret file size limits (defense-in-depth; avoid memory abuse).
- [x] Add an integration test that simulates a K8s-style `..data` symlink layout.
- [x] Track "required secrets" from config (`secret_ref` values) and:
  - keep `/healthz` not-ready until they appear (implemented via periodic check + readiness gating)
- [x] Update `docs/security.md` to reflect the new secret-loading behavior (symlink handling + size cap + readiness gating).


### SEC-005 (High): RustSec advisory in dependency tree (`protobuf` via `prometheus`) (Fixed)

Finding:
- `cargo audit` previously reported:
  - Crate: `protobuf` v2.28.0
  - Advisory: RUSTSEC-2024-0437 (uncontrolled recursion -> crash)
  - Dependency path: `protobuf` -> `prometheus` -> `botbox`

Current status in this repository:
- Fixed by upgrading dependencies (`prometheus` -> 0.14, `protobuf` -> 3.7.2).
- `cargo audit` exit code is 0.

Impact:
- Potential denial-of-service depending on how/where protobuf parsing/serialization is exercised.
- Even if practical exploitability is low in current code paths, this will typically fail security compliance gates.

Where this shows up:
- `Cargo.lock` (resolved versions)
- `Cargo.toml` (`prometheus` dependency)

Recommended fix:
- Upgrade dependencies until `cargo audit` is clean.
- If the ecosystem does not yet support a fixed `protobuf` major, consider:
  - swapping metrics backend, or
  - removing/isolating the vulnerable code path, or
  - documenting exploitability and applying compensating controls temporarily (time-boxed).

TODO:
- [x] Upgrade `prometheus` (and transitive deps) and re-run `cargo audit`.
- [ ] If still pinned to vulnerable `protobuf`, evaluate alternate Prometheus exporter crates or metric libraries.
- [ ] Add CI job that runs `cargo audit` and fails on new advisories.


### SEC-006 (Medium): `secrets_dir` default is overly broad and can load unintended files (Fixed)

What happens today:
- If `secrets_dir` is not set, code defaults to `/var/run/secrets/botbox`.

Impact:
- Misconfiguration can cause BotBox to load unrelated secret material that happens to exist in that tree (e.g., service account tokens).
- In the worst case, an operator could accidentally wire a `secret_ref` to sensitive, non-API-key data.

Where this shows up:
- `src/config.rs` (`secrets_dir()` default)

TODO:
- [x] Change the default to a BotBox-specific subdirectory (`/var/run/secrets/botbox`).
- [ ] Consider an allowlist of secret keys (derived from config) instead of reading the entire directory.


### SEC-012 (Low): IPv6 literal upstream authority formatting is invalid (missing brackets)

What happens today:
- For IPv6 literals, `host_header_value()` and `build_upstream_uri()` can produce invalid authorities like `https://::1/` or `https://::1:8443/`.
- IPv6 in URI authorities and HTTP `Host` headers must be bracketed (`[::1]`, `[::1]:8443`).

Impact:
- Requests to IPv6 literal upstreams fail (typically 500 due to URI parse failure).
- If IPv6 literals are allowed by policy, a client can trigger avoidable errors and degrade availability.

Where this shows up:
- `src/proxy.rs` (`host_header_value`, `build_upstream_uri`)

TODO:
- [x] Implement correct authority formatting for IPv6 literals (bracket for both upstream URI and `Host` header).
- [x] Add unit tests for IPv6 without port and with non-443 ports.
- [x] Ensure allowlist + proxy normalization agree for bracketed vs bare IPv6 inputs.


### SEC-007 (Medium): Timeout applies to upstream request, not necessarily response body streaming

What happens today:
- A timeout wraps `client.request(...)`, then BotBox streams the upstream response body without additional time bounds.

Impact:
- An allowed upstream (or network middlebox) that stalls a response body can hold BotBox connections and semaphores, leading to resource exhaustion.

Where this shows up:
- `src/proxy.rs` (timeout + streaming)

TODO:
- [ ] Add response-body idle timeout and/or overall request deadline (including streaming).
- [ ] Add per-connection read/write timeouts (downstream and upstream).
- [ ] Consider max response size caps for endpoints where that is acceptable.


### SEC-008 (Medium): Header rewrite policy can allow unsafe headers (e.g., `Host`) (Fixed)

What happened before:
- Header rewrite config validated header names syntactically but did not restrict reserved/hop-by-hop headers.

Current status in this repository:
- Config validation rejects rewrites for reserved/hop-by-hop headers (including `Host`).

Impact:
- Misconfiguration can create request-routing confusion or unintended upstream routing behavior.

Where this shows up:
- `src/header_rewrite.rs`
- `src/proxy.rs`

TODO:
- [x] Add a denylist of headers that cannot be rewritten (at minimum `Host` and hop-by-hop headers).
- [x] Forbid rewriting `Host` so rewrite ordering cannot override it.
- [x] Document safe header rewrite patterns and footguns (docs/security.md updated).


### SEC-009 (Low): Metrics label cardinality can become unbounded with `default_action: allow`

What happens today:
- When default policy is allow, unknown hosts are accepted and the `host` label can be attacker-controlled.

Impact:
- Unbounded label cardinality can exhaust memory / CPU in the metrics registry.

Where this shows up:
- `src/allowlist.rs` (default allow creates a bare allow rule)
- `src/proxy.rs` (metrics label uses request host)

TODO:
- [x] Cap label cardinality: `DefaultAllow` decisions use a fixed `_default_allow` host label instead of attacker-controlled values.
- [x] Config validation emits a warning when `default_action: allow` is used (discouraged for production).


### SEC-010 (Low): Secrets are stored as plain `String` (no zeroization) (Fixed)

What happens today:
- Secret material in the secret store is held in a `Zeroizing<String>` and is redacted for `Debug`/`Display`.

Impact:
- In-memory exposure risks (core dumps, memory scraping) are not mitigated.

Where this shows up:
- `src/secrets.rs`

TODO:
- [x] Add zeroization for secret values on drop.
- [ ] Consider additional hardening (e.g., `secrecy::SecretString`) to reduce accidental clones/copies across code paths.


### SEC-011 (Low): Example/test manifests contain "key-shaped" strings

What happens today:
- Test and example files include dummy strings that resemble API keys.

Impact:
- Increases the chance real keys are accidentally committed later (people copy/paste).

Where this shows up:
- `tests/e2e/manifests/egress-test.yaml`
- `tests/integration_test.rs`

TODO:
- [x] Make all examples explicitly "NOT A REAL KEY" and/or use obvious placeholders.
- [ ] Add a secret scanning tool in CI (e.g., gitleaks) to prevent accidental key commits.


## Verification Checklist (After Fixes)

- [x] `cargo test` passes (71 unit tests + 11 integration tests)
- [x] `cargo audit` is clean (prometheus upgraded to 0.14, protobuf to 3.7.2)
- [x] `cargo clippy` is clean
- [ ] E2E test proves bypass is blocked under the supported enforcement model (requires kind cluster; include TCP 443 and UDP 443 bypass attempts)
- [x] Readiness only reports ready when required secrets are available (implemented via periodic check + AtomicBool gating)

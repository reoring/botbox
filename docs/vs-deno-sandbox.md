# BotBox vs Deno Sandbox (allowNet + secrets)

This document compares BotBox with Deno Sandbox's outbound network restriction (`allowNet`) and secret injection (`secrets`) as described in the `@deno/sandbox` SDK documentation.

The goal is to evaluate containment properties for autonomous agents:

- What reduces exfiltration to arbitrary destinations?
- What prevents credential *values* from being disclosed to agent code?
- What remains possible when an upstream must be allowlisted?

## Problem Statement

In agentic coding you often need both:

- outbound access to a sensitive upstream API (for example GitHub API), and
- credentials (API keys / tokens) to authenticate.

Host allowlisting can reduce the set of reachable exfil destinations, but it cannot stop misuse/exfiltration via an allowlisted upstream.

This document separates two risks:

1. Secret value exfiltration: the agent learns and leaks the credential value.
2. Token misuse / data exfiltration: the agent does not learn the value, but can still use injected credentials to perform unwanted actions or leak other data to an allowlisted upstream.

## Source Excerpts (Quoted)

Deno Sandbox (`@deno/sandbox`):

> "Create isolated sandboxes on Deno Deploy to securely run code in a lightweight Linux microVM." ([DENO-OVERVIEW])

> "You can restrict which hosts the sandbox can make outbound network requests to using the `allowNet` option." ([DENO-ALLOWNET])

> "If `allowNet` is not specified, no network restrictions are applied." ([DENO-ALLOWNET])

> Supported patterns:
> - Exact hostnames with optional ports: "example.com", "example.com:80"
> - Wildcard subdomains with optional ports: "*.example.com", "*.example.com:443"
> - IP addresses with optional ports: "203.0.113.110", "203.0.113.110:80"
> - IPv6 addresses with optional ports: "[2001:db8::1]", "[2001:db8::1]:443" ([DENO-ALLOWNET])

> "Set secret environment variables that are never exposed to sandbox code. The real secret values are injected on the wire when the sandbox makes HTTPS requests to the specified hosts." ([DENO-SECRETS])

BotBox (this repo):

> "BotBox is a Kubernetes sidecar proxy that sits between your container and the internet. It intercepts all outbound traffic via iptables, enforces a deny-by-default allowlist, and injects API keys at the network boundary — so the container itself never holds credentials and can only reach hosts you explicitly permit." ([BOTBOX-README-OVERVIEW])

> "- **The agent never sees real API keys.** Credentials are stored in Kubernetes Secrets and injected by BotBox at the network layer." ([BOTBOX-README-CONTAINMENT])

> "- **Auditable.** Every request is logged with structured tracing. You can see exactly what your agent tried to reach and whether it was allowed or denied." ([BOTBOX-README-CONTAINMENT])

> "- Policy is host-based with exact match semantics." ([BOTBOX-SECURITY-EGRESS])

> "- Policy is port-aware: requests default to port 443 only unless `allowed_ports` is explicitly configured per rule." ([BOTBOX-SECURITY-EGRESS])

> "- Deployments must prevent direct outbound connections from application containers (iptables OUTPUT filter rules and/or NetworkPolicy). NAT redirect alone is bypassable for HTTPS and QUIC." ([BOTBOX-SECURITY-EGRESS])

> "| Filter: `-p udp -j DROP` | Block all other direct outbound UDP from app containers (prevents QUIC bypass) |" ([BOTBOX-ARCH-IPTABLES])

> "- `CONNECT` is explicitly rejected (`405`) to prevent generic TCP tunnel behavior." ([BOTBOX-SECURITY-HARDENING])

> "- Rewrites use delete-then-add behavior to remove all prior values first." ([BOTBOX-SECURITY-REWRITE])

> "- Secret-backed values are resolved via `secret_ref` and injected via templates." ([BOTBOX-SECURITY-REWRITE])

> "- Missing secrets fail closed for that request (`500`) instead of forwarding without credentials." ([BOTBOX-SECURITY-REWRITE])

> "When HTTPS interception is enabled, BotBox terminates and re-originates TLS for outbound HTTPS traffic." ([BOTBOX-SECURITY-HTTPS])

> "- The CA private key (`ca_key_path`) must **never** be mounted into app containers." ([BOTBOX-SECURITY-HTTPS])

> "Absolute-form requests (`GET http://host/path`) are rejected because the URI authority could override the Host header and bypass security checks." ([BOTBOX-SECURITY-HTTPS])

> "- Policy is hostname-based; DNS trust remains part of the security boundary." ([BOTBOX-SECURITY-RESIDUAL])

> "- BotBox does not inspect payload content for exfiltration." ([BOTBOX-SECURITY-RESIDUAL])

> "- **IPv6 bypass:** ... When `BOTBOX_ENABLE_IPV6=0`, IPv6 traffic bypasses the proxy entirely ..." ([BOTBOX-SECURITY-RESIDUAL])

## Boundary and Trust Model

### Isolation boundary

Deno Sandbox is described as a lightweight Linux microVM sandbox ([DENO-OVERVIEW]). BotBox is a Kubernetes sidecar proxy that provides a network boundary inside a Pod ([BOTBOX-README-OVERVIEW]).

Practical implication:

- Deno Sandbox implies a VM boundary around execution.
- BotBox does not aim to be a compute/filesystem sandbox; it focuses on egress policy and credential handling at the network boundary.

### What is being contained?

Both approaches focus on containment by controlling outbound communication and credential exposure:

- Deno Sandbox: `allowNet` for outbound restriction, `secrets` for on-the-wire injection ([DENO-ALLOWNET], [DENO-SECRETS]).
- BotBox: iptables + proxy allowlist + boundary injection, with an explicit requirement to block direct egress from application containers ([BOTBOX-SECURITY-EGRESS]).

## Network Egress Policy: Semantics and Expressiveness

### Host matching

- Deno `allowNet` supports patterns including wildcard subdomains, IPs, and IPv6 literals (with optional ports) ([DENO-ALLOWNET]).
- BotBox policy uses exact host match semantics ([BOTBOX-SECURITY-EGRESS]).

Trade-off:

- Wildcards reduce config overhead but can widen the allowed set.
- Exact match reduces ambiguity but requires enumerating all necessary hosts.

### Default behavior when unset

The `@deno/sandbox` documentation states that if `allowNet` is not specified, network restrictions are not applied ([DENO-ALLOWNET]). BotBox's recommended baseline is deny-by-default allowlisting (as described in the README and security docs) ([BOTBOX-README-OVERVIEW], [BOTBOX-SECURITY-EGRESS]).

### Port behavior

- Deno `allowNet` patterns include optional ports ([DENO-ALLOWNET]).
- BotBox defaults to allowing only port 443 unless `allowed_ports` is configured ([BOTBOX-SECURITY-EGRESS]).

## Secret Injection: Where Secrets Live and How They Are Applied

### Deno Sandbox `secrets`

The SDK describes secrets as environment variables that are "never exposed to sandbox code", with real values injected on the wire for HTTPS requests to specified hosts ([DENO-SECRETS]).

The cited documentation does not specify what the in-sandbox value looks like (absent vs placeholder) or how injection is implemented; the documented contract is "never exposed" and "injected on the wire" ([DENO-SECRETS]).

### BotBox boundary injection

BotBox is described as injecting API keys at the network boundary so the application container does not hold credentials ([BOTBOX-README-OVERVIEW]). Secret-backed injection is implemented via header rewrite templates that resolve `secret_ref` values, remove prior header values first, and fail closed when secrets are missing ([BOTBOX-SECURITY-REWRITE]).

## Enforcement Points and Bypass Surface (BotBox)

BotBox explicitly calls out that NAT redirect alone is not sufficient and that deployments must prevent direct outbound connections from app containers; otherwise bypasses exist for HTTPS and QUIC ([BOTBOX-SECURITY-EGRESS]).

The reference iptables design includes a UDP drop rule to prevent QUIC bypass ([BOTBOX-ARCH-IPTABLES]).

BotBox also rejects CONNECT to avoid generic tunnel behavior ([BOTBOX-SECURITY-HARDENING]).

When HTTPS interception is enabled, BotBox terminates and re-originates TLS; additional request-shape checks (such as rejecting absolute-form requests) are described to prevent authority-based bypasses ([BOTBOX-SECURITY-HTTPS]).

## The "Allowlisted Upstream" Case (e.g. GitHub)

### 1) Secret value exfiltration

Both systems (as documented) aim to prevent the agent from learning the real credential value:

- Deno: secrets are "never exposed" and are injected on the wire ([DENO-SECRETS]).
- BotBox: the container "never holds credentials" and secret-backed rewrites fail closed ([BOTBOX-README-OVERVIEW], [BOTBOX-SECURITY-REWRITE]).

If deployed correctly, this blocks the simplest leak: "print the token value".

### 2) Token misuse / data exfiltration to an allowlisted host

Neither mechanism can, by itself, prevent an agent from using injected credentials to do harmful things *against an allowlisted upstream*.

This is true even when the token value is never disclosed. Mitigation is largely outside the egress boundary:

- least-privilege / fine-grained / short-lived tokens,
- upstream-side guardrails (repo protections, required reviews, scope-limited tokens),
- minimizing what is allowlisted.

## Attack/Defense Matrix (Agent Threats)

Legend:

- Mitigated: documented to be prevented by design.
- Not mitigated: possible given the model or outside the stated guarantees.
- Unknown: not specified in the cited sources.

| Threat | Deno Sandbox (`allowNet` / `secrets`) | BotBox |
|---|---|---|
| Leak credential value by printing env / reading files | Mitigated by "never exposed to sandbox code" ([DENO-SECRETS]) | Mitigated by "container itself never holds credentials" plus boundary injection semantics ([BOTBOX-README-OVERVIEW], [BOTBOX-SECURITY-REWRITE]) |
| Exfiltrate to arbitrary attacker domain over HTTPS | Mitigated if the domain is not in `allowNet` ([DENO-ALLOWNET]) | Mitigated by deny-by-default allowlisting, assuming direct egress is blocked as required ([BOTBOX-README-OVERVIEW], [BOTBOX-SECURITY-EGRESS]) |
| Exfiltrate to an allowlisted upstream | Not mitigated by allowlisting and value-hiding alone | Not mitigated by allowlisting and value-hiding alone |
| Use injected token to perform unwanted actions against an allowlisted upstream | Not mitigated by value-hiding alone | Not mitigated by value-hiding alone |
| QUIC bypass | Unknown from SDK docs | Mitigated if direct UDP is blocked as described ([BOTBOX-SECURITY-EGRESS], [BOTBOX-ARCH-IPTABLES]) |
| IPv6 bypass | Unknown from SDK docs (though allowNet supports IPv6 patterns) ([DENO-ALLOWNET]) | Not mitigated unless IPv6 controls are enabled; bypass is documented when disabled ([BOTBOX-SECURITY-RESIDUAL]) |

## Residual Risks (BotBox)

BotBox documents several limitations relevant to containment:

- Hostname-based policy means DNS trust is part of the boundary ([BOTBOX-SECURITY-RESIDUAL]).
- Payload content is not inspected for exfiltration ([BOTBOX-SECURITY-RESIDUAL]).
- IPv6 can bypass when IPv6 rules are disabled ([BOTBOX-SECURITY-RESIDUAL]).
- HTTPS interception introduces CA key compromise risk and plaintext-in-memory exposure ([BOTBOX-SECURITY-HTTPS], [BOTBOX-SECURITY-RESIDUAL]).

## Practical Recommendations (Allowlisted Upstream)

Once a powerful upstream must be allowlisted and credentials must be usable against it, the primary safety lever becomes credential minimization:

- Use least-privilege, fine-grained, short-lived tokens.
- Constrain the allowed host set to the minimum required.
- Add upstream-side guardrails (repo protections, required review, tight token scopes).

BotBox-specific operational notes follow from its documented deployment requirements:

- Block direct egress from app containers (OUTPUT filter rules / NetworkPolicy) ([BOTBOX-SECURITY-EGRESS]).
- Ensure app containers do not run as BotBox UID to avoid owner-match bypass ([BOTBOX-ARCH-UID]).
- If enabling HTTPS interception, keep the CA private key mounted only into BotBox ([BOTBOX-SECURITY-HTTPS]).

## Conclusion

Both Deno Sandbox `secrets` and BotBox boundary injection are designed to prevent secret *value* disclosure to agent code ([DENO-SECRETS], [BOTBOX-README-OVERVIEW]). This addresses a key weakness of allowlist-only designs for credential value exfiltration, even when a sensitive upstream must be allowlisted.

However, neither approach can prevent token misuse or data exfiltration to an allowlisted upstream by itself. The remaining risk must be managed with least privilege, upstream-side controls, and minimizing what is allowlisted.

## References

- [DENO-OVERVIEW] https://jsr.io/@deno/sandbox#@deno/sandbox
- [DENO-ALLOWNET] https://jsr.io/@deno/sandbox#restrict-outbound-network-access
- [DENO-SECRETS] https://jsr.io/@deno/sandbox#secret-on-the-wire
- [BOTBOX-README-OVERVIEW] https://github.com/reoring/botbox/blob/main/README.md#L13-L15
- [BOTBOX-README-CONTAINMENT] https://github.com/reoring/botbox/blob/main/README.md#L19-L24
- [BOTBOX-SECURITY-EGRESS] https://github.com/reoring/botbox/blob/main/docs/security.md#L41-L53
- [BOTBOX-SECURITY-HARDENING] https://github.com/reoring/botbox/blob/main/docs/security.md#L57-L66
- [BOTBOX-SECURITY-REWRITE] https://github.com/reoring/botbox/blob/main/docs/security.md#L71-L78
- [BOTBOX-SECURITY-HTTPS] https://github.com/reoring/botbox/blob/main/docs/security.md#L99-L140
- [BOTBOX-SECURITY-RESIDUAL] https://github.com/reoring/botbox/blob/main/docs/security.md#L185-L194
- [BOTBOX-ARCH-IPTABLES] https://github.com/reoring/botbox/blob/main/docs/architecture.md#L141-L154
- [BOTBOX-ARCH-UID] https://github.com/reoring/botbox/blob/main/docs/architecture.md#L156-L158

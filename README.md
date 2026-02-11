# BotBox

[![CI](https://github.com/reoring/botbox/actions/workflows/ci.yml/badge.svg)](https://github.com/reoring/botbox/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

<p align="center">
  <img src="docs/botbox.png" alt="BotBox" width="600">
</p>

**Sandbox any container's network — especially AI agents.**

BotBox is a Kubernetes sidecar proxy that sits between your container and the internet. It intercepts all outbound traffic via iptables, enforces a deny-by-default allowlist, and injects API keys at the network boundary — so the container itself never holds credentials and can only reach hosts you explicitly permit.

### AI Agent Containment

Running an autonomous AI agent (LLM-based coding agent, tool-use agent, etc.) in a container? BotBox gives you a hard network boundary:

- **The agent can only reach hosts you allow.** Deny-by-default policy blocks all other egress — no data exfiltration, no unauthorized API calls.
- **The agent never sees real API keys.** Credentials are stored in Kubernetes Secrets and injected by BotBox at the network layer. Even if the agent dumps its own environment or memory, there are no keys to leak.
- **Zero app changes required.** iptables transparent redirect means the agent doesn't need proxy settings — it just makes normal HTTP requests and BotBox handles the rest.
- **Auditable.** Every request is logged with structured tracing. You can see exactly what your agent tried to reach and whether it was allowed or denied.

```mermaid
flowchart LR
    subgraph Pod
        Agent["🤖 AI Agent<br/><i>no credentials</i>"]
        IPT[/"iptables<br/>transparent<br/>redirect"/]
        BotBox["🔒 BotBox<br/><i>sidecar</i>"]
    end

    Agent -- "curl http://api.openai.com" --> IPT
    IPT -- ":80 → :8080" --> BotBox

    BotBox -- "✅ Allowed + TLS + Key injected" --> API["api.openai.com"]
    BotBox -. "❌ Denied → 403" .-> Agent

    style Agent fill:#fef3c7,stroke:#d97706
    style BotBox fill:#dbeafe,stroke:#2563eb
    style API fill:#d1fae5,stroke:#059669
```

This makes BotBox a natural fit for any scenario where you need to **run untrusted or semi-trusted code** with controlled, auditable network access.

## How it Works

### Request Processing

```mermaid
flowchart LR
    A["HTTP request"] --> B{"Allowlist"}
    B -- "deny" --> C["403"]
    B -- "allow" --> D["Rewrite headers\n+ inject secrets"] --> E["TLS → upstream"]

    style C fill:#fee2e2,stroke:#dc2626
    style E fill:#d1fae5,stroke:#059669
```

See [Architecture](docs/architecture.md) for the full request processing pipeline.

### iptables Network Rules

```mermaid
flowchart TD
    OUT["Outbound packet<br/><i>OUTPUT chain</i>"] --> FIL{"EGRESS_FILTER"}

    FIL -- "loopback" --> PASS1["✅ RETURN"]
    FIL -- "UID 1337<br/><i>BotBox itself</i>" --> PASS2["✅ RETURN"]
    FIL -- "DNS (53)" --> PASS3["✅ RETURN"]
    FIL -- "other TCP/UDP" --> DROP["🚫 DROP"]

    OUT --> NAT{"EGRESS_REDIRECT<br/><i>NAT</i>"}
    NAT -- "loopback" --> SKIP1["RETURN"]
    NAT -- "UID 1337" --> SKIP2["RETURN"]
    NAT -- "TCP :80" --> REDIR[":80 → :8080<br/><i>REDIRECT to BotBox</i>"]

    style DROP fill:#fee2e2,stroke:#dc2626
    style REDIR fill:#dbeafe,stroke:#2563eb
```

## Quickstart

### Prerequisites

- Docker
- [kind](https://kind.sigs.k8s.io/)
- kubectl

### 1. Build and load the images

```bash
docker build -t botbox:test .
docker build --target iptables-init -t botbox-iptables-init:test .
kind load docker-image botbox:test botbox-iptables-init:test
```

### 2. Write your egress policy

```yaml
# config.yaml
allow_non_loopback: false  # keep false unless intentionally exposing outside the pod
egress_policy:
  default_action: deny
  rules:
    - host: api.openai.com
      action: allow
      header_rewrites:
        - name: Authorization
          value: "Bearer {value}"
          secret_ref: openai-api-key   # reads from K8s Secret
```

### 3. Add the sidecar to your pod

```yaml
initContainers:
  - name: iptables-init          # installs the recommended iptables NAT+filter rules
    image: botbox-iptables-init:test
    securityContext:
      capabilities: { add: [NET_ADMIN] }
      runAsUser: 0
      runAsNonRoot: false

  - name: botbox                  # runs for the pod's lifetime
    image: botbox:test
    restartPolicy: Always
    args: ["--config", "/etc/botbox/config.yaml"]
    securityContext:
      runAsUser: 1337
      runAsNonRoot: true
    # mount your ConfigMap and Secret here

containers:
  - name: app                     # your application — no proxy config needed
    image: your-app:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000             # must NOT be 1337 (BotBox UID) or iptables owner-match can be bypassed
```

### 4. Run acceptance tests on kind (automated)

```bash
tests/e2e/run-kind-acceptance.sh
```

### 5. Run individual E2E tests (optional)

```bash
tests/e2e/run-egress-test.sh
tests/e2e/run-https-interception-test.sh
```

### 6. Run unit tests

```bash
cargo test
```

## Why

| Problem | How BotBox solves it |
|---|---|
| API keys leaked in app env vars | Keys live only in K8s Secrets, injected at the network boundary |
| Apps must configure HTTP_PROXY | iptables makes interception transparent — zero app changes |
| Uncontrolled outbound traffic | Deny-by-default allowlist; only approved hosts are reachable |
| Key rotation requires restarts | Secrets directory is watched with inotify; hot-reload, no downtime |

## Documentation

- [Architecture](docs/architecture.md) — module structure, request flow, iptables rules, configuration reference
- [Security](docs/security.md) — threat model, controls, hardening checklist, residual risks

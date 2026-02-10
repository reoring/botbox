# BotBox

A Kubernetes sidecar that transparently adds API keys to outbound requests. Your app calls `curl http://api.openai.com/v1/models` — BotBox intercepts it via iptables, injects the `Authorization` header from a Kubernetes Secret, and forwards over HTTPS. Your app never sees the real key.

## Quickstart

### Prerequisites

- Docker
- [kind](https://kind.sigs.k8s.io/)
- kubectl

### 1. Build and load the image

```bash
docker build -t botbox:test .
kind load docker-image botbox:test
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
  - name: iptables-init          # sets up transparent redirect
    image: alpine:3.19
    command: ["/bin/sh", "-c", "apk add --no-cache iptables && iptables -t nat -N EGRESS_REDIRECT && iptables -t nat -A EGRESS_REDIRECT -o lo -j RETURN && iptables -t nat -A EGRESS_REDIRECT -m owner --uid-owner 1337 -j RETURN && iptables -t nat -A EGRESS_REDIRECT -p tcp --dport 80 -j REDIRECT --to-port 8080 && iptables -t nat -I OUTPUT 1 -p tcp -j EGRESS_REDIRECT && iptables -N EGRESS_FILTER && iptables -A EGRESS_FILTER -o lo -j RETURN && iptables -A EGRESS_FILTER -m owner --uid-owner 1337 -j RETURN && iptables -A EGRESS_FILTER -p udp --dport 53 -j RETURN && iptables -A EGRESS_FILTER -p tcp --dport 53 -j RETURN && iptables -A EGRESS_FILTER -p tcp -j DROP && iptables -A EGRESS_FILTER -p udp -j DROP && iptables -I OUTPUT 1 -j EGRESS_FILTER"]
    securityContext:
      capabilities: { add: [NET_ADMIN] }
      runAsUser: 0

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
```

### 4. Run the E2E test

```bash
kubectl apply -f k8s/egress-test.yaml
kubectl -n egress-test wait --for=jsonpath='{.status.phase}'=Succeeded pod/egress-test --timeout=120s
kubectl -n egress-test logs egress-test -c curl-client
kubectl delete namespace egress-test
```

### 5. Run unit tests

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

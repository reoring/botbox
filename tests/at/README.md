# BotBox Acceptance Test (AT) Procedure

This document defines manual acceptance tests for BotBox.
The tests validate the end-to-end behavior in a Kubernetes cluster (kind recommended).

## Scope

- iptables init image applies NAT redirect + OUTPUT egress filter
- BotBox enforces host allowlist and port policy
- Header rewrite injects secrets (and fails closed when missing)
- Readiness gating via `/healthz` reflects required secret availability
- Direct egress bypass (TCP 443 and UDP 443/QUIC) is blocked for non-BotBox UIDs

## Prerequisites

- Docker
- kind
- kubectl

Notes:
- These tests require Pod-level iptables (`CAP_NET_ADMIN`) to be permitted.
- The test pod reaches `httpbin.org` over the public internet.

## Automated Execution (kind E2E)

For an automated acceptance run (image build + kind image load + non-MITM E2E + MITM E2E), use:

```bash
tests/e2e/run-kind-acceptance.sh
```

Useful environment variables:

- `KIND_CLUSTER_NAME` (default: `kind`)
- `KUBECTL_CONTEXT` (default: `kind-${KIND_CLUSTER_NAME}`)
- `CREATE_KIND_CLUSTER=1` to auto-create the cluster when missing
- `SKIP_IMAGE_BUILD=1` to reuse already-built `botbox:test` images

## Environment Setup (kind)

1. Create a cluster:

```bash
kind create cluster --name botbox-at
```

2. Build images:

```bash
docker build -t botbox:test .
docker build --target iptables-init -t botbox-iptables-init:test .
```

3. Load images into kind:

```bash
kind load docker-image --name botbox-at botbox:test botbox-iptables-init:test
```

## Deploy the AT Pod

Apply the manifest (starts with the required secret missing on purpose):

```bash
kubectl apply -f tests/at/manifests/at-pod.yaml
kubectl -n botbox-at get pods -w
```

Open a shell in the client container:

```bash
kubectl -n botbox-at exec -it pod/botbox-at -c client -- sh
```

## Test Cases

### AT-001: Readiness is NOT ready while required secret is missing

From inside the client container:

```bash
curl -si http://127.0.0.1:9090/healthz
```

Expected:
- HTTP status: 503
- Body contains: `not ready`


### AT-002: Proxy fails closed when secret is missing

From inside the client container:

```bash
curl -si http://httpbin.org/headers
```

Expected:
- HTTP status: 500
- Body contains: `internal error: secret not available`


### AT-003: Add secret; readiness flips to ready WITHOUT restart (hot reload)

From your host (outside the pod), add the required secret key:

```bash
kubectl -n botbox-at create secret generic botbox-secrets \
  --from-literal=at-secret=at-secret-value-123 \
  --dry-run=client -o yaml | kubectl apply -f -
```

Wait ~10-15 seconds (watch debounce + periodic readiness check), then from inside the client container:

```bash
curl -si http://127.0.0.1:9090/healthz
```

Expected:
- HTTP status: 200
- Body contains: `ok`


### AT-004: Secret injection works end-to-end

From inside the client container:

```bash
curl -s http://httpbin.org/headers | grep -i "x-at-secret"
```

Expected:
- Output contains the injected header name and value (case may vary)
- Example match: `"X-At-Secret": "at-secret-value-123"`


### AT-005: Default-deny host policy (unknown host returns 403)

From inside the client container:

```bash
curl -si http://example.com/
```

Expected:
- HTTP status: 403
- Body contains: `host not allowed`


### AT-006: Port policy (non-443 denied by default)

Use explicit proxy mode to force BotBox to evaluate a non-443 port:

```bash
curl -si -x http://127.0.0.1:8080 http://httpbin.org:8443/headers -m 5
```

Expected:
- HTTP status: 403


### AT-007: Direct egress bypass is blocked (direct HTTPS)

From inside the client container (no proxy):

```bash
curl -sv https://httpbin.org/headers --connect-timeout 2 -m 5
```

Expected:
- Connection times out (egress filter drops direct TCP 443)


### AT-008: QUIC/UDP 443 bypass is blocked (optional)

If your `curl` supports HTTP/3, try:

```bash
curl --version
curl -sv --http3 https://cloudflare-quic.com/ --connect-timeout 2 -m 5
```

Expected:
- Connection times out (egress filter drops direct UDP 443)

If `curl` does not support `--http3`, mark this test as not applicable.


### AT-009: Metrics endpoint is reachable

From inside the client container:

```bash
curl -si http://127.0.0.1:9090/metrics | grep -E "^# HELP botbox_"
curl -si http://127.0.0.1:9090/does-not-exist
```

Expected:
- `/metrics` returns 200 and includes BotBox metrics
- unknown path returns 404 and body `not found`


### AT-010: Secret value is not logged

From your host:

```bash
kubectl -n botbox-at logs pod/botbox-at -c botbox | grep -n "at-secret-value-123" || true
```

Expected:
- No matches

## Cleanup

```bash
kubectl delete -f tests/at/manifests/at-pod.yaml
kind delete cluster --name botbox-at
```

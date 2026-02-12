# HTTPS interception example (Kubernetes)

This example deploys BotBox as a sidecar and enables `https_interception`, so in-pod clients can make normal `https://...` requests while BotBox enforces the allowlist and injects secrets.

## Build images (kind / local)

```bash
docker build -t botbox:test .
docker build --target iptables-init -t botbox-iptables-init:test .

# If you are using kind
kind load docker-image botbox:test botbox-iptables-init:test
```

## Deploy

```bash
kubectl apply -k examples/https_interception
kubectl -n botbox-https-interception rollout status deploy/botbox-https-interception-demo
```

## Try it

```bash
kubectl -n botbox-https-interception exec -it deploy/botbox-https-interception-demo -c client -- sh

# Allowed host (expect upstream reachability; often 401 with dummy key)
curl -sv https://api.openai.com/v1/models -o /dev/null

# Disallowed host (expect 403 from BotBox)
curl -sv https://example.com/ -o /dev/null
```

## Notes

- The pod generates an ephemeral CA keypair at startup (emptyDir). For production use, provide a stable CA via Kubernetes Secrets.
- `BOTBOX_ENABLE_IPV6` is set to `0` for compatibility with kind defaults. In dual-stack environments, set it to `1` and ensure `ip6tables` + ip6table_nat are available.

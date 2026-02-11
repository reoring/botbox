#!/usr/bin/env bash

set -euo pipefail

NAMESPACE="egress-test"
MANIFEST="tests/e2e/manifests/egress-test.yaml"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-}"

k() {
  if [[ -n "${KUBECTL_CONTEXT}" ]]; then
    kubectl --context "${KUBECTL_CONTEXT}" "$@"
  else
    kubectl "$@"
  fi
}

cleanup() {
  k delete namespace "${NAMESPACE}" --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

k apply -f "${MANIFEST}"
k -n "${NAMESPACE}" wait --for=jsonpath='{.status.phase}'=Succeeded pod/egress-test --timeout=180s

logs="$(k -n "${NAMESPACE}" logs egress-test -c curl-client)"
echo "${logs}"

if ! printf '%s\n' "${logs}" | grep -q -- "--- curl exit code: 0 ---"; then
  echo "E2E failed: non-MITM egress smoke test did not complete successfully"
  exit 1
fi

echo "Non-MITM E2E checks passed."

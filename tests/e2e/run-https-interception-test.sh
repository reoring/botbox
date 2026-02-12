#!/usr/bin/env bash

set -euo pipefail

NAMESPACE="https-interception-test"
MANIFEST="tests/e2e/manifests/https-interception-test.yaml"
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
k -n "${NAMESPACE}" wait --for=jsonpath='{.status.phase}'=Succeeded pod/https-interception-test --timeout=300s

logs="$(k -n "${NAMESPACE}" logs https-interception-test -c curl-client)"
echo "${logs}"

openai_code="$(printf '%s\n' "${logs}" | sed -n 's/^HTTPS_INTERCEPTION_OPENAI_CODE=//p' | tail -n1)"
deny_code="$(printf '%s\n' "${logs}" | sed -n 's/^HTTPS_INTERCEPTION_DENY_CODE=//p' | tail -n1)"
tcp_code="$(printf '%s\n' "${logs}" | sed -n 's/^HTTPS_INTERCEPTION_TCP443_CODE=//p' | tail -n1)"
udp_rc="$(printf '%s\n' "${logs}" | sed -n 's/^HTTPS_INTERCEPTION_UDP443_RC=//p' | tail -n1)"
http3_unsupported="$(printf '%s\n' "${logs}" | sed -n 's/^HTTPS_INTERCEPTION_HTTP3_UNSUPPORTED=//p' | tail -n1)"

if [[ -z "${openai_code}" || "${openai_code}" == "000" ]]; then
  echo "E2E failed: HTTPS_INTERCEPTION_OPENAI_CODE is missing or indicates timeout (${openai_code:-missing})"
  exit 1
fi

if [[ "${deny_code}" != "403" ]]; then
  echo "E2E failed: expected HTTPS_INTERCEPTION_DENY_CODE=403, got '${deny_code:-missing}'"
  exit 1
fi

if [[ "${tcp_code}" != "403" && "${tcp_code}" != "000" ]]; then
  echo "E2E failed: expected HTTPS_INTERCEPTION_TCP443_CODE to be 403 or 000, got '${tcp_code:-missing}'"
  exit 1
fi

if [[ -n "${udp_rc}" ]]; then
  if [[ "${udp_rc}" == "0" ]]; then
    echo "E2E failed: UDP/443 probe succeeded unexpectedly"
    exit 1
  fi
elif [[ "${http3_unsupported}" != "1" ]]; then
  echo "E2E failed: neither HTTPS_INTERCEPTION_UDP443_RC nor HTTPS_INTERCEPTION_HTTP3_UNSUPPORTED marker found"
  exit 1
fi

echo "HTTPS interception E2E checks passed."

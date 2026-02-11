#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER_NAME="${KIND_CLUSTER_NAME:-kind}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-kind-${CLUSTER_NAME}}"
CREATE_CLUSTER="${CREATE_KIND_CLUSTER:-0}"
SKIP_IMAGE_BUILD="${SKIP_IMAGE_BUILD:-0}"
RUN_EGRESS_TEST="${RUN_EGRESS_TEST:-1}"
RUN_HTTPS_INTERCEPTION_TEST="${RUN_HTTPS_INTERCEPTION_TEST:-1}"

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Required command not found: ${cmd}" >&2
    exit 1
  fi
}

kind_cluster_exists() {
  kind get clusters 2>/dev/null | grep -Fxq "${CLUSTER_NAME}"
}

kubectl_context_exists() {
  kubectl config get-contexts -o name | grep -Fxq "${KUBECTL_CONTEXT}"
}

build_botbox_image() {
  echo "[1/5] Building botbox:test from repository Dockerfile..."
  if docker build -t botbox:test "${ROOT_DIR}"; then
    return 0
  fi

  echo "Primary Dockerfile build failed; retrying with rust:1.93-bookworm fallback..."
  local tmp_dockerfile
  tmp_dockerfile="$(mktemp)"
  cat > "${tmp_dockerfile}" <<'EOF'
FROM rust:1.93-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./

RUN mkdir src && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs
RUN cargo build --release
RUN rm -rf src

COPY src/ src/
RUN touch src/main.rs src/lib.rs && cargo build --release

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/target/release/botbox /botbox
COPY config.yaml /etc/botbox/config.yaml

EXPOSE 8080 8443 9090
ENTRYPOINT ["/botbox"]
CMD ["--config", "/etc/botbox/config.yaml"]
EOF

  if ! docker build -f "${tmp_dockerfile}" -t botbox:test "${ROOT_DIR}"; then
    rm -f "${tmp_dockerfile}"
    return 1
  fi
  rm -f "${tmp_dockerfile}"
}

build_iptables_image() {
  echo "[2/5] Building botbox-iptables-init:test..."
  docker build --target iptables-init -t botbox-iptables-init:test "${ROOT_DIR}"
}

run_e2e_tests() {
  if [[ "${RUN_EGRESS_TEST}" == "1" ]]; then
    echo "[4/5] Running HTTP-mode E2E test (no interception)..."
    KUBECTL_CONTEXT="${KUBECTL_CONTEXT}" bash "${ROOT_DIR}/tests/e2e/run-egress-test.sh"
  fi

  if [[ "${RUN_HTTPS_INTERCEPTION_TEST}" == "1" ]]; then
    echo "[5/5] Running HTTPS interception E2E test..."
    KUBECTL_CONTEXT="${KUBECTL_CONTEXT}" bash "${ROOT_DIR}/tests/e2e/run-https-interception-test.sh"
  fi
}

require_cmd docker
require_cmd kind
require_cmd kubectl

if [[ "${RUN_EGRESS_TEST}" != "1" && "${RUN_HTTPS_INTERCEPTION_TEST}" != "1" ]]; then
  echo "Nothing to run: both RUN_EGRESS_TEST and RUN_HTTPS_INTERCEPTION_TEST are disabled." >&2
  exit 1
fi

if ! kind_cluster_exists; then
  if [[ "${CREATE_CLUSTER}" == "1" ]]; then
    echo "kind cluster '${CLUSTER_NAME}' not found; creating it..."
    kind create cluster --name "${CLUSTER_NAME}"
  else
    echo "kind cluster '${CLUSTER_NAME}' not found." >&2
    echo "Create it first or rerun with CREATE_KIND_CLUSTER=1." >&2
    exit 1
  fi
fi

if ! kubectl_context_exists; then
  echo "kubectl context '${KUBECTL_CONTEXT}' not found." >&2
  echo "Set KUBECTL_CONTEXT to a valid context for cluster '${CLUSTER_NAME}'." >&2
  exit 1
fi

if [[ "${SKIP_IMAGE_BUILD}" != "1" ]]; then
  build_botbox_image
  build_iptables_image
else
  echo "[1/5] SKIP_IMAGE_BUILD=1 -> skipping image build."
fi

echo "[3/5] Loading images into kind cluster '${CLUSTER_NAME}'..."
kind load docker-image --name "${CLUSTER_NAME}" botbox:test botbox-iptables-init:test

run_e2e_tests

echo "All requested acceptance tests passed on context '${KUBECTL_CONTEXT}'."

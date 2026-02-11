#!/bin/sh

set -eu

# BotBox iptables init script.
# Applies transparent redirect + egress-blocking rules inside the Pod network namespace.
#
# Requirements:
# - run as root
# - CAP_NET_ADMIN
#
# IPv6 support:
# BOTBOX_ENABLE_IPV6 must be explicitly set to 1 or 0.
# When 1, every iptables rule is mirrored via ip6tables. If ip6tables is
# unavailable the script exits with an error (fail-fast).
# When 0, only IPv4 rules are applied. In dual-stack environments IPv6
# traffic may bypass the proxy — secure IPv6 separately (e.g. NetworkPolicy,
# sysctl net.ipv6.conf.all.disable_ipv6=1).

PROXY_UID="${BOTBOX_UID:-1337}"
PROXY_PORT="${BOTBOX_PROXY_PORT:-8080}"
REDIRECT_FROM_PORT="${BOTBOX_REDIRECT_FROM_PORT:-80}"
ENABLE_HTTPS_INTERCEPTION="${BOTBOX_ENABLE_HTTPS_INTERCEPTION:-0}"
HTTPS_INTERCEPTION_PORT="${BOTBOX_HTTPS_INTERCEPTION_PORT:-8443}"

# BOTBOX_ENABLE_IPV6 is required — no default.
if [ -z "${BOTBOX_ENABLE_IPV6+x}" ]; then
  echo "ERROR: BOTBOX_ENABLE_IPV6 is not set." >&2
  echo "  Set BOTBOX_ENABLE_IPV6=1 to mirror rules via ip6tables (recommended for dual-stack)." >&2
  echo "  Set BOTBOX_ENABLE_IPV6=0 for IPv4-only (ensure IPv6 is disabled or blocked separately)." >&2
  exit 1
fi
ENABLE_IPV6="${BOTBOX_ENABLE_IPV6}"

if [ "$ENABLE_IPV6" != "0" ] && [ "$ENABLE_IPV6" != "1" ]; then
  echo "ERROR: BOTBOX_ENABLE_IPV6 must be 0 or 1 (got '${ENABLE_IPV6}')." >&2
  exit 1
fi

NAT_CHAIN="${BOTBOX_NAT_CHAIN:-EGRESS_REDIRECT}"
FILTER_CHAIN="${BOTBOX_FILTER_CHAIN:-EGRESS_FILTER}"

WAIT_SECONDS="${BOTBOX_IPTABLES_WAIT_SECONDS:-5}"

# Helper: run iptables, and optionally ip6tables, with the same arguments.
# Used for rules that are identical across IPv4 and IPv6 (e.g. -o lo, --uid-owner).
run_ipt() {
  iptables -w "${WAIT_SECONDS}" "$@"
  if [ "$ENABLE_IPV6" = "1" ]; then
    ip6tables -w "${WAIT_SECONDS}" "$@"
  fi
}

run_ipt_nat() {
  iptables -w "${WAIT_SECONDS}" -t nat "$@"
  if [ "$ENABLE_IPV6" = "1" ]; then
    ip6tables -w "${WAIT_SECONDS}" -t nat "$@"
  fi
}

# IPv6: verify ip6tables is available when enabled; warn when disabled.
if [ "$ENABLE_IPV6" = "1" ]; then
  if ! command -v ip6tables >/dev/null 2>&1; then
    echo "ERROR: BOTBOX_ENABLE_IPV6=1 but ip6tables is not available." >&2
    echo "  Install ip6tables or set BOTBOX_ENABLE_IPV6=0." >&2
    exit 1
  fi
  if ! ip6tables -w "${WAIT_SECONDS}" -t nat -L -n >/dev/null 2>&1; then
    echo "ERROR: BOTBOX_ENABLE_IPV6=1 but ip6tables NAT table is not available." >&2
    echo "  The kernel may not support ip6table_nat. Set BOTBOX_ENABLE_IPV6=0 or load the module." >&2
    exit 1
  fi
else
  echo "[WARN] BOTBOX_ENABLE_IPV6=0: IPv6 traffic control is DISABLED." >&2
  echo "  In dual-stack environments, IPv6 traffic may bypass the proxy." >&2
  echo "  Ensure IPv6 is disabled (sysctl) or blocked via NetworkPolicy." >&2
fi

# Guard: HTTPS interception + REDIRECT_FROM_PORT=443 conflict.
# When both are set, the HTTP redirect rule matches port 443 first and sends
# traffic to the plain-HTTP proxy, making the HTTPS interception REDIRECT rule unreachable.
if [ "${ENABLE_HTTPS_INTERCEPTION}" = "1" ] && [ "${REDIRECT_FROM_PORT}" = "443" ]; then
  echo "ERROR: BOTBOX_ENABLE_HTTPS_INTERCEPTION=1 and BOTBOX_REDIRECT_FROM_PORT=443 conflict." >&2
  echo "  Port 443 traffic would be redirected to the HTTP proxy (port ${PROXY_PORT})" >&2
  echo "  instead of the HTTPS interception listener (port ${HTTPS_INTERCEPTION_PORT})." >&2
  echo "  Use BOTBOX_REDIRECT_FROM_PORT=80 (default) with BOTBOX_ENABLE_HTTPS_INTERCEPTION=1." >&2
  exit 1
fi

echo "Installing BotBox iptables rules..."
echo "  proxy_uid=${PROXY_UID} proxy_port=${PROXY_PORT} redirect_from_port=${REDIRECT_FROM_PORT} ipv6=${ENABLE_IPV6}"

# --- NAT rules: redirect app HTTP to BotBox ---

# Create chain (ignore if it already exists), then flush for idempotency.
run_ipt_nat -N "${NAT_CHAIN}" 2>/dev/null || true
run_ipt_nat -F "${NAT_CHAIN}"

# Ensure OUTPUT jump exists exactly once and is first.
# Remove all existing jumps before re-inserting.
while iptables -w "${WAIT_SECONDS}" -t nat -D OUTPUT -p tcp -j "${NAT_CHAIN}" 2>/dev/null; do :; done
if [ "$ENABLE_IPV6" = "1" ]; then
  while ip6tables -w "${WAIT_SECONDS}" -t nat -D OUTPUT -p tcp -j "${NAT_CHAIN}" 2>/dev/null; do :; done
fi

# -o lo: loopback interface is the same for IPv4 and IPv6, safe to use run_ipt_nat.
run_ipt_nat -A "${NAT_CHAIN}" -o lo -j RETURN
run_ipt_nat -A "${NAT_CHAIN}" -m owner --uid-owner "${PROXY_UID}" -j RETURN
run_ipt_nat -A "${NAT_CHAIN}" -p tcp --dport "${REDIRECT_FROM_PORT}" -j REDIRECT --to-port "${PROXY_PORT}"

# HTTPS interception: redirect outbound HTTPS (port 443) to interception listener
if [ "${ENABLE_HTTPS_INTERCEPTION}" = "1" ]; then
  echo "  https_interception_port=${HTTPS_INTERCEPTION_PORT} (HTTPS interception enabled)"
  run_ipt_nat -A "${NAT_CHAIN}" -p tcp --dport 443 -j REDIRECT --to-port "${HTTPS_INTERCEPTION_PORT}"
fi

run_ipt_nat -I OUTPUT 1 -p tcp -j "${NAT_CHAIN}"

# --- Filter rules: block direct outbound from non-BotBox processes ---

run_ipt -N "${FILTER_CHAIN}" 2>/dev/null || true
run_ipt -F "${FILTER_CHAIN}"

while iptables -w "${WAIT_SECONDS}" -D OUTPUT -j "${FILTER_CHAIN}" 2>/dev/null; do :; done
if [ "$ENABLE_IPV6" = "1" ]; then
  while ip6tables -w "${WAIT_SECONDS}" -D OUTPUT -j "${FILTER_CHAIN}" 2>/dev/null; do :; done
fi

run_ipt -A "${FILTER_CHAIN}" -o lo -j RETURN
run_ipt -A "${FILTER_CHAIN}" -m owner --uid-owner "${PROXY_UID}" -j RETURN
# On some kernels (>=6.x), REDIRECT changes the destination to loopback but
# does not update the output interface to lo before the filter chain runs.
# Allow packets whose destination was rewritten to loopback by NAT REDIRECT.
# IPv4 loopback is 127.0.0.0/8; IPv6 loopback is ::1/128. These must be separate calls.
iptables -w "${WAIT_SECONDS}" -A "${FILTER_CHAIN}" -d 127.0.0.0/8 -j RETURN
if [ "$ENABLE_IPV6" = "1" ]; then
  ip6tables -w "${WAIT_SECONDS}" -A "${FILTER_CHAIN}" -d ::1/128 -j RETURN
fi
run_ipt -A "${FILTER_CHAIN}" -p udp --dport 53 -j RETURN
run_ipt -A "${FILTER_CHAIN}" -p tcp --dport 53 -j RETURN
run_ipt -A "${FILTER_CHAIN}" -p tcp -j DROP
run_ipt -A "${FILTER_CHAIN}" -p udp -j DROP

run_ipt -I OUTPUT 1 -j "${FILTER_CHAIN}"

echo "iptables rules installed:"
iptables -w "${WAIT_SECONDS}" -t nat -L "${NAT_CHAIN}" -v -n
iptables -w "${WAIT_SECONDS}" -L "${FILTER_CHAIN}" -v -n
if [ "$ENABLE_IPV6" = "1" ]; then
  echo "ip6tables rules installed:"
  ip6tables -w "${WAIT_SECONDS}" -t nat -L "${NAT_CHAIN}" -v -n
  ip6tables -w "${WAIT_SECONDS}" -L "${FILTER_CHAIN}" -v -n
fi

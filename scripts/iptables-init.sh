#!/bin/sh

set -eu

# BotBox iptables init script.
# Applies transparent redirect + egress-blocking rules inside the Pod network namespace.
#
# Requirements:
# - run as root
# - CAP_NET_ADMIN

PROXY_UID="${BOTBOX_UID:-1337}"
PROXY_PORT="${BOTBOX_PROXY_PORT:-8080}"
REDIRECT_FROM_PORT="${BOTBOX_REDIRECT_FROM_PORT:-80}"

NAT_CHAIN="${BOTBOX_NAT_CHAIN:-EGRESS_REDIRECT}"
FILTER_CHAIN="${BOTBOX_FILTER_CHAIN:-EGRESS_FILTER}"

WAIT_SECONDS="${BOTBOX_IPTABLES_WAIT_SECONDS:-5}"

ipt() {
  iptables -w "${WAIT_SECONDS}" "$@"
}

ipt_nat() {
  iptables -w "${WAIT_SECONDS}" -t nat "$@"
}

echo "Installing BotBox iptables rules..."
echo "  proxy_uid=${PROXY_UID} proxy_port=${PROXY_PORT} redirect_from_port=${REDIRECT_FROM_PORT}"

# --- NAT rules: redirect app HTTP to BotBox ---

# Create chain (ignore if it already exists), then flush for idempotency.
ipt_nat -N "${NAT_CHAIN}" 2>/dev/null || true
ipt_nat -F "${NAT_CHAIN}"

# Ensure OUTPUT jump exists exactly once and is first.
while ipt_nat -D OUTPUT -p tcp -j "${NAT_CHAIN}" 2>/dev/null; do :; done

ipt_nat -A "${NAT_CHAIN}" -o lo -j RETURN
ipt_nat -A "${NAT_CHAIN}" -m owner --uid-owner "${PROXY_UID}" -j RETURN
ipt_nat -A "${NAT_CHAIN}" -p tcp --dport "${REDIRECT_FROM_PORT}" -j REDIRECT --to-port "${PROXY_PORT}"

ipt_nat -I OUTPUT 1 -p tcp -j "${NAT_CHAIN}"

# --- Filter rules: block direct outbound from non-BotBox processes ---

ipt -N "${FILTER_CHAIN}" 2>/dev/null || true
ipt -F "${FILTER_CHAIN}"

while ipt -D OUTPUT -j "${FILTER_CHAIN}" 2>/dev/null; do :; done

ipt -A "${FILTER_CHAIN}" -o lo -j RETURN
ipt -A "${FILTER_CHAIN}" -m owner --uid-owner "${PROXY_UID}" -j RETURN
# On some kernels (≥6.x), REDIRECT changes the destination to 127.0.0.1 but
# does not update the output interface to lo before the filter chain runs.
# Allow packets whose destination was rewritten to loopback by NAT REDIRECT.
ipt -A "${FILTER_CHAIN}" -d 127.0.0.0/8 -j RETURN
ipt -A "${FILTER_CHAIN}" -p udp --dport 53 -j RETURN
ipt -A "${FILTER_CHAIN}" -p tcp --dport 53 -j RETURN
ipt -A "${FILTER_CHAIN}" -p tcp -j DROP
ipt -A "${FILTER_CHAIN}" -p udp -j DROP

ipt -I OUTPUT 1 -j "${FILTER_CHAIN}"

echo "iptables rules installed:"
ipt_nat -L "${NAT_CHAIN}" -v -n
ipt -L "${FILTER_CHAIN}" -v -n

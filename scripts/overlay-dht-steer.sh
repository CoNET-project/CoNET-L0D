#!/bin/bash
# Rewrite dest <peer public>:4300 UDP and :4200 TCP to the overlay vIP so
# discv5 that follows a public ENR, then the libp2p dial that ENR advertises,
# still ride TUN / L0. Lab: L0_ONLY .45 → .98 (defaults). Also .98 → .82
# (PEER_PUBLIC_IP=216.225.202.82 PEER_OVERLAY_VIP=100.64.0.7). Does not
# rewrite QUIC :13000 — that stays public until beacon --disable-quic.
# Does NOT restart geth/beacon/validator. Does NOT touch CONET_L0D.
#
# Packet path (locally generated):
#   mangle OUTPUT  — no MARK on the public dest (that raced routing before DNAT)
#   nat OUTPUT     — DNAT public:4300/4200 → overlay VIP
#   mangle POSTROUTING — MARK dest VIP so table 6300 keeps the packet on TUN
#   table 6300     — overlay CIDR + hub public /32 via TUN (no ens6 fallback)
# apply() also drops stale conntrack for the hub :4300/:4200 5-tuples so
# discv5 is NEW again and hits DNAT.
#
# Reconnect (lab): if beacon `connected` drops but geth overlay stays ESTAB,
# re-run `apply` first. Do **not** restart geth or beacon to clear UNREPLIED
# UDP / ghost TCP to the hub public IP. restart-beacon is only for in-process
# Prysm dial backoff after that flush.
set -euo pipefail

TUN_IFACE="${TUN_IFACE:-conet-l0}"
PEER_PUBLIC_IP="${PEER_PUBLIC_IP:-198.251.77.98}"
PEER_OVERLAY_VIP="${PEER_OVERLAY_VIP:-100.64.0.6}"
BEACON_P2P_TCP_PORT="${BEACON_P2P_TCP_PORT:-4200}"
BEACON_P2P_UDP_PORT="${BEACON_P2P_UDP_PORT:-4300}"
STEER_CHAIN="${STEER_CHAIN:-CONET_L0D_DHT_STEER}"
STEER_MANGLE="${STEER_MANGLE:-CONET_L0D_DHT_STEER_M}"
STEER_MANGLE_POST="${STEER_MANGLE_POST:-CONET_L0D_DHT_STEER_MP}"
STEER_MARK="${STEER_MARK:-0x6c30}"
STEER_TABLE="${STEER_TABLE:-6300}"
OVERLAY_CIDR="${OVERLAY_CIDR:-100.64.0.0/10}"
ISOLATE_CHAIN="${ISOLATE_CHAIN:-CONET_L0D_P2P_ISOLATE}"
ISOLATE_OUT_CHAIN="${ISOLATE_OUT_CHAIN:-CONET_L0D_P2P_ISOLATE_OUT}"

die() { echo "ERROR: $*" >&2; exit 1; }

[[ "$STEER_CHAIN" != "CONET_L0D" ]] || die "refuse to hijack CONET_L0D"
[[ "$STEER_MANGLE" != "CONET_L0D" ]] || die "refuse to hijack CONET_L0D"
[[ "$STEER_MANGLE_POST" != "CONET_L0D" ]] || die "refuse to hijack CONET_L0D"
ip -4 addr show dev "$TUN_IFACE" >/dev/null 2>&1 || die "TUN $TUN_IFACE is down"
# VIP is often /32 on the TUN; the usable route is OVERLAY_CIDR, not a
# host route whose dest string equals PEER_OVERLAY_VIP.
ip route show | grep -q "${OVERLAY_CIDR} dev ${TUN_IFACE}" \
	|| ip route get "$PEER_OVERLAY_VIP" 2>/dev/null | grep -q "dev ${TUN_IFACE}" \
	|| die "overlay route via $TUN_IFACE is missing"

ensure_jump() {
	local table="$1"
	local hook="$2"
	local chain="$3"
	if ! sudo -n iptables -t "$table" -C "$hook" -j "$chain" 2>/dev/null; then
		sudo -n iptables -t "$table" -I "$hook" 1 -j "$chain"
	fi
}

ensure_isolate_overlay_return() {
	local chain="$1"
	sudo -n iptables -nL "$chain" >/dev/null 2>&1 || return 0
	if sudo -n iptables -C "$chain" -d "$OVERLAY_CIDR" -j RETURN 2>/dev/null; then
		return 0
	fi
	sudo -n iptables -I "$chain" 3 -d "$OVERLAY_CIDR" -j RETURN
	echo "isolate $chain: RETURN dest $OVERLAY_CIDR"
}

flush_hub_conntrack() {
	# Stale ESTABLISHED UDP :4300 without NAT skips DNAT forever.
	local ct
	ct="$(command -v conntrack 2>/dev/null || true)"
	[[ -n "$ct" ]] || ct="/usr/sbin/conntrack"
	if [[ ! -x "$ct" ]]; then
		echo "WARN: conntrack tool missing; discv5 may stay on the old 5-tuple" >&2
		return 0
	fi
	sudo -n "$ct" -D -p udp -d "$PEER_PUBLIC_IP" --dport "$BEACON_P2P_UDP_PORT" >/dev/null 2>&1 || true
	sudo -n "$ct" -D -p tcp -d "$PEER_PUBLIC_IP" --dport "$BEACON_P2P_TCP_PORT" >/dev/null 2>&1 || true
	sudo -n "$ct" -D -p udp -d "$PEER_OVERLAY_VIP" --dport "$BEACON_P2P_UDP_PORT" >/dev/null 2>&1 || true
	sudo -n "$ct" -D -p tcp -d "$PEER_OVERLAY_VIP" --dport "$BEACON_P2P_TCP_PORT" >/dev/null 2>&1 || true
	echo "conntrack flushed for ${PEER_PUBLIC_IP}/$PEER_OVERLAY_VIP :${BEACON_P2P_UDP_PORT}/:${BEACON_P2P_TCP_PORT}"
}

apply() {
	sudo -n iptables -t nat -N "$STEER_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -F "$STEER_CHAIN"
	sudo -n iptables -t nat -A "$STEER_CHAIN" -p udp -d "$PEER_PUBLIC_IP" \
		--dport "$BEACON_P2P_UDP_PORT" -j DNAT \
		--to-destination "${PEER_OVERLAY_VIP}:${BEACON_P2P_UDP_PORT}"
	sudo -n iptables -t nat -A "$STEER_CHAIN" -p tcp -d "$PEER_PUBLIC_IP" \
		--dport "$BEACON_P2P_TCP_PORT" -j DNAT \
		--to-destination "${PEER_OVERLAY_VIP}:${BEACON_P2P_TCP_PORT}"
	ensure_jump nat OUTPUT "$STEER_CHAIN"
	ensure_jump nat PREROUTING "$STEER_CHAIN"

	# Do not MARK the public dest in mangle OUTPUT: routing runs before
	# DNAT, and table 6300 used to have no route to the hub public IP.
	sudo -n iptables -t mangle -N "$STEER_MANGLE" 2>/dev/null || true
	sudo -n iptables -t mangle -F "$STEER_MANGLE"
	sudo -n iptables -t mangle -D OUTPUT -j "$STEER_MANGLE" 2>/dev/null || true

	# MARK after DNAT: dest is already the overlay VIP.
	sudo -n iptables -t mangle -N "$STEER_MANGLE_POST" 2>/dev/null || true
	sudo -n iptables -t mangle -F "$STEER_MANGLE_POST"
	sudo -n iptables -t mangle -A "$STEER_MANGLE_POST" -p udp -d "$PEER_OVERLAY_VIP" \
		--dport "$BEACON_P2P_UDP_PORT" -j MARK --set-mark "$STEER_MARK"
	sudo -n iptables -t mangle -A "$STEER_MANGLE_POST" -p tcp -d "$PEER_OVERLAY_VIP" \
		--dport "$BEACON_P2P_TCP_PORT" -j MARK --set-mark "$STEER_MARK"
	ensure_jump mangle POSTROUTING "$STEER_MANGLE_POST"

	sudo -n ip rule del fwmark "$STEER_MARK" table "$STEER_TABLE" 2>/dev/null || true
	sudo -n ip rule add fwmark "$STEER_MARK" table "$STEER_TABLE"
	sudo -n ip route replace "$OVERLAY_CIDR" dev "$TUN_IFACE" table "$STEER_TABLE"
	sudo -n ip route replace "${PEER_PUBLIC_IP}/32" dev "$TUN_IFACE" table "$STEER_TABLE"

	ensure_isolate_overlay_return "$ISOLATE_CHAIN"
	ensure_isolate_overlay_return "$ISOLATE_OUT_CHAIN"
	flush_hub_conntrack

	echo "overlay DHT steer ($STEER_CHAIN): ${PEER_PUBLIC_IP}:udp:${BEACON_P2P_UDP_PORT}/tcp:${BEACON_P2P_TCP_PORT} -> ${PEER_OVERLAY_VIP}"
	echo "overlay DHT mark ($STEER_MANGLE_POST): POSTROUTING dest ${PEER_OVERLAY_VIP} fwmark $STEER_MARK table $STEER_TABLE (+ ${PEER_PUBLIC_IP}/32)"
}

remove() {
	sudo -n iptables -t nat -D OUTPUT -j "$STEER_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -D PREROUTING -j "$STEER_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -F "$STEER_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -X "$STEER_CHAIN" 2>/dev/null || true
	sudo -n iptables -t mangle -D OUTPUT -j "$STEER_MANGLE" 2>/dev/null || true
	sudo -n iptables -t mangle -F "$STEER_MANGLE" 2>/dev/null || true
	sudo -n iptables -t mangle -X "$STEER_MANGLE" 2>/dev/null || true
	sudo -n iptables -t mangle -D POSTROUTING -j "$STEER_MANGLE_POST" 2>/dev/null || true
	sudo -n iptables -t mangle -F "$STEER_MANGLE_POST" 2>/dev/null || true
	sudo -n iptables -t mangle -X "$STEER_MANGLE_POST" 2>/dev/null || true
	sudo -n ip rule del fwmark "$STEER_MARK" table "$STEER_TABLE" 2>/dev/null || true
	sudo -n ip route flush table "$STEER_TABLE" 2>/dev/null || true
	echo "overlay DHT steer off"
}

show() {
	sudo -n iptables -t nat -S "$STEER_CHAIN" 2>/dev/null || echo "$STEER_CHAIN: absent"
	sudo -n iptables -t mangle -S "$STEER_MANGLE" 2>/dev/null || echo "$STEER_MANGLE: absent"
	sudo -n iptables -t mangle -S "$STEER_MANGLE_POST" 2>/dev/null || echo "$STEER_MANGLE_POST: absent"
	echo "--- $STEER_CHAIN counters ---"
	sudo -n iptables -t nat -L "$STEER_CHAIN" -n -v 2>/dev/null || true
	echo "--- $STEER_MANGLE_POST counters ---"
	sudo -n iptables -t mangle -L "$STEER_MANGLE_POST" -n -v 2>/dev/null || true
	ip rule show | grep -E "$STEER_MARK|$STEER_TABLE" || true
	ip route show table "$STEER_TABLE" || true
	sudo -n iptables -t nat -S OUTPUT
}

case "${1:-apply}" in
apply) apply ;;
remove) remove ;;
status) show ;;
*)
	echo "Usage: $0 {apply|remove|status}"
	exit 1
	;;
esac

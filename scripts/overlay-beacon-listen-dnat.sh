#!/bin/bash
# Lab-only: steer overlay TCP 4200 to the public-IP listen that Prysm already owns.
# Does NOT restart geth/beacon/validator. Does NOT touch CONET_L0D.
# Needed on .98 while that host keeps --p2p-host-ip=<public> (binds public:4200 only).
set -euo pipefail

TUN_IFACE="${TUN_IFACE:-conet-l0}"
PUBLIC_IP="${PUBLIC_IP:-198.251.77.98}"
OVERLAY_VIP="${OVERLAY_VIP:-100.64.0.6}"
BEACON_P2P_TCP_PORT="${BEACON_P2P_TCP_PORT:-4200}"
DNAT_CHAIN="${DNAT_CHAIN:-CONET_L0D_BEACON_REDIR}"
SNAT_CHAIN="${SNAT_CHAIN:-CONET_L0D_BEACON_SNAT}"

die() { echo "ERROR: $*" >&2; exit 1; }

[[ "$DNAT_CHAIN" != "CONET_L0D" && "$SNAT_CHAIN" != "CONET_L0D" ]] \
	|| die "refuse to hijack CONET_L0D"
ip -4 addr show dev "$TUN_IFACE" >/dev/null 2>&1 || die "TUN $TUN_IFACE is down"
ss -lnt | grep -q "${PUBLIC_IP}:${BEACON_P2P_TCP_PORT}" \
	|| die "beacon is not listening on ${PUBLIC_IP}:${BEACON_P2P_TCP_PORT}"

ensure_jump() {
	local hook="$1"
	local chain="$2"
	if ! sudo -n iptables -t nat -C "$hook" -j "$chain" 2>/dev/null; then
		sudo -n iptables -t nat -I "$hook" 1 -j "$chain"
	fi
}

apply() {
	sudo -n iptables -t nat -N "$DNAT_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -F "$DNAT_CHAIN"
	sudo -n iptables -t nat -A "$DNAT_CHAIN" -i "$TUN_IFACE" -p tcp \
		--dport "$BEACON_P2P_TCP_PORT" -j DNAT --to-destination "${PUBLIC_IP}:${BEACON_P2P_TCP_PORT}"
	# Local self-check / hairpin to the advertised vIP does not hit PREROUTING.
	sudo -n iptables -t nat -A "$DNAT_CHAIN" -d "$OVERLAY_VIP" -p tcp \
		--dport "$BEACON_P2P_TCP_PORT" -j DNAT --to-destination "${PUBLIC_IP}:${BEACON_P2P_TCP_PORT}"
	ensure_jump PREROUTING "$DNAT_CHAIN"
	ensure_jump OUTPUT "$DNAT_CHAIN"

	# Replies are generated from PUBLIC_IP:4200. Without SNAT the client
	# socket (connected to OVERLAY_VIP:4200) drops them. SNAT cannot live
	# in the PREROUTING/DNAT chain.
	sudo -n iptables -t nat -N "$SNAT_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -F "$SNAT_CHAIN"
	sudo -n iptables -t nat -A "$SNAT_CHAIN" -o "$TUN_IFACE" -p tcp \
		--sport "$BEACON_P2P_TCP_PORT" -j SNAT --to-source "$OVERLAY_VIP"
	ensure_jump POSTROUTING "$SNAT_CHAIN"

	echo "overlay beacon DNAT ($DNAT_CHAIN): $TUN_IFACE:$BEACON_P2P_TCP_PORT -> ${PUBLIC_IP}:${BEACON_P2P_TCP_PORT}"
	echo "overlay beacon SNAT ($SNAT_CHAIN): ${PUBLIC_IP}:${BEACON_P2P_TCP_PORT} -> $OVERLAY_VIP out $TUN_IFACE"
}

remove() {
	sudo -n iptables -t nat -D PREROUTING -j "$DNAT_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -D OUTPUT -j "$DNAT_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -D POSTROUTING -j "$SNAT_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -D POSTROUTING -j "$DNAT_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -F "$DNAT_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -X "$DNAT_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -F "$SNAT_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -X "$SNAT_CHAIN" 2>/dev/null || true
	echo "overlay beacon DNAT/SNAT off"
}

show() {
	sudo -n iptables -t nat -S "$DNAT_CHAIN" 2>/dev/null || echo "$DNAT_CHAIN: absent"
	sudo -n iptables -t nat -S "$SNAT_CHAIN" 2>/dev/null || echo "$SNAT_CHAIN: absent"
	sudo -n iptables -t nat -S PREROUTING
	sudo -n iptables -t nat -S POSTROUTING
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

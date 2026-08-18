#!/bin/bash
# Lab-only: map overlay-VIP tcp/udp onto the public-IP listen Prysm owns.
# Does NOT restart geth/beacon/validator. Does NOT touch CONET_L0D.
#
# Needed on a public-advertise peer (.98) and on L0_ONLY .45: --p2p-host-ip
# is advertise-only; Prysm still bind()s the host public IP. Overlay dest
# 100.64.0.x:4200 would otherwise miss that socket.
#
# discv5 / libp2p client sockets use ephemeral source ports. Port-only
# SNAT/DNAT (:4200/:4300) leaves replies on the VIP with no socket →
# ICMP port unreachable and the TCP handshake dies. Rewrite every TUN
# tcp/udp to the VIP except overlay geth :8400 (already ESTAB on the VIP).
# Crate already carries complete IPv4. This is operator NAT, not a new SI command.
#
# 2026-08-18 lab: Prysm TCP listens on the public IP only. DNAT from TUN to
# that local public IP needs accept_local / route_localnet on the TUN, or
# the SYN is counted in NAT and never reaches the socket (no SYN-ACK on TUN).
# Replies must leave TUN with overlay-VIP source so the L0_ONLY peer's
# public-ENR DNAT conntrack matches. Do not SNAT overlay UDP to the public
# IP (that breaks the L0_ONLY last-wins /32 handshake).
set -euo pipefail

TUN_IFACE="${TUN_IFACE:-conet-l0}"
BEACON_P2P_TCP_PORT="${BEACON_P2P_TCP_PORT:-4200}"
BEACON_P2P_UDP_PORT="${BEACON_P2P_UDP_PORT:-4300}"
GETH_P2P_PORT="${GETH_P2P_PORT:-8400}"
DNAT_CHAIN="${DNAT_CHAIN:-CONET_L0D_BEACON_REDIR}"
SNAT_CHAIN="${SNAT_CHAIN:-CONET_L0D_BEACON_SNAT}"

if [[ -z "${OVERLAY_VIP:-}" ]]; then
	OVERLAY_VIP="$(ip -4 -o addr show dev "$TUN_IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)"
fi
if [[ -z "${PUBLIC_IP:-}" ]]; then
	PUBLIC_IP="$(ss -lnt | awk -v p=":${BEACON_P2P_TCP_PORT}" '$4 ~ p"$" {split($4,a,":"); if (a[1] != "0.0.0.0" && a[1] != "*") print a[1]}' | head -n1 || true)"
fi
PUBLIC_IP="${PUBLIC_IP:-}"
OVERLAY_VIP="${OVERLAY_VIP:-}"

die() { echo "ERROR: $*" >&2; exit 1; }

beacon_tcp_listening() {
	ss -lnt | grep -Eq "(${PUBLIC_IP}|0.0.0.0|\\*|\\[::\\]):${BEACON_P2P_TCP_PORT}\\b"
}

beacon_udp_listening() {
	ss -lun | grep -Eq "(${PUBLIC_IP}|0.0.0.0|\\*|\\[::\\]):${BEACON_P2P_UDP_PORT}\\b"
}

[[ "$DNAT_CHAIN" != "CONET_L0D" && "$SNAT_CHAIN" != "CONET_L0D" ]] \
	|| die "refuse to hijack CONET_L0D"
ip -4 addr show dev "$TUN_IFACE" >/dev/null 2>&1 || die "TUN $TUN_IFACE is down"
[[ -n "$OVERLAY_VIP" ]] || die "set OVERLAY_VIP or put an IPv4 on $TUN_IFACE"
[[ -n "$PUBLIC_IP" ]] || die "set PUBLIC_IP or have beacon listen on a concrete IPv4:${BEACON_P2P_TCP_PORT}"
beacon_tcp_listening \
	|| die "beacon is not listening TCP :${BEACON_P2P_TCP_PORT}"
if ! beacon_udp_listening; then
	echo "WARN beacon is not listening UDP :${BEACON_P2P_UDP_PORT} yet (typical with --no-discovery); still installing UDP DNAT"
fi

ensure_jump() {
	local hook="$1"
	local chain="$2"
	if ! sudo -n iptables -t nat -C "$hook" -j "$chain" 2>/dev/null; then
		sudo -n iptables -t nat -I "$hook" 1 -j "$chain"
	fi
}

enable_tun_local_dnat() {
	# DNAT TUN dest VIP → locally bound PUBLIC_IP. Without accept_local,
	# PREROUTING counts the SYN and INPUT never delivers it.
	sudo -n sysctl -w "net.ipv4.conf.${TUN_IFACE}.accept_local=1" >/dev/null
	sudo -n sysctl -w "net.ipv4.conf.${TUN_IFACE}.route_localnet=1" >/dev/null
	sudo -n sysctl -w "net.ipv4.conf.${TUN_IFACE}.rp_filter=0" >/dev/null
	sudo -n sysctl -w net.ipv4.conf.all.accept_local=1 >/dev/null
	sudo -n sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null
	sudo -n sysctl -w net.ipv4.ip_forward=1 >/dev/null
	echo "sysctl TUN ${TUN_IFACE}: accept_local=1 route_localnet=1 rp_filter=0"
}

flush_overlay_beacon_conntrack() {
	local ct peer_vip=""
	ct="$(command -v conntrack 2>/dev/null || true)"
	[[ -n "$ct" ]] || ct="/usr/sbin/conntrack"
	if [[ ! -x "$ct" ]]; then
		echo "WARN: conntrack tool missing; overlay :${BEACON_P2P_TCP_PORT}/:${BEACON_P2P_UDP_PORT} may stay on an old 5-tuple" >&2
		return 0
	fi
	if [[ -n "${PEER_OVERLAY_VIP:-}" ]]; then
		peer_vip="$PEER_OVERLAY_VIP"
	elif [[ "$OVERLAY_VIP" == "100.64.0.6" ]]; then
		peer_vip="100.64.0.5"
	elif [[ "$OVERLAY_VIP" == "100.64.0.5" ]]; then
		peer_vip="100.64.0.6"
	fi
	if [[ -n "$peer_vip" ]]; then
		sudo -n "$ct" -D -p tcp -s "$peer_vip" --dport "$BEACON_P2P_TCP_PORT" >/dev/null 2>&1 || true
		sudo -n "$ct" -D -p udp -s "$peer_vip" --dport "$BEACON_P2P_UDP_PORT" >/dev/null 2>&1 || true
		sudo -n "$ct" -D -p tcp -d "$peer_vip" --dport "$BEACON_P2P_TCP_PORT" >/dev/null 2>&1 || true
		sudo -n "$ct" -D -p udp -d "$peer_vip" --dport "$BEACON_P2P_UDP_PORT" >/dev/null 2>&1 || true
		sudo -n "$ct" -D -p tcp -s "$OVERLAY_VIP" -d "$peer_vip" --dport "$BEACON_P2P_TCP_PORT" >/dev/null 2>&1 || true
		sudo -n "$ct" -D -p udp -s "$OVERLAY_VIP" -d "$peer_vip" --dport "$BEACON_P2P_UDP_PORT" >/dev/null 2>&1 || true
	fi
	sudo -n "$ct" -D -p tcp --dport "$BEACON_P2P_TCP_PORT" -s "$OVERLAY_VIP" >/dev/null 2>&1 || true
	sudo -n "$ct" -D -p udp --dport "$BEACON_P2P_UDP_PORT" -s "$OVERLAY_VIP" >/dev/null 2>&1 || true
	echo "conntrack flushed for overlay beacon :${BEACON_P2P_TCP_PORT}/:${BEACON_P2P_UDP_PORT} (geth :${GETH_P2P_PORT} and public peers kept)"
}

apply() {
	enable_tun_local_dnat
	sudo -n iptables -t nat -N "$DNAT_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -F "$DNAT_CHAIN"
	# Inbound TUN → public listen, any tcp/udp port except overlay geth.
	# Ephemeral discv5 / outbound libp2p sockets bind the public IP.
	sudo -n iptables -t nat -A "$DNAT_CHAIN" -i "$TUN_IFACE" -d "$OVERLAY_VIP" -p tcp \
		! --dport "$GETH_P2P_PORT" -j DNAT --to-destination "$PUBLIC_IP"
	sudo -n iptables -t nat -A "$DNAT_CHAIN" -i "$TUN_IFACE" -d "$OVERLAY_VIP" -p udp \
		! --dport "$GETH_P2P_PORT" -j DNAT --to-destination "$PUBLIC_IP"
	# Local self-check / hairpin to the advertised vIP does not hit PREROUTING.
	sudo -n iptables -t nat -A "$DNAT_CHAIN" -d "$OVERLAY_VIP" -p tcp \
		--dport "$BEACON_P2P_TCP_PORT" -j DNAT --to-destination "${PUBLIC_IP}:${BEACON_P2P_TCP_PORT}"
	sudo -n iptables -t nat -A "$DNAT_CHAIN" -d "$OVERLAY_VIP" -p udp \
		--dport "$BEACON_P2P_UDP_PORT" -j DNAT --to-destination "${PUBLIC_IP}:${BEACON_P2P_UDP_PORT}"
	ensure_jump PREROUTING "$DNAT_CHAIN"
	ensure_jump OUTPUT "$DNAT_CHAIN"

	# Replies must leave TUN with overlay-VIP source. Default UDP SNAT to
	# the VIP. Do not set SNAT_UDP_SOURCE=$PUBLIC_IP on the hub — L0_ONLY
	# last-wins /32 conntrack then stays UNREPLIED.
	SNAT_UDP_SOURCE="${SNAT_UDP_SOURCE:-$OVERLAY_VIP}"
	sudo -n iptables -t nat -N "$SNAT_CHAIN" 2>/dev/null || true
	sudo -n iptables -t nat -F "$SNAT_CHAIN"
	sudo -n iptables -t nat -A "$SNAT_CHAIN" -o "$TUN_IFACE" -p tcp \
		--sport "$BEACON_P2P_TCP_PORT" -j SNAT --to-source "$OVERLAY_VIP"
	sudo -n iptables -t nat -A "$SNAT_CHAIN" -o "$TUN_IFACE" -p udp \
		--sport "$BEACON_P2P_UDP_PORT" -j SNAT --to-source "$SNAT_UDP_SOURCE"
	sudo -n iptables -t nat -A "$SNAT_CHAIN" -o "$TUN_IFACE" -s "$PUBLIC_IP" -p tcp \
		! --sport "$GETH_P2P_PORT" -j SNAT --to-source "$OVERLAY_VIP"
	sudo -n iptables -t nat -A "$SNAT_CHAIN" -o "$TUN_IFACE" -p tcp \
		! --sport "$GETH_P2P_PORT" -j SNAT --to-source "$OVERLAY_VIP"
	sudo -n iptables -t nat -A "$SNAT_CHAIN" -o "$TUN_IFACE" -p udp \
		! --sport "$GETH_P2P_PORT" -j SNAT --to-source "$SNAT_UDP_SOURCE"
	ensure_jump POSTROUTING "$SNAT_CHAIN"
	flush_overlay_beacon_conntrack

	echo "overlay VIP DNAT ($DNAT_CHAIN): $TUN_IFACE dest $OVERLAY_VIP tcp/udp (!:$GETH_P2P_PORT) -> ${PUBLIC_IP}"
	echo "overlay VIP SNAT ($SNAT_CHAIN): $TUN_IFACE sport :${BEACON_P2P_TCP_PORT}/:${BEACON_P2P_UDP_PORT} + src ${PUBLIC_IP} -> $OVERLAY_VIP"
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
	echo "--- $DNAT_CHAIN counters ---"
	sudo -n iptables -t nat -L "$DNAT_CHAIN" -n -v 2>/dev/null || true
	echo "--- $SNAT_CHAIN counters ---"
	sudo -n iptables -t nat -L "$SNAT_CHAIN" -n -v 2>/dev/null || true
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

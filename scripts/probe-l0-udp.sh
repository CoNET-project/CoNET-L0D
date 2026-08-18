#!/bin/bash
# Lab-only L0 UDP comms probe. Does NOT restart geth/beacon/l0d.
# Crate overlay envelope is complete IPv4 (proto 17 included). This is not SI udp_relay.
set -euo pipefail

LOCAL_VIP="${LOCAL_VIP:-}"
PEER_VIP="${PEER_VIP:-}"
ECHO_PORT="${ECHO_PORT:-19999}"
DHT_PORT="${DHT_PORT:-4300}"
TUN_IFACE="${TUN_IFACE:-conet-l0}"
TOKEN="${TOKEN:-l0d-udp-probe}"

die() { echo "ERROR: $*" >&2; exit 1; }

need_tun() {
	ip -4 addr show dev "$TUN_IFACE" >/dev/null 2>&1 || die "TUN $TUN_IFACE is down"
}

detect_local_vip() {
	if [[ -n "$LOCAL_VIP" ]]; then
		return 0
	fi
	LOCAL_VIP="$(ip -4 -o addr show dev "$TUN_IFACE" | awk '{print $4}' | cut -d/ -f1 | head -n1)"
	[[ -n "$LOCAL_VIP" ]] || die "could not read overlay vIP on $TUN_IFACE"
}

echo_listen() {
	need_tun
	detect_local_vip
	echo "UDP echo listen ${LOCAL_VIP}:${ECHO_PORT} token=$TOKEN"
	python3 - "$LOCAL_VIP" "$ECHO_PORT" "$TOKEN" <<'PY'
import socket, sys
host, port, token = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((host, port))
s.settimeout(20)
try:
    data, addr = s.recvfrom(2048)
except socket.timeout:
    print("LISTEN_TIMEOUT")
    sys.exit(2)
print(f"RECV from={addr[0]}:{addr[1]} bytes={len(data)}")
s.sendto(token + b"-pong", addr)
print("PONG sent")
PY
}

echo_send() {
	need_tun
	detect_local_vip
	[[ -n "$PEER_VIP" ]] || die "set PEER_VIP (peer overlay vIP)"
	echo "UDP echo send ${LOCAL_VIP} -> ${PEER_VIP}:${ECHO_PORT}"
	python3 - "$LOCAL_VIP" "$PEER_VIP" "$ECHO_PORT" "$TOKEN" <<'PY'
import socket, sys
src, dest, port, token = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4].encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
s.settimeout(8)
s.sendto(token + b"-ping", (dest, port))
try:
    data, addr = s.recvfrom(2048)
except socket.timeout:
    print("ECHO_TIMEOUT")
    sys.exit(2)
print(f"PONG from={addr[0]}:{addr[1]} payload={data!r}")
if not data.startswith(token):
    print("ECHO_UNEXPECTED")
    sys.exit(3)
print("ECHO_OK")
PY
}

dht_send() {
	need_tun
	detect_local_vip
	[[ -n "$PEER_VIP" ]] || die "set PEER_VIP (peer overlay vIP)"
	echo "UDP DHT-port send ${LOCAL_VIP} -> ${PEER_VIP}:${DHT_PORT}"
	python3 - "$LOCAL_VIP" "$PEER_VIP" "$DHT_PORT" "$TOKEN" <<'PY'
import socket, sys
src, dest, port, token = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4].encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
s.settimeout(3)
s.sendto(token + b"-dht", (dest, port))
print(f"SENT bytes={len(token)+4} to={dest}:{port} from={s.getsockname()}")
try:
    data, addr = s.recvfrom(2048)
    print(f"REPLY from={addr[0]}:{addr[1]} bytes={len(data)}")
    print("DHT_PORT_REPLY")
except socket.timeout:
    print("DHT_PORT_SENT_NO_REPLY")
    print("A sent datagram with no reply still proves L0 egress if the peer TUN/tcpdump saw it.")
PY
}

steer_send() {
	need_tun
	detect_local_vip
	local public_ip="${PEER_PUBLIC_IP:-198.251.77.98}"
	echo "UDP steer send ${LOCAL_VIP} -> ${public_ip}:${DHT_PORT} (expect DNAT to overlay)"
	python3 - "$LOCAL_VIP" "$public_ip" "$DHT_PORT" "$TOKEN" <<'PY'
import socket, sys
src, dest, port, token = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4].encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
s.settimeout(3)
try:
    s.sendto(token + b"-steer", (dest, port))
except OSError as exc:
    print(f"STEER_SEND_FAIL {exc}")
    sys.exit(2)
print(f"STEER_SENT bytes={len(token)+6} to={dest}:{port} from={s.getsockname()}")
try:
    data, addr = s.recvfrom(2048)
    print(f"STEER_REPLY from={addr[0]}:{addr[1]} bytes={len(data)}")
except socket.timeout:
    print("STEER_SENT_NO_REPLY")
PY
}

sniff() {
	need_tun
	local port="${2:-$DHT_PORT}"
	echo "tcpdump $TUN_IFACE udp port $port (20s / first packet)"
	sudo -n timeout 20 tcpdump -n -i "$TUN_IFACE" -c 1 "udp port $port" 2>&1 || true
}

case "${1:-}" in
echo-listen) echo_listen ;;
echo-send) echo_send ;;
dht-send) dht_send ;;
steer-send) steer_send ;;
sniff) sniff "$@" ;;
*)
	echo "Usage: $0 {echo-listen|echo-send|dht-send|steer-send|sniff}"
	echo "  PEER_VIP=100.64.0.6 $0 echo-send"
	echo "  PEER_VIP=100.64.0.6 $0 dht-send"
	echo "  PEER_PUBLIC_IP=198.251.77.98 $0 steer-send"
	exit 1
	;;
esac

#!/usr/bin/env bash
# Lab-only :4300 duplex observation window.
# Does NOT restart geth / beacon / validator.
# Optional: L0D_BOUNCE=1 restarts only conet-l0d on this host (TUN blip).
#
# Usage (on each lab host, from ~/conet-l0d-lab):
#   WINDOW_SECS=300 PEER_VIP=100.64.0.6 ./observe-4300-duplex.sh run
#   L0D_BOUNCE=1 WINDOW_SECS=300 PEER_VIP=100.64.0.6 ./observe-4300-duplex.sh run
set -euo pipefail

CMD="${1:-run}"
LOG="${LOG:-$HOME/conet-l0d-lab/conet-l0d.log}"
LAB="${LAB:-$HOME/conet-l0d-lab}"
TUN_IFACE="${TUN_IFACE:-conet-l0}"
PEER_VIP="${PEER_VIP:-}"
LOCAL_VIP="${LOCAL_VIP:-}"
DHT_PORT="${DHT_PORT:-4300}"
WINDOW_SECS="${WINDOW_SECS:-300}"
PROBE_EVERY_SECS="${PROBE_EVERY_SECS:-5}"
BURST="${BURST:-8}"
L0D_BOUNCE="${L0D_BOUNCE:-0}"
OUT_DIR="${OUT_DIR:-$LAB/observe-4300}"
TOKEN="${TOKEN:-l0d4300obs}"

die() { echo "ERROR: $*" >&2; exit 1; }

need() {
	command -v "$1" >/dev/null 2>&1 || die "missing $1"
}

detect_local_vip() {
	if [[ -n "$LOCAL_VIP" ]]; then
		return 0
	fi
	LOCAL_VIP="$(ip -4 -o addr show dev "$TUN_IFACE" | awk '{print $4}' | cut -d/ -f1 | head -n1)"
	[[ -n "$LOCAL_VIP" ]] || die "no vIP on $TUN_IFACE"
}

snapshot() {
	local tag="$1"
	local f="$OUT_DIR/${tag}.txt"
	{
		echo "tag=$tag"
		date -u +%Y-%m-%dT%H:%M:%SZ
		echo "log_bytes=$(stat -c%s "$LOG" 2>/dev/null || echo 0)"
		ip -s link show "$TUN_IFACE" || true
		echo "--- ss overlay ---"
		ss -uapn 2>/dev/null | grep -E ":${DHT_PORT}\b|${LOCAL_VIP}" | head -40 || true
		echo "--- conntrack overlay vip :${DHT_PORT} ---"
		sudo -n conntrack -L 2>/dev/null | grep -E "${LOCAL_VIP}|${PEER_VIP}" | grep -E "dport=${DHT_PORT}|sport=${DHT_PORT}" | head -40 || true
	} >"$f"
	echo "wrote $f"
}

parse_delta() {
	local start_bytes="$1"
	local end_tag="$2"
	python3 - "$LOG" "$start_bytes" "$OUT_DIR/${end_tag}-summary.txt" <<'PY'
import re, sys, pathlib
from collections import Counter
log_path, start_bytes, out_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
raw = pathlib.Path(log_path).read_bytes()
chunk = raw[start_bytes:].decode("utf-8", errors="replace")
ansi = re.compile(r"\x1b\[[0-9;]*m")
text = ansi.sub("", chunk)
aes = Counter(); p1 = Counter()
aes_n = p1_n = pipe = offer = accept = reject = pipe_fail = post_fail = 0
aes_pkts = p1_pkts = aes_bytes = p1_bytes = 0
for line in text.splitlines():
    def port_of(s):
        m = re.search(r"port=(\d+)", s)
        return m.group(1) if m else "?"
    def packets_of(s):
        m = re.search(r"packets=(\d+)", s)
        return int(m.group(1)) if m else 0
    def frame_of(s):
        m = re.search(r"frame_bytes=(\d+)", s)
        return int(m.group(1)) if m else 0
    if "duplex AES frame written" in line:
        aes_n += 1
        p = port_of(line)
        aes[p] += 1
        aes_pkts += packets_of(line)
        aes_bytes += frame_of(line)
    if "P1 overlay batch flushed for POST" in line:
        p1_n += 1
        p = port_of(line)
        p1[p] += 1
        p1_pkts += packets_of(line)
        p1_bytes += frame_of(line)
    if "pipe queue full" in line:
        pipe += 1
    if "duplex_offer accepted" in line:
        offer += 1
    if "duplex_accept on occupied" in line or "duplex_accept queued for Chat" in line:
        accept += 1
    if "duplex_reject" in line:
        reject += 1
    if "l0_connect pipe failed" in line:
        pipe_fail += 1
    if "POST /post failed" in line or "POST refused" in line:
        post_fail += 1
lines = [
    f"aes_batches={aes_n}",
    f"aes_by_port={dict(aes)}",
    f"aes_packets={aes_pkts}",
    f"aes_frame_bytes={aes_bytes}",
    f"p1_batches={p1_n}",
    f"p1_by_port={dict(p1)}",
    f"p1_packets={p1_pkts}",
    f"p1_frame_bytes={p1_bytes}",
    f"pipe_queue_full={pipe}",
    f"offer_accepted={offer}",
    f"accept_seen={accept}",
    f"reject={reject}",
    f"pipe_failed={pipe_fail}",
    f"post_failed={post_fail}",
    f"aes_share_4300={aes.get('4300',0)}/{aes_n if aes_n else 0}",
    f"p1_share_4300={p1.get('4300',0)}/{p1_n if p1_n else 0}",
]
pathlib.Path(out_path).write_text("\n".join(lines) + "\n")
print("\n".join(lines))
PY
}

udp_burst() {
	local n="$1"
	python3 - "$LOCAL_VIP" "$PEER_VIP" "$DHT_PORT" "$TOKEN" "$n" <<'PY'
import socket, sys, time
src, dest, port, token, n = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4].encode(), int(sys.argv[5])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
for i in range(n):
    payload = token + f"-burst-{i}-{time.time_ns()}".encode()
    # pad to ~200B discv5-ish size
    payload = payload + b"x" * max(0, 180 - len(payload))
    s.sendto(payload, (dest, port))
print(f"SENT burst={n} -> {dest}:{port}")
PY
}

bounce_l0d() {
	[[ -d "$LAB" ]] || die "LAB $LAB missing"
	cd "$LAB"
	local cfg
	if [[ -f ./conet-l0d.45.toml ]]; then
		cfg=./conet-l0d.45.toml
	elif [[ -f ./conet-l0d.98.toml ]]; then
		cfg=./conet-l0d.98.toml
	else
		die "no conet-l0d.*.toml in $LAB"
	fi
	echo "L0D_BOUNCE: stop/start $cfg (geth/beacon untouched)"
	sudo -n ./conet-l0d stop --config "$cfg" || true
	sleep 1
	# binary path: prefer lab cwd
	nohup sudo -n ./conet-l0d start --config "$cfg" >>"$LOG" 2>&1 &
	sleep 3
	pgrep -af './conet-l0d start' | head -3 || die "conet-l0d did not start"
}

case "$CMD" in
run)
	need python3
	need ip
	detect_local_vip
	[[ -n "$PEER_VIP" ]] || die "set PEER_VIP"
	mkdir -p "$OUT_DIR"
	if [[ "$L0D_BOUNCE" == "1" ]]; then
		bounce_l0d
		# wait a bit for duplex offer/accept
		sleep 8
	fi
	START_BYTES="$(stat -c%s "$LOG")"
	echo "OBS_START $(date -u +%Y-%m-%dT%H:%M:%SZ) local=$LOCAL_VIP peer=$PEER_VIP window=${WINDOW_SECS}s start_bytes=$START_BYTES"
	snapshot "t0"
	END=$((SECONDS + WINDOW_SECS))
	bursts=0
	while (( SECONDS < END )); do
		udp_burst "$BURST" || true
		bursts=$((bursts + 1))
		sleep "$PROBE_EVERY_SECS"
	done
	snapshot "t1"
	echo "OBS_END $(date -u +%Y-%m-%dT%H:%M:%SZ) bursts=$bursts"
	parse_delta "$START_BYTES" "window"
	echo "artifacts under $OUT_DIR"
	;;
summary)
	detect_local_vip
	START_BYTES="${2:-0}"
	parse_delta "$START_BYTES" "manual"
	;;
*)
	die "unknown cmd $CMD (run|summary)"
	;;
esac

#!/bin/bash
# Read-only P1 follow-the-chain snapshot for the authorized L0_ONLY lab host (.45).
# Does NOT restart geth, beacon, validator, or conet-l0d.
# Does NOT wipe. Does NOT mutate CONET_L0D.
# Serial ticks only (sleep after each snapshot). No setInterval.
set -euo pipefail

LAB_DIR="${LAB_DIR:-/home/peter/conet-l0d-lab}"
PROJECT_DIR="${PROJECT_DIR:-/home/peter/ethereum-pos-mainnet}"
NODE_DIR="${NODE_DIR:-$PROJECT_DIR/network/node-0}"
L0D_LOG="${L0D_LOG:-$LAB_DIR/logs/conet-l0d.log}"
BEACON_LOG="${BEACON_LOG:-$NODE_DIR/logs/beacon.log}"
GETH_HTTP_PORT="${GETH_HTTP_PORT:-8545}"
PRYSM_BEACON_GRPC_GATEWAY_PORT="${PRYSM_BEACON_GRPC_GATEWAY_PORT:-4100}"
LOCAL_VIP="${LOCAL_VIP:-100.64.0.5}"
PEER_VIP="${PEER_VIP:-100.64.0.6}"
SYNC_DISTANCE_OK="${SYNC_DISTANCE_OK:-64}"
WATCH="${WATCH:-0}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-60}"

log() {
	echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ') $*"
}

json_field() {
	python3 -c 'import json,sys
raw=sys.stdin.read().strip()
if not raw:
    print("")
    raise SystemExit(0)
try:
    d=json.loads(raw)
except Exception:
    print("")
    raise SystemExit(0)
keys=sys.argv[1].split(".")
cur=d
for k in keys:
    if isinstance(cur, dict) and k in cur:
        cur=cur[k]
    else:
        print("")
        raise SystemExit(0)
if cur is None:
    print("")
elif isinstance(cur, bool):
    print("true" if cur else "false")
else:
    print(cur)
' "$1" 2>/dev/null || true
}

count_estab() {
	local dest_port="$1"
	ss -tn state established 2>/dev/null | grep -cE "${LOCAL_VIP}:[0-9]+[[:space:]]+${PEER_VIP}:${dest_port}([[:space:]]|$)" || true
}

queue_full_since_start() {
	if [[ ! -f "$L0D_LOG" ]]; then
		echo "unavailable"
		return
	fi
	python3 - "$L0D_LOG" <<'PY'
import sys
path = sys.argv[1]
start = 0
drops = 0
with open(path, errors="replace") as f:
    for i, line in enumerate(f, 1):
        if "conet-l0d started" in line:
            start = i
            drops = 0
        elif start and "queue full" in line:
            drops += 1
print(drops if start else "no-start")
PY
}

last_initial_sync() {
	if [[ ! -f "$BEACON_LOG" ]]; then
		echo "unavailable"
		return
	fi
	grep -E "initial-sync:.*Processing blocks" "$BEACON_LOG" | tail -n 1 | sed 's/\x1b\[[0-9;]*m//g' || true
}

snapshot() {
	local geth_raw peers_raw sync_raw peer_count_raw
	local el peers head distance syncing connected
	local overlay_geth overlay_beacon drops verdict

	geth_raw="$(curl -sS --max-time 3 "http://127.0.0.1:${GETH_HTTP_PORT}" \
		-H 'content-type: application/json' \
		-d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' 2>/dev/null || true)"
	peers_raw="$(curl -sS --max-time 3 "http://127.0.0.1:${GETH_HTTP_PORT}" \
		-H 'content-type: application/json' \
		-d '{"jsonrpc":"2.0","id":1,"method":"net_peerCount","params":[]}' 2>/dev/null || true)"
	sync_raw="$(curl -sS --max-time 3 "http://127.0.0.1:${PRYSM_BEACON_GRPC_GATEWAY_PORT}/eth/v1/node/syncing" 2>/dev/null || true)"
	peer_count_raw="$(curl -sS --max-time 3 "http://127.0.0.1:${PRYSM_BEACON_GRPC_GATEWAY_PORT}/eth/v1/node/peer_count" 2>/dev/null || true)"

	el="$(printf '%s' "$geth_raw" | json_field result)"
	peers="$(printf '%s' "$peers_raw" | json_field result)"
	head="$(printf '%s' "$sync_raw" | json_field data.head_slot)"
	distance="$(printf '%s' "$sync_raw" | json_field data.sync_distance)"
	syncing="$(printf '%s' "$sync_raw" | json_field data.is_syncing)"
	connected="$(printf '%s' "$peer_count_raw" | json_field data.connected)"
	overlay_geth="$(count_estab 8400)"
	overlay_beacon="$(count_estab 4200)"
	drops="$(queue_full_since_start)"

	verdict="FOLLOW_IN_PROGRESS"
	if [[ -z "$el" || -z "$peers" || -z "$head" || -z "$distance" || -z "$syncing" || -z "$connected" ]]; then
		verdict="UNTRUSTED"
	elif [[ "$overlay_geth" -lt 1 || "$overlay_beacon" -lt 1 ]]; then
		verdict="OVERLAY_DOWN"
	elif [[ "$peers" == "0x0" || "$peers" == "0x00" || "$connected" == "0" ]]; then
		verdict="PEERS_DOWN"
	elif [[ "$el" == "0x0" || "$el" == "0x" ]]; then
		verdict="FOLLOW_IN_PROGRESS"
	elif [[ "$syncing" == "true" ]]; then
		verdict="FOLLOW_IN_PROGRESS"
	elif [[ "$distance" =~ ^[0-9]+$ ]] && [[ "$distance" -le "$SYNC_DISTANCE_OK" ]]; then
		verdict="FOLLOW_OK"
	else
		verdict="FOLLOW_IN_PROGRESS"
	fi

	log "verdict=$verdict el=$el geth_peers=$peers cl_head=$head sync_distance=$distance is_syncing=$syncing beacon_connected=$connected overlay_geth=$overlay_geth overlay_beacon=$overlay_beacon queue_full_since_l0d_start=$drops"
	local sync_line
	sync_line="$(last_initial_sync)"
	if [[ -n "$sync_line" ]]; then
		log "beacon $sync_line"
	fi
	if [[ "$verdict" == "FOLLOW_OK" ]]; then
		return 0
	fi
	return 1
}

if [[ "$WATCH" != "1" ]]; then
	if snapshot; then
		exit 0
	fi
	exit 1
fi

while true; do
	if snapshot; then
		exit 0
	fi
	sleep "$INTERVAL_SECONDS"
done

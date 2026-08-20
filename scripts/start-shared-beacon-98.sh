#!/bin/bash
# geth + beacon ONLY for the conet-l0d MVP lab on 198.251.77.98.
# Does NOT start validator. Does NOT wipe datadir. Does NOT geth init
# when chaindata already exists.
# Retired as a remote-VA shared beacon: gRPC/REST bind 127.0.0.1 only.
# Remote validators must not use this host. MVP tests geth/beacon P2P only.
# Prefer this over leftover 09_shared_beacon_98.sh start (that script is retired).
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-/home/peter/ethereum-pos-mainnet}"
NODE_DIR="${NODE_DIR:-$PROJECT_DIR/network/node-0}"
PUBLIC_IP="${PUBLIC_IP:-198.251.77.98}"
CHAIN_ID="${CHAIN_ID:-224422}"
L0_ONLY="${L0_ONLY:-0}"
OVERLAY_CIDR="${OVERLAY_CIDR:-100.64.0.0/10}"
OVERLAY_VIP="${OVERLAY_VIP:-100.64.0.6}"

GETH_BINARY="${GETH_BINARY:-$PROJECT_DIR/dependencies/geth-v1.17.5/geth}"
PRYSM_BEACON_BINARY="${PRYSM_BEACON_BINARY:-$PROJECT_DIR/dependencies/prysm-v7.1.8/beacon-chain}"

JWT_SECRET_FILE="${JWT_SECRET_FILE:-$NODE_DIR/execution/jwtsecret}"
CONSENSUS_GENESIS="${CONSENSUS_GENESIS:-$NODE_DIR/consensus/genesis.ssz}"
CHAIN_CONFIG_FILE="${CHAIN_CONFIG_FILE:-$NODE_DIR/consensus/config.yml}"

GETH_HTTP_PORT="${GETH_HTTP_PORT:-8889}"
GETH_AUTH_RPC_PORT="${GETH_AUTH_RPC_PORT:-8200}"
GETH_METRICS_PORT="${GETH_METRICS_PORT:-8300}"
GETH_P2P_PORT="${GETH_P2P_PORT:-8400}"
GETH_CACHE="${GETH_CACHE:-256}"

PRYSM_BEACON_RPC_PORT="${PRYSM_BEACON_RPC_PORT:-4000}"
PRYSM_BEACON_GRPC_GATEWAY_PORT="${PRYSM_BEACON_GRPC_GATEWAY_PORT:-4100}"
PRYSM_BEACON_P2P_TCP_PORT="${PRYSM_BEACON_P2P_TCP_PORT:-4200}"
PRYSM_BEACON_P2P_UDP_PORT="${PRYSM_BEACON_P2P_UDP_PORT:-4300}"
PRYSM_BEACON_MONITORING_PORT="${PRYSM_BEACON_MONITORING_PORT:-4400}"

# Public advertise is retained only for the legacy/public-hub mode.
ADVERTISE_IP="${ADVERTISE_IP:-$PUBLIC_IP}"
FEE_RECIPIENT="${FEE_RECIPIENT:-0x0981275553A41E00ec1006fe074971285E00c2A3}"
DEPOSIT_CONTRACT="${DEPOSIT_CONTRACT:-0x4242424242424242424242424242424242424242}"
MIN_SYNC_PEERS="${MIN_SYNC_PEERS:-1}"
ETH1_HEADER_REQ_LIMIT="${ETH1_HEADER_REQ_LIMIT:-4096}"

# Live EL bootnodes (2026-08-17) plus the .45 lab peer. Do not use leftover 192.76 / old .50 id.
LAB_45_ENODE="${LAB_45_ENODE:-enode://0c0a77bc4cd67ae806bc4e020ff7c39fbebfabb3fcc8bf7fd574eb75ed3b15e7e497a8b9f6e312ad47bc311dae92b4d40065f39ca56cca3a7688fe0bacaf552d@74.208.224.45:8400}"
# .82 overlay VIP (live geth must admin_removePeer public @216.225.202.82:8400 first).
HUB_BOOTNODES="${HUB_BOOTNODES:-enode://e5fe89d9ad924db6e4699480242a12fccba2c00e35772db706e46190c0ded9bb2b7e0d996826f5e46d369e01336213ef263c5038f94552e5f5e6e8ec76573a3f@38.102.126.30:8400,enode://d9243095bca94720f88d38c93ae4ccefc8b67651c66b4c93c915f845f6abfd39a091465db02db32b1a5b8061566c1558d2e6842f75620bf533480bab8a180168@38.102.126.50:8400,enode://5cf9a159e641318cda27e6bc1b4185667c0cdb1b54c3df5b8626eacbacea93af64c243dbdd09b40c62ba24792d0afc571cf17cbc47a5ed5a6207f27054c01d65@216.225.202.23:8400,enode://8e09d44bb4c29543a172e53dd8a74677a2a63d3d98a3d530f9d8b6f6bd6802a542f5b79d509ff737a9a764a66ab44a81403597cb50e350178ddd91f487e28f2d@216.225.202.22:8400,enode://dc0624c81896cdec036af7096886b1629a288b4824a467038df645c5c6b0f7fe75e13758ea80c0c37ba6245b221680db1fb553d564e54b55410eb6063bb64ca0@216.225.197.3:8400,enode://f1e249c97ce861441b3bd4832213cc634dd5c23d1a8722cd9c1aea28492779f6b64e012e8d97d56006d69be5224903ea5a787d8af68e9542db82ac1f76491dd5@100.64.0.7:8400}"
EXECUTION_BOOTNODES="${EXECUTION_BOOTNODES:-${HUB_BOOTNODES},${LAB_45_ENODE}}"
L0_OVERLAY_45_ENODE="${L0_OVERLAY_45_ENODE:-enode://0c0a77bc4cd67ae806bc4e020ff7c39fbebfabb3fcc8bf7fd574eb75ed3b15e7e497a8b9f6e312ad47bc311dae92b4d40065f39ca56cca3a7688fe0bacaf552d@100.64.0.5:8400?discport=0}"
L0_OVERLAY_82_ENODE="${L0_OVERLAY_82_ENODE:-enode://f1e249c97ce861441b3bd4832213cc634dd5c23d1a8722cd9c1aea28492779f6b64e012e8d97d56006d69be5224903ea5a787d8af68e9542db82ac1f76491dd5@100.64.0.7:8400}"

# Lab DHT server: do not dial the .45 public :4200 (isolate drops it; old peer id is stale).
# Leave empty so this host stays a public discv5 hub. Overlay .45 finds it via ENR + L0 steer.
EXTRA_BEACON_PEERS="${EXTRA_BEACON_PEERS:-}"

# DHT-over-L0 toward production hub .82 (steer dest 216.225.202.82:4300/:4200 → 100.64.0.7).
# This host MUST stay a public discv5 hub for .45: do NOT last-wins allowlist /32, do NOT L0_ONLY isolate.
LAB_DIR="${LAB_DIR:-/home/peter/conet-l0d-lab}"
L0_DHT_ENV="${L0_DHT_ENV:-$LAB_DIR/run/l0-dht-82.env}"
if [[ -f "$L0_DHT_ENV" ]]; then
	# shellcheck disable=SC1090
	source "$L0_DHT_ENV"
fi
L0_DHT="${L0_DHT:-0}"
L0_DHT_HUB_PUBLIC_IP="${L0_DHT_HUB_PUBLIC_IP:-216.225.202.82}"
L0_DHT_HUB_OVERLAY_VIP="${L0_DHT_HUB_OVERLAY_VIP:-100.64.0.7}"
L0_DHT_STEER_CHAIN="${L0_DHT_STEER_CHAIN:-CONET_L0D_DHT_STEER}"
L0_DHT_BOOTSTRAP_ENR="${L0_DHT_BOOTSTRAP_ENR:-}"
L0_OVERLAY_BEACON_PEERS="${L0_OVERLAY_BEACON_PEERS:-/ip4/100.64.0.7/tcp/4200/p2p/16Uiu2HAmDJCHuVkXtkPrrL8YykQ9gFZnQkR9Q6WjZZUrmueohPfd}"

die() { echo "ERROR: $*" >&2; exit 1; }
require_file() { [[ -f "$1" ]] || die "Missing file: $1"; }
require_dir() { [[ -d "$1" ]] || die "Missing dir: $1"; }
require_exec() { [[ -x "$1" ]] || die "Missing exec: $1"; }

pid_alive() {
	local pid="$1"
	[[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

stop_pid_file() {
	local name="$1"
	local pid_file="$2"
	local wait_secs="${3:-30}"
	[[ -f "$pid_file" ]] || return 0
	local pid
	pid="$(cat "$pid_file" 2>/dev/null || true)"
	if pid_alive "$pid"; then
		echo "Stopping $name pid=$pid (SIGTERM, wait ${wait_secs}s)"
		kill "$pid" 2>/dev/null || true
		local i
		for ((i = 1; i <= wait_secs; i++)); do
			pid_alive "$pid" || { rm -f "$pid_file"; echo "$name exited after ${i}s"; return 0; }
			sleep 1
		done
		echo "WARN $name still alive after SIGTERM; sending SIGKILL"
		kill -9 "$pid" 2>/dev/null || true
		sleep 2
	fi
	rm -f "$pid_file"
}

stop_geth() {
	echo "Stopping geth only (beacon/validator untouched, data preserved)"
	stop_pid_file geth "$NODE_DIR/geth.pid" 90
}

stop_beacon() {
	echo "Stopping beacon only (geth/validator untouched, data preserved)"
	stop_pid_file beacon "$NODE_DIR/beacon.pid" 30
}

wait_for_port() {
	local host="$1" port="$2" name="$3" retries="${4:-120}"
	echo "Waiting for $name at $host:$port ..."
	local i
	for ((i = 1; i <= retries; i++)); do
		if timeout 1 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
			echo "$name is up"
			return 0
		fi
		sleep 1
	done
	echo "Warning: $name did not open $host:$port"
	return 1
}

load_colo_args() {
	COLO_ARGS=()
	if [[ -f "$PROJECT_DIR/conet_p2p_colocation_whitelist.sh" ]]; then
		# shellcheck disable=SC1091
		source "$PROJECT_DIR/conet_p2p_colocation_whitelist.sh"
		if declare -F p2p_colocation_whitelist_args >/dev/null 2>&1; then
			mapfile -t COLO_ARGS < <(p2p_colocation_whitelist_args || true)
		fi
	fi
	# Overlay vIPs share one public host; allow 100.64.0.0/10 so L0 DHT clients are not coloc-kicked.
	local overlay_wl=0
	local arg
	for arg in "${COLO_ARGS[@]+"${COLO_ARGS[@]}"}"; do
		[[ "$arg" == *100.64.0.0/10* ]] && overlay_wl=1
	done
	if ((overlay_wl == 0)); then
		COLO_ARGS+=(--p2p-colocation-whitelist=100.64.0.0/10)
	fi
}

l0_dht_on() {
	[[ "${L0_DHT}" == "1" || "${L0_DHT}" == "true" || "${L0_DHT}" == "yes" ]]
}

# Fail-closed: without steer, discv5 to the .82 public ENR stays on the public IP (or QUIC :13000).
require_l0_dht_steer() {
	local rules
	rules="$(sudo -n iptables -t nat -S "$L0_DHT_STEER_CHAIN" 2>/dev/null || true)"
	[[ -n "$rules" ]] || die "L0_DHT: missing $L0_DHT_STEER_CHAIN; run overlay-dht-steer.sh first (PEER_PUBLIC_IP=$L0_DHT_HUB_PUBLIC_IP PEER_OVERLAY_VIP=$L0_DHT_HUB_OVERLAY_VIP)"
	[[ "$rules" == *"-d ${L0_DHT_HUB_PUBLIC_IP}"* ]] \
		|| die "L0_DHT: $L0_DHT_STEER_CHAIN does not match hub $L0_DHT_HUB_PUBLIC_IP; run overlay-dht-steer.sh"
	[[ "$rules" == *"-p udp"* && "$rules" == *"--dport ${PRYSM_BEACON_P2P_UDP_PORT}"* && "$rules" == *"--to-destination ${L0_DHT_HUB_OVERLAY_VIP}:${PRYSM_BEACON_P2P_UDP_PORT}"* ]] \
		|| die "L0_DHT: $L0_DHT_STEER_CHAIN has no UDP :${PRYSM_BEACON_P2P_UDP_PORT} DNAT -> ${L0_DHT_HUB_OVERLAY_VIP}; run overlay-dht-steer.sh"
	[[ "$rules" == *"-p tcp"* && "$rules" == *"--dport ${PRYSM_BEACON_P2P_TCP_PORT}"* && "$rules" == *"--to-destination ${L0_DHT_HUB_OVERLAY_VIP}:${PRYSM_BEACON_P2P_TCP_PORT}"* ]] \
		|| die "L0_DHT: $L0_DHT_STEER_CHAIN has no TCP :${PRYSM_BEACON_P2P_TCP_PORT} DNAT -> ${L0_DHT_HUB_OVERLAY_VIP}; run overlay-dht-steer.sh"
	echo "OK  L0_DHT steer $L0_DHT_HUB_PUBLIC_IP :${PRYSM_BEACON_P2P_UDP_PORT}/udp :${PRYSM_BEACON_P2P_TCP_PORT}/tcp -> $L0_DHT_HUB_OVERLAY_VIP"
}

write_l0_dht_env() {
	L0_DHT=1
	mkdir -p "$(dirname "$L0_DHT_ENV")"
	{
		echo "L0_DHT=1"
		echo "L0_DHT_HUB_PUBLIC_IP=$L0_DHT_HUB_PUBLIC_IP"
		echo "L0_DHT_HUB_OVERLAY_VIP=$L0_DHT_HUB_OVERLAY_VIP"
		if [[ -n "${L0_DHT_BOOTSTRAP_ENR:-}" && "${L0_DHT_BOOTSTRAP_ENR}" == enr:* ]]; then
			printf "L0_DHT_BOOTSTRAP_ENR='%s'\n" "${L0_DHT_BOOTSTRAP_ENR//\'/}"
		fi
		printf "L0_OVERLAY_BEACON_PEERS='%s'\n" "${L0_OVERLAY_BEACON_PEERS//\'/}"
	} > "$L0_DHT_ENV"
	echo "Wrote $L0_DHT_ENV (public advertise kept; not L0_ONLY). Overlay beacon TCP toward .82 needs authorized restart-beacon with --disable-quic; this write does not restart EL/CL."
}

load_bootstrap_args() {
	BOOTSTRAP_ARGS=()
	require_exec "$PROJECT_DIR/fetch_bootstrap_enrs.sh"
	local -a enrs=()
	mapfile -t enrs < <(DHT_BOOTSTRAP_ONLY="${DHT_BOOTSTRAP_ONLY:-NO}" PUBLIC_IP="$PUBLIC_IP" "$PROJECT_DIR/fetch_bootstrap_enrs.sh" || true)
	local enr
	for enr in "${enrs[@]}"; do
		if [[ "$enr" == enr:* ]]; then
			echo "OK  bootstrap $enr"
			BOOTSTRAP_ARGS+=(--bootstrap-node="$enr")
		fi
	done
	if l0_dht_on && [[ -n "${L0_DHT_BOOTSTRAP_ENR:-}" && "${L0_DHT_BOOTSTRAP_ENR}" == enr:* ]]; then
		echo "OK  L0_DHT extra bootstrap $L0_DHT_BOOTSTRAP_ENR"
		BOOTSTRAP_ARGS+=(--bootstrap-node="$L0_DHT_BOOTSTRAP_ENR")
	fi
	((${#BOOTSTRAP_ARGS[@]} > 0)) || die "No live DHT ENRs"
}

load_extra_beacon_peers() {
	PEER_ARGS=()
	[[ -n "$EXTRA_BEACON_PEERS" ]] || return 0
	local IFS=','
	local peer
	for peer in $EXTRA_BEACON_PEERS; do
		peer="${peer//[[:space:]]/}"
		[[ -n "$peer" ]] || continue
		echo "OK  extra beacon peer $peer"
		PEER_ARGS+=(--peer="$peer")
	done
}

start_geth() {
	local -a extra=()
	if [[ "$L0_ONLY" == "1" || "$L0_ONLY" == "true" || "$L0_ONLY" == "yes" ]]; then
		ADVERTISE_IP="$OVERLAY_VIP"
		EXECUTION_BOOTNODES="$L0_OVERLAY_82_ENODE,$L0_OVERLAY_45_ENODE"
		extra+=(--nodiscover --netrestrict "$OVERLAY_CIDR" --maxpeers 8)
		echo "Starting geth L0_ONLY advertise=$ADVERTISE_IP cache=$GETH_CACHE (no public fallback)"
	else
		echo "Starting geth advertise=$ADVERTISE_IP cache=$GETH_CACHE (no wipe)"
		echo "EXECUTION_BOOTNODES=$EXECUTION_BOOTNODES"
	fi
	nohup "$GETH_BINARY" \
		--datadir "$NODE_DIR/execution" \
		--state.scheme=hash \
		--networkid "$CHAIN_ID" \
		--port "$GETH_P2P_PORT" \
		--discovery.port "$GETH_P2P_PORT" \
		--bootnodes "$EXECUTION_BOOTNODES" \
		"${extra[@]}" \
		--nat "extip:$ADVERTISE_IP" \
		--cache "$GETH_CACHE" \
		--http \
		--http.addr 127.0.0.1 \
		--http.port "$GETH_HTTP_PORT" \
		--http.api eth,net,web3,txpool,admin \
		--http.vhosts localhost \
		--authrpc.addr 127.0.0.1 \
		--authrpc.port "$GETH_AUTH_RPC_PORT" \
		--authrpc.vhosts localhost \
		--authrpc.jwtsecret "$JWT_SECRET_FILE" \
		--metrics --metrics.addr 127.0.0.1 --metrics.port "$GETH_METRICS_PORT" \
		--syncmode full \
		--gcmode full \
		> "$NODE_DIR/logs/geth.log" 2>&1 &
	echo $! > "$NODE_DIR/geth.pid"
	wait_for_port 127.0.0.1 "$GETH_AUTH_RPC_PORT" geth-authrpc 120 || true
	wait_for_port 127.0.0.1 "$GETH_HTTP_PORT" geth-http 30 || true
}

start_beacon() {
	echo "Starting beacon advertise=$ADVERTISE_IP (no validator, RPC 127.0.0.1; remote VA retired)"
	local -a extra=()
	if [[ "$L0_ONLY" == "1" || "$L0_ONLY" == "true" || "$L0_ONLY" == "yes" ]]; then
		ADVERTISE_IP="$OVERLAY_VIP"
		EXTRA_BEACON_PEERS="$L0_OVERLAY_BEACON_PEERS"
		extra+=(--no-discovery --disable-quic)
		echo "L0_ONLY=1: beacon accepts only explicit overlay peers; no bootstrap/discovery/public fallback"
	elif l0_dht_on; then
		require_l0_dht_steer
		# QUIC :13000 is public and not steered. Disable so .82 discv5/libp2p use :4300/:4200 (DNAT → overlay).
		extra+=(--disable-quic)
		echo "L0_DHT=1 toward $L0_DHT_HUB_PUBLIC_IP (steer → $L0_DHT_HUB_OVERLAY_VIP); public discv5 hub kept; --disable-quic"
	fi
	if [[ "$L0_ONLY" != "1" && "$L0_ONLY" != "true" && "$L0_ONLY" != "yes" ]]; then
		load_bootstrap_args
	fi
	load_colo_args
	load_extra_beacon_peers
	nohup "$PRYSM_BEACON_BINARY" \
		--datadir="$NODE_DIR/consensus/beacondata" \
		--accept-terms-of-use \
		--genesis-state="$CONSENSUS_GENESIS" \
		--chain-config-file="$CHAIN_CONFIG_FILE" \
		--execution-endpoint="http://127.0.0.1:${GETH_AUTH_RPC_PORT}" \
		--jwt-secret="$JWT_SECRET_FILE" \
		--chain-id="$CHAIN_ID" \
		"${BOOTSTRAP_ARGS[@]}" \
		"${COLO_ARGS[@]}" \
		"${PEER_ARGS[@]}" \
		"${extra[@]}" \
		--rpc-host=127.0.0.1 \
		--rpc-port="$PRYSM_BEACON_RPC_PORT" \
		--grpc-gateway-host=127.0.0.1 \
		--grpc-gateway-port="$PRYSM_BEACON_GRPC_GATEWAY_PORT" \
		--p2p-tcp-port="$PRYSM_BEACON_P2P_TCP_PORT" \
		--p2p-udp-port="$PRYSM_BEACON_P2P_UDP_PORT" \
		--p2p-host-ip="$ADVERTISE_IP" \
		--p2p-static-id \
		--p2p-max-peers=40 \
		--disable-staking-contract-check \
		--min-sync-peers="$MIN_SYNC_PEERS" \
		--monitoring-host=127.0.0.1 \
		--monitoring-port="$PRYSM_BEACON_MONITORING_PORT" \
		--suggested-fee-recipient="$FEE_RECIPIENT" \
		--contract-deployment-block=0 \
		--deposit-contract="$DEPOSIT_CONTRACT" \
		--eth1-header-req-limit="$ETH1_HEADER_REQ_LIMIT" \
		> "$NODE_DIR/logs/beacon.log" 2>&1 &
	echo $! > "$NODE_DIR/beacon.pid"
	wait_for_port 127.0.0.1 "$PRYSM_BEACON_RPC_PORT" beacon-rpc 120 || true
	wait_for_port 127.0.0.1 "$PRYSM_BEACON_GRPC_GATEWAY_PORT" beacon-gateway 30 || true
}

stop_clients() {
	echo "Stopping geth + beacon only (validator untouched, data preserved)"
	stop_pid_file beacon "$NODE_DIR/beacon.pid" 30
	stop_pid_file geth "$NODE_DIR/geth.pid" 90
}

show_status() {
	for name in geth beacon; do
		local pid_file="$NODE_DIR/${name}.pid"
		if [[ -f "$pid_file" ]]; then
			local pid
			pid="$(cat "$pid_file" 2>/dev/null || true)"
			if pid_alive "$pid"; then
				echo "$name: running pid=$pid"
			else
				echo "$name: pid file stale"
			fi
		else
			echo "$name: not running"
		fi
	done
	if pgrep -af 'validator --' | grep -v pgrep >/dev/null 2>&1; then
		echo "validator: UNEXPECTED running (must stay off on this host)"
	else
		echo "validator: not started (expected; remote VA retired)"
	fi
	if ss -lnt 2>/dev/null | grep -E '0\.0\.0\.0:4000|0\.0\.0\.0:4100|:::4000|:::4100' >/dev/null; then
		echo "WARN: beacon gRPC/REST is public; remote VA must stay retired (bind 127.0.0.1)"
	else
		echo "beacon RPC: 127.0.0.1 only (remote VA retired)"
	fi
	if curl -sf "http://127.0.0.1:${GETH_HTTP_PORT}" >/dev/null 2>&1; then
		curl -s "http://127.0.0.1:${GETH_HTTP_PORT}" -H 'content-type: application/json' \
			-d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'
		echo
		curl -s "http://127.0.0.1:${GETH_HTTP_PORT}" -H 'content-type: application/json' \
			-d '{"jsonrpc":"2.0","id":2,"method":"net_peerCount","params":[]}'
		echo
	fi
	if curl -sf "http://127.0.0.1:${PRYSM_BEACON_GRPC_GATEWAY_PORT}/eth/v1/node/syncing" >/dev/null 2>&1; then
		curl -s "http://127.0.0.1:${PRYSM_BEACON_GRPC_GATEWAY_PORT}/eth/v1/node/syncing"
		echo
		curl -s "http://127.0.0.1:${PRYSM_BEACON_GRPC_GATEWAY_PORT}/eth/v1/node/peer_count"
		echo
	fi
}

ACTION="${1:-start}"
mkdir -p "$NODE_DIR/logs"
require_exec "$GETH_BINARY"
require_exec "$PRYSM_BEACON_BINARY"
require_dir "$NODE_DIR/execution/geth/chaindata"
require_file "$JWT_SECRET_FILE"
require_file "$CONSENSUS_GENESIS"
require_file "$CHAIN_CONFIG_FILE"

case "$ACTION" in
start)
	stop_clients
	start_geth
	start_beacon
	show_status
	echo "Started geth+beacon only. Remote VA is retired on this host."
	echo "Overlay advertise requires a live L0 stream before ADVERTISE_IP=100.64.0.6."
	;;
stop)
	stop_clients
	;;
restart)
	stop_clients
	start_geth
	start_beacon
	show_status
	;;
start-geth)
	stop_geth
	start_geth
	show_status
	;;
stop-geth)
	stop_geth
	show_status
	;;
restart-beacon)
	stop_beacon
	start_beacon
	show_status
	echo "Beacon restarted with --p2p-static-id. geth untouched. Re-apply overlay-beacon-listen-dnat.sh (not steer immediately)."
	;;
enable-l0-dht)
	write_l0_dht_env
	echo "L0_DHT env written. Apply overlay-dht-steer.sh PEER_PUBLIC_IP=$L0_DHT_HUB_PUBLIC_IP PEER_OVERLAY_VIP=$L0_DHT_HUB_OVERLAY_VIP."
	echo "This host stays a public discv5 hub (no L0_ONLY isolate, no last-wins /32). Overlay beacon TCP toward .82 needs authorized restart-beacon with --disable-quic (lab 2026-08-20). This is not origin anonymity."
	echo "This script did not restart EL/CL."
	;;
status)
	show_status
	;;
*)
	echo "Usage: $0 {start|stop|restart|status|start-geth|stop-geth|restart-beacon|enable-l0-dht}"
	exit 1
	;;
esac

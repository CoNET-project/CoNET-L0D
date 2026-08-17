#!/bin/bash
# Add the two conet-l0d MVP lab hosts as geth static peers (public IP).
# Beacon static --peer is applied at process start (see EXTRA_BEACON_PEERS).
# Does not restart geth/beacon. Does not wipe. Does not start validator.
set -euo pipefail

HOST_45="${HOST_45:-74.208.224.45}"
HOST_98="${HOST_98:-198.251.77.98}"
HTTP_45="${HTTP_45:-http://127.0.0.1:8545}"
HTTP_98="${HTTP_98:-http://127.0.0.1:8889}"
SSH_45="${SSH_45:-peter@$HOST_45}"
SSH_98="${SSH_98:-peter@$HOST_98}"

rpc() {
	local url="$1" method="$2" params="${3:-[]}"
	curl -sS --max-time 12 "$url" -H 'content-type: application/json' \
		-d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}"
}

enode_of() {
	local url="$1"
	rpc "$url" admin_nodeInfo | python3 -c 'import sys,json
d=json.load(sys.stdin).get("result") or {}
print(d.get("enode") or "")'
}

add_peer() {
	local url="$1" enode="$2"
	rpc "$url" admin_addPeer "[\"$enode\"]"
	echo
}

echo "=== collect enodes ==="
ENODE_45="$(ssh -o BatchMode=yes -o ConnectTimeout=12 "$SSH_45" "curl -sS --max-time 8 $HTTP_45 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"admin_nodeInfo\",\"params\":[]}'" | python3 -c 'import sys,json; print((json.load(sys.stdin).get("result") or {}).get("enode") or "")')"
ENODE_98="$(ssh -o BatchMode=yes -o ConnectTimeout=12 "$SSH_98" "curl -sS --max-time 8 $HTTP_98 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"admin_nodeInfo\",\"params\":[]}'" | python3 -c 'import sys,json; print((json.load(sys.stdin).get("result") or {}).get("enode") or "")')"

echo "45 $ENODE_45"
echo "98 $ENODE_98"
[[ "$ENODE_45" == enode://* ]] || { echo "ERROR: missing .45 enode" >&2; exit 1; }
[[ "$ENODE_98" == enode://* ]] || { echo "ERROR: missing .98 enode" >&2; exit 1; }

echo "=== addPeer both ways ==="
ssh -o BatchMode=yes -o ConnectTimeout=12 "$SSH_45" "curl -sS --max-time 8 $HTTP_45 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"admin_addPeer\",\"params\":[\"$ENODE_98\"]}'"
echo
ssh -o BatchMode=yes -o ConnectTimeout=12 "$SSH_98" "curl -sS --max-time 8 $HTTP_98 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"admin_addPeer\",\"params\":[\"$ENODE_45\"]}'"
echo

echo "=== geth peer counts ==="
ssh -o BatchMode=yes -o ConnectTimeout=12 "$SSH_45" "curl -sS --max-time 8 $HTTP_45 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"net_peerCount\",\"params\":[]}'"
echo
ssh -o BatchMode=yes -o ConnectTimeout=12 "$SSH_98" "curl -sS --max-time 8 $HTTP_98 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"net_peerCount\",\"params\":[]}'"
echo

# Experimental L1 process flags

Revision: 2026-08-22

This note applies only when an operator deliberately carries selected L1 TCP
streams through the experimental `web3://` duplex transport. It does not
replace the public [Run an L1 node](https://gitbook.conet.network/developers/l1-node.html)
guide.

## 1. Keep identity separate from transport

`conet-l0d` carries application bytes. It does not replace geth enode identity
or Prysm peer identity.

| Layer | Stable identity |
|---|---|
| Geth | node key and enode ID |
| Prysm | libp2p private key and peer ID |
| `web3://` | wallet address or exact BeamioTag used to select the remote application |

Changing the transport must not silently rotate any of these identities.

## 2. Public node path

For the public node-joining path:

- advertise the node's reachable public IP;
- expose the geth and Prysm P2P ports required by the node guide;
- use the published enode and Prysm peer ID; and
- verify peers through the clients' own APIs.

The public path does not require `conet-l0d`.

## 3. Experimental duplex path

For a controlled Linux-to-Linux experiment:

1. publish the remote local TCP service with `--proxyDuplex`;
2. select it from the client with `--clientDuplex web3://<wallet-or-tag>:<port>`;
3. point the local L1 process at the resulting client endpoint;
4. keep the original node key or libp2p identity; and
5. verify both the application stream and the L1 peer.

Example logical service ports:

| Port | Laboratory role |
|---:|---|
| `8400` | geth devp2p TCP |
| `4200` | Prysm libp2p TCP |

If the requested local port is already occupied, `conet-l0d` may select the
documented fallback listener (`port + 10000`). Read the startup log or
`conet-l0d status` and configure the local process with the actual endpoint.

## 4. Geth

For an experimental static connection, preserve the remote node ID and change
only the reachable endpoint used by the local experiment.

Verify:

```bash
curl -s http://127.0.0.1:8545 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"net_peerCount","params":[]}'
```

Where admin RPC is enabled locally, inspect `admin_peers` and confirm the
expected enode ID. A connected TCP stream without the expected enode is not a
successful geth test.

## 5. Prysm

Use a static multiaddr containing the expected peer ID:

```text
/ip4/<local-endpoint>/tcp/<port>/p2p/<peer-id>
```

Verify:

```bash
curl -s http://127.0.0.1:4100/eth/v1/node/peer_count
curl -s http://127.0.0.1:4100/eth/v1/node/peers
```

An established application stream does not by itself prove that Prysm accepted
the peer. Confirm `connected >= 1` and match the peer ID.

## 6. Laboratory identities

The repository's
[`scripts/l1-beacon-static-peers.env`](../scripts/l1-beacon-static-peers.env)
records laboratory peer IDs. Treat that file as the source for a repeated
experiment; do not substitute a DHT identity for a Prysm peer ID.

The August 2026 experiment used overlay endpoints `100.64.0.5` and
`100.64.0.6`. Those values are a lab record, not defaults for other operators.

## 7. Operational safety

- Diagnose the `web3://` session before changing L1 processes.
- Do not restart geth, beacon-chain, or validator without explicit approval.
- Do not wipe chain data to repair an application-stream failure.
- Do not interpret a temporarily low public peer count after a restart as
  proof that the application transport failed.
- Record the actual local endpoint, wallet destination, enode, and Prysm peer
  ID for every experiment.

## SI pool
`l0.si_pool_from_contract` defaults to `true`. It permits empty static `entries` and `listen_entries`, using GuardianNodesInfoV6 via `l0.rpc`; set it to `false` to operate only with static entries.

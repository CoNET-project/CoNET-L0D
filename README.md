# CoNET-L0D

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitBook Applications](https://img.shields.io/badge/GitBook-Applications-1B67B3)](https://gitbook.conet.network/applications/conet-l0d.html)
[![GitBook Developers](https://img.shields.io/badge/GitBook-Developers-1B67B3)](https://gitbook.conet.network/developers/conet-l0d.html)

**Repository:** [https://github.com/CoNET-project/CoNET-L0D](https://github.com/CoNET-project/CoNET-L0D)

Linux userspace daemon that lets CoNET L1 `geth` and Prysm `beacon-chain` use **Layer Minus (L0)** as a **static overlay P2P path** without patching those clients.

`conet-l0d` owns the network objects for its own lifetime:

- creates TUN `conet-l0`
- adds the overlay address and a route for `100.64.0.0/10`
- installs a dedicated iptables chain `CONET_L0D` (loopback is returned first)
- removes **exactly those** objects on `stop`, SIGINT / SIGTERM, or `teardown`

Operators do **not** run `iptables` by hand.

**Maturity: under development.** Crate MVP is accepted (CLI, locator, TUN / iptables lifecycle, packet counters). Overlay `/post` prefers SI **`l0_listen` / `l0_connect`** occupancy plus **application duplex** (`duplex_offer` on Chat gossip; accept / reject / AES `duplex_frame` on the occupied pipe); **P1 gossip** remains the fallback if the peer app never sends `duplex_accept` or the pipe is missing. P1 outbound encrypt + mailbox wrap + `POST { data }`, inbound decrypt + TUN write-back, and listen HTTP+SSE workers exist in-crate and default **off**. Listen ingest matches SI `forWardPGPMessageToClient` raw JSON `{ "data": "<armor>" }` (Chat `handleInbound`), plus duplex JSON frames. In-crate listen matches SI `checkSign`. An authorized lab may enable `[l0]`. The 2026-08-18 lab on authorized L0_ONLY `.45` advertises overlay vIP `100.64.0.5`, completed overlay geth + beacon TCP, and is running CL initial-sync over overlay; after the batching binary the limiter is Prysm (~3.2 blocks/s); EL is still `0x0`. Lab overlay UDP echo and `:4300` (direct + public-ENR steer) arrived on the peer TUN; live discv5 from L0_ONLY `.45` to the `.98` DHT server over L0 is **accepted** (not a production product). Production mailbox delivery is **not** shipped. Production proposers keep public P2P (geth `8400`, beacon `4200` / `4300`) for the 6-second slot.

## What it is not

| Other product | Difference |
| --- | --- |
| SilentPass / `SaaS_Sock5` | Device or app **egress** to a public `host:port`. Not L1 consensus P2P. |
| Current L0 UDP forward | AES frames over HTTP / SSE — not raw OS UDP, not discv4. |
| Validator client | Talks only to the **local** beacon. Do not capture its uid or read its keystore. |

Layer Minus stays a PGP / wallet-address forwarding plane. HTTP `/post` is only `{ "data": "<OpenPGP armor>" }`. This crate is an **application composition**, not a second IP network.

Overlay duplex is SI **`l0_listen` / `l0_connect`** plus **application JSON** on Chat gossip / occupied AES. SI does **not** implement `duplex_*`. There is **no** live SI command named `p2p_stream_*` or `listenKind: "l1p2p"`. Do not send `mining` + `listenKind: "duplex"`.

For `--clientDuplex`, local TCP is connection-driven. Each
`TcpListener.accept()` event is the sole connection handle; its explicit
`mainWallet:port` new-line request creates a fresh temporary wallet/PGP route,
AES key, return queue, and occupied pipe before offer handling.
The same socket reuses that line until EOF/error; concurrent sockets on the
same local port receive independent lines. Raw Geth/Prysm bytes are not
prefixed with a private header; the socket handle and encrypted
`pipe_handle` provide correlation. `--client` remains the packet/TUN
request/response path.

For a TUN-less Beacon bridge, set `L0_STREAM_ONLY=1` in the operator startup
environment and pass the local listener peer through `EXTRA_BEACON_PEERS`.
The script then disables discovery and QUIC and does not load public/DHT
peers. Explicit `EXTRA_BEACON_PEERS` values win over sourced host defaults,
preventing a stale overlay VIP from being used as the Beacon `--peer`.

## Identity (`web3://`)

The URI is a **peer locator**, not an ERC-4804 content URL.

```text
web3://0x<40-hex>/p2p/geth
web3://YourExactTag.web3/p2p/beacon
```

`@beamioTag` must match **exactly** (`CoNET` ≠ `CONET`). Do not take `search-users` `results[0]`. An AA without AddressPGP is not a destination.

Routing EOA ≠ deposit keystore ≠ fee recipient.

## Build

Requires a stable Rust toolchain (`rust-toolchain.toml`).

```bash
git clone https://github.com/CoNET-project/CoNET-L0D.git
cd CoNET-L0D
cargo test
cargo build --release
# binary: target/release/conet-l0d
sudo install -m 0755 target/release/conet-l0d /usr/local/sbin/conet-l0d
```

`check-config`, `resolve`, and `status` run on any OS. `start` / `stop` / `teardown` need Linux, `ip`, `iptables`, and `CAP_NET_ADMIN` (usually `sudo`). `gateway` is a separate server mode and does not create a TUN or modify iptables; it reads key material from local files.

## Commands

```bash
conet-l0d check-config --config config/conet-l0d.example.toml
conet-l0d resolve 'web3://0x1111111111111111111111111111111111111111/p2p/geth'
conet-l0d status --config /etc/conet-l0d.toml
sudo conet-l0d start --config /etc/conet-l0d.toml
conet-l0d gateway --config /etc/conet-l0d-gateway.toml
sudo conet-l0d stop --config /etc/conet-l0d.toml
sudo conet-l0d teardown --config /etc/conet-l0d.toml
```

Gateway mode uses `[gateway]` with a loopback `upstream`, separate
`listen_entries` and `post_entries`, `routing_eoa`, and local files for the
gateway PGP certificate, EIP-191 secret, and mailbox route public key. It
accepts signed `conet_web3_request_v1` messages over mailbox SSE, proxies
validated GET/HEAD requests to the upstream, and posts an encrypted
`conet_web3_response_v1` to the requester through an Entry. The inbound SSE
is receive-only; the requester receives the response on its own mailbox SSE.

### Verified deployment: `conet.network` (2026-08-20)

The gateway mode was built natively for Linux and deployed on `conet.network`
as `conet-l0d-gateway.service`. A separate
`conet-web3-origin-proxy.service` serves the existing
`https://conet.network` origin through loopback HTTP on `127.0.0.1:8080`.
Both services were verified active.

The real end-to-end acceptance flow used a newly generated requester EOA and
PGP identity, the production AddressPGP registration path, a real Entry node,
and the official gateway destination:

```text
web3://0xA8386335F1a8C6Fab3798F36cd4F663Ce7bF5A53/
```

The response returned HTTP `200` with `text/html`; its SHA-256 matched a direct
fetch of `https://conet.network/` exactly. This proves the deployed mailbox
request/response path and origin adapter, but does not make the gateway a
direct public port-80 mailbox or claim production multi-Guardian hosting.

Copy `config/conet-l0d.example.toml` to `/etc/conet-l0d.toml` and set `local_vip`, `identity.locator`, and `[[peers]]`.

Optional systemd unit (`systemd/conet-l0d.service`):

```bash
sudo cp systemd/conet-l0d.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now conet-l0d
```

The unit must call `conet-l0d start` / `stop`. Do not put raw `iptables` in the unit.

## Client flags (advertise only)

Authorized L0_ONLY `.45` points geth / beacon advertise flags at the overlay **vIP**. `.98` and production proposers keep the public IP. Do not bind Engine or HTTP to the vIP.

```bash
geth --nat extip:100.64.0.5 --bootnodes "enode://<peer-key>@100.64.0.1:8400" \
  --http.addr 127.0.0.1 --authrpc.addr 127.0.0.1 --port 8400

beacon-chain --p2p-host-ip=100.64.0.5 --p2p-tcp-port=4200 --p2p-udp-port=4300 \
  --rpc-host=127.0.0.1 --grpc-gateway-host=127.0.0.1
```

Advertise-only flags do **not** stop the clients when the TUN is down. Binding `--http.addr`, `--authrpc.addr`, `--p2p-local-ip`, or `--rpc-host` to the overlay vIP can fail startup. Details: [docs/operator-flags.md](docs/operator-flags.md).

Phase 1 uses **static** overlay peers. The crate envelope already carries IPv4 including UDP. A lab may prove overlay UDP / DHT-port comms and live discv5 via L0 ([docs/P2.md](docs/P2.md)); that is not a production discv5 product.

## Safety

- First iptables rules: `RETURN` `127.0.0.0/8` (Engine JWT, beacon gRPC, local RPC).
- Optional `validator_uid` is never captured.
- Never REDIRECT `0.0.0.0/0:8400` or the whole public P2P space.
- This process does not restart geth, beacon, or validator.
- Do not invent a new public hostname for this product.

## Documentation

| Document | Role |
| --- | --- |
| [Whitepaper (EN)](whitepaper/conet-l0d.md) | Design (canonical technical wording) |
| [白皮书（简体中文）](whitepaper/conet-l0d.zh-CN.md) | Paired translation |
| [MVP](docs/MVP.md) · [MVP（中文）](docs/MVP.zh-CN.md) | Accepted crate MVP |
| [P1](docs/P1.md) · [P1（中文）](docs/P1.zh-CN.md) | Overlay `/post` encrypt + mailbox wrap + POST; inbound decrypt + TUN write-back; EIP-191 listen worker; SI gossip JSON ingest; `[l0]` default off; authorized lab may enable `[l0]`; 2026-08-18: `.45` advertises overlay vIP; overlay geth + beacon TCP; CL initial-sync in progress |
| `systemd/conet-l0d-gateway.service` | Optional gateway-only unit; no `CAP_NET_ADMIN`, TUN, or iptables |
| [P2](docs/P2.md) · [P2（中文）](docs/P2.zh-CN.md) | Lab overlay UDP / DHT-port comms (echo + `:4300` + public-ENR steer + live discv5 via L0). Not a closed P2 / production product |
| [Lab overlay QoS 2026-08-18](docs/lab-overlay-qos-2026-08-18.md) | Both-end log + TUN + TCP quality snapshot (~15 min). Mailbox path lossless; overlay RTT ~500 ms; hub TUN `tx_dropped=937`. Not a protocol change |
| [Operator flags](docs/operator-flags.md) | geth / beacon advertise flags |
| [RULES.md](RULES.md) | Engineering constraints |
| [GitBook Applications](https://gitbook.conet.network/applications/conet-l0d.html) | Operator how-to |
| [GitBook Developers](https://gitbook.conet.network/developers/conet-l0d.html) | CLI, config, wire contract |
| [How to use Layer Minus](https://gitbook.conet.network/l0/using-l0.html) | L0 forwarding plane |
| [Run an L1 node](https://gitbook.conet.network/developers/l1-node.html) | Public P2P (production default) |

A change to the whitepaper, `RULES.md`, or MVP must update **both** GitBook pages in the same task.

## What this revision does / does not

**Does:** overlay vIP table, `web3://` locator parse, TUN + iptables lifecycle, packet counters, **application duplex** on Chat gossip (offer / accept / AES `duplex_frame`) when the peer app accepts, **P1 gossip** fallback otherwise, dest-aggregated IPv4 batch in `ipv4` (POST concurrency 32 / queue 2048; inbound TUN write queue 1024), inbound decrypt + TUN write queue when `routing_key_file` is set, listen HTTP+SSE workers when enabled plus `listen_entries`, `mailbox_route_pgp_file`, `routing_eoa`, `routing_key_file`, and `routing_eth_key_file`. Optional `[[l0.channels]]` is one routing EOA + SSE per overlay port (8400 / 4200 / 4300). Listen ingest accepts SI gossip JSON `{ "data": "<armor>" }` and duplex frames. An authorized lab may enable `[l0]`.

**Does not (yet):** finish L0-only follow-the-chain (2026-08-18: overlay TCP proven; after the batching binary the limiter is Prysm initial-sync at ~3.2 blocks/s, ~15 h; `.45` EL still `0x0`; watch with `scripts/watch-l0-follow.sh`), production mailbox delivery, production discv4 / discv5 (lab discv5 via L0 is accepted — [docs/P2.md](docs/P2.md); if `connected` drops, `overlay-dht-steer.sh apply` first; authorized `.45` `restart-beacon` only after dial backoff; after DNAT, `.45` `ss` may show hub public `:4200` — original dest, not a leak), validator proxying. Do **not** treat SI `duplex_*` or `p2p_stream_*` as current SI. The crate never restarts geth/beacon; an authorized operator script may restart only the named lab host.

## License

[MIT](LICENSE) © 2026 CoNET / Beamio

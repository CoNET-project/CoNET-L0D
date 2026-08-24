## Client and proxy transport modes

`--client web3://<mainWallet>:<port>` is the default P1 request/response
client. `--clientDuplex` is the explicit persistent bidirectional stream mode.
The client daemon selects a local VIP automatically when `local_vip = "auto"`
and prints the resulting `web3://... -> VIP:port` mapping.

On a server, `--proxy HOST:PORT` is request/response configuration and
`--proxyDuplex HOST:PORT` is raw bidirectional forwarding. A proxy-only daemon
does not create a TUN, route, or iptables chain. The same logical port cannot be
configured in both proxy modes.
# MVP — conet-l0d

**Paired:** [中文](./MVP.zh-CN.md)  
**Revision:** 2026-08-24 (`DuplexLineRole` gates proxy upstream; `web3://…:port@local`; dynamic proxy lines, main-wallet billing, per-line temporary identities)

Public how-to: [Applications](https://gitbook.conet.network/applications/conet-l0d.html) · [Developers](https://gitbook.conet.network/developers/conet-l0d.html)

## Goal

Ship an independent **Linux command** `conet-l0d` that operators can start and stop. Start creates TUN + iptables. Stop/teardown removes **only** those objects. No hand-written `iptables`.

## In scope

| Item | Acceptance |
| --- | --- |
| Binary | `cargo build --release` → `conet-l0d` |
| `check-config` / `resolve` | Work on any OS; exact `web3://` parse |
| `start` | Linux + `CAP_NET_ADMIN`: TUN `conet-l0`, `/32` local vIP, route `100.64.0.0/10`, chain `CONET_L0D` with loopback `RETURN` |
| `stop` / SIGINT / SIGTERM | Reverse of start; pid from state file |
| `teardown` | Same reverse path if the daemon is dead |
| Packet loop | Count IPv4 packets on the TUN; log dest vIP (no secrets) |
| L0 | Crate stub accepted: count TUN IPv4 and log dest vIP. Live overlay `/post` prefers **SI `l0_listen` / `l0_connect` occupancy pipe + application duplex** (offer on Chat gossip; accept / reject / frames as AES on the occupied pipe); P1 gossip on `duplex_reject` or missing `duplex_accept` or missing pipe — [P1](./P1.md). Do not claim SI `duplex_*` or `p2p_stream_*` |
| Docs | Whitepaper pair + these MVP pages + GitBook Applications + Developers |
| Example + unit | `config/conet-l0d.example.toml` and `systemd/conet-l0d.service` (`start`/`stop` only) |

## Dynamic proxy lines

Server mode may configure `[[l0.proxies]]` targets. `billing_eoa` and its
local `billing_eth_key_file` sign duplex offer/accept (peer-verified). Mailbox
`l0_listen` / `l0_connect` are signed by each channel wallet until SI fleets
ship `billingWallet`. Each line still uses a distinct temporary wallet/PGP/AES
session identity after `mainWallet:port` match. The temporary identity is
registered before routing and is released on any transport failure. Multiple
clients may use one logical port, but never share a line identity or pipe.
Occupied bytes are copied to the configured `host:port`; offline data is
discarded.

For `--clientDuplex`, the local TCP listener is connection-driven rather than
port-driven. Every new `accept()` event is a new socket handle and the
explicit `mainWallet:port` new-line request allocates its fresh temporary
wallet/PGP route, AES key, local return queue, and duplex offer before offer
processing. The same socket keeps using that line until EOF or error; a
second socket to the same `127.0.0.1:<port>` receives a different line. L0d
does not add a private header to Geth/Prysm bytes: the accepted socket handle
and encrypted `pipe_handle` are the correlation mechanism.

**Role gate:** `maybe_start_proxy_drain` attaches local upstream only for
`DuplexLineRole::Proxy` sessions (inbound proxy handshake). `client_duplex`
sessions are `Peer` and must not dial local geth/beacon just because they
share a logical port with `proxy_duplex`.

**Local bind:** `l0.client_duplex` accepts `web3://<billing>:8400@18400`
(and `:4200@14200`). `@local` is an explicit listen port; without it the
daemon tries `port` then `port+10000`. Dialed `mainWallet` must be the peer
`billing_eoa`.


Proxy-only servers (`[[l0.proxies]]` and no `l0.clients` / `--client`) do not
create TUN or iptables. Each explicit new-line request creates a separate
upstream raw stream to its configured `host:port`; same-port connections remain
isolated. An incoming `duplex_offer` is attach-only: it may bind an existing
`pipe_handle` or temporary `listenWallet`, but an unknown, stale, or ambiguous
offer is rejected and never creates a wallet, session, or `l0_connect`.
Multi-port proxy must configure one `[[l0.channels]]` routing EOA per port
(SI exclusive occupy); offer matching still uses `billing_eoa` as `mainWallet`.
Legacy `--client` keeps the packet/TUN path. `--clientDuplex` uses the local
TCP listener and allocates lines only when applications actually connect.

### Beacon over a TUN-less duplex listener

When `conet-l0d` exposes a local duplex listener (for example
`127.0.0.1:14200` for Beacon), the Beacon process must use the local stream
peer, not the other client's VIP or a public ENR. The lab operator scripts
support `L0_STREAM_ONLY=1` for this mode. It keeps only the explicitly supplied
`EXTRA_BEACON_PEERS`, adds `--no-discovery` and `--disable-quic`, and does not
require TUN, iptables, DHT steering, or listen-DNAT. Explicit command-line
peer values take precedence over host environment defaults, so stale `.98`
peers cannot replace the `.82` stream target.

## Out of scope (not a failed MVP)

- Production mailbox delivery (P1 crate can POST existing `/post` and ingest SI gossip JSON `{ "data": "<armor>" }`; an authorized lab may enable `[l0]`; 2026-08-18 lab advertises overlay vIP on `.45`, completed overlay geth + beacon TCP; after the batching binary the limiter is Prysm initial-sync at ~3.2 blocks/s; EL still `0x0`; watch `scripts/watch-l0-follow.sh` — see [P1.md](./P1.md))
- Production discv4 / discv5 (lab overlay UDP + live discv5 via L0: [P2.md](./P2.md); drop recovery is `overlay-dht-steer.sh apply` first; authorized `.45` `restart-beacon` only after dial backoff; after DNAT, `.45` `ss` may show hub public `:4200` — original dest, not a leak; not a closed P2 / production product)
- Validator proxy or keystore access
- New SI hostnames. Overlay duplex is application JSON on Chat gossip; do not invent SI `duplex_*` or `p2p_stream_*`
- The crate restarting geth / beacon / validator (an authorized **operator** script may restart **only** `.45` for L0_ONLY; never `.98` unless that host is authorized; never wipe)

## Commands

```bash
conet-l0d check-config --config config/conet-l0d.example.toml
conet-l0d resolve 'web3://0x1111111111111111111111111111111111111111/p2p/geth'
sudo conet-l0d start --config /etc/conet-l0d.toml
sudo conet-l0d stop --config /etc/conet-l0d.toml
sudo conet-l0d teardown --config /etc/conet-l0d.toml
conet-l0d status --config /etc/conet-l0d.toml
```

## Tests

```bash
cargo test
```

`resolve` / config unit tests must pass on macOS. `start` is Linux-only.

## Sync rule

If this file, the whitepaper, or `RULES.md` changes, update GitBook **Applications** and **Developers** `conet-l0d` pages in the same task.

## Duplex bootstrap payloads

For `--clientDuplex`, a local TCP accept event creates the unique session
handle. Its initial application bytes are carried in the control offer as
`firstChunk`, but the offer is not sent until the per-socket temporary route is
registered, visible on AddressPGP `searchKey` (HTTP 200 is not enough), and
its `l0_listen` SSE is ready. A matching `--proxyDuplex`
endpoint verifies the signed billing wallet and exact `mainWallet:port`,
registers its own temporary route, and waits for its listen SSE before opening
one upstream socket. It writes the first chunk, includes the first upstream
response as `responseChunk` in `duplex_accept`, reverse-occupies the
initiator listen only if that return pipe is still empty, then resumes the
upstream socket. It does not wait for a second local protocol chunk. The
initiator decrypts the accept, writes `responseChunk` to the local socket,
and occupies immediately (an empty first AES blob is allowed). All subsequent
bytes are framed on the established `pipe_handle`; unsigned, stale,
ambiguous, or unmatched offers must not allocate a line.

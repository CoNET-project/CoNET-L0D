# MVP — conet-l0d

**Paired:** [中文](./MVP.zh-CN.md)  
**Revision:** 2026-08-21 (dynamic proxy lines, main-wallet billing, per-line temporary identities)

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

Proxy-only servers (`[[l0.proxies]]` and no `l0.clients` / `--client`) still
create TUN + iptables: current clients seal IPv4 on the occupy pipe. Proxy
upstream copy applies to **non-IPv4** stream bytes; IPv4 frames write to TUN.
Multi-port proxy must configure one `[[l0.channels]]` routing EOA per port
(SI exclusive occupy); offer matching still uses `billing_eoa` as `mainWallet`.
Clients use `--client 'web3://<peerMainWallet>:port'` to seed a pending duplex
line toward that peer VIP:port while keeping TUN for local geth/beacon.

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

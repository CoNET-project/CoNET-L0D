# MVP — conet-l0d

**Paired:** [中文](./MVP.zh-CN.md)  
**Revision:** 2026-08-18 (crate MVP still accepted; authorized L0_ONLY `.45` advertises overlay vIP; overlay geth + beacon TCP proven; follow-the-chain Prysm-bound — see [P1.md](./P1.md); DHT drop recovery and ~17:28Z `restart-beacon` in [P2.md](./P2.md))

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
| L0 | Crate stub accepted: count TUN IPv4 and log dest vIP. Do not claim a live SI `p2p_stream_*` command. Live `/post` stream is [P1](./P1.md) |
| Docs | Whitepaper pair + these MVP pages + GitBook Applications + Developers |
| Example + unit | `config/conet-l0d.example.toml` and `systemd/conet-l0d.service` (`start`/`stop` only) |

## Out of scope (not a failed MVP)

- Production mailbox delivery (P1 crate can POST existing `/post` and ingest SI gossip JSON `{ "data": "<armor>" }`; an authorized lab may enable `[l0]`; 2026-08-18 lab advertises overlay vIP on `.45`, completed overlay geth + beacon TCP; after the batching binary the limiter is Prysm initial-sync at ~3.2 blocks/s; EL still `0x0`; watch `scripts/watch-l0-follow.sh` — see [P1.md](./P1.md))
- Production discv4 / discv5 (lab overlay UDP + live discv5 via L0: [P2.md](./P2.md); drop recovery is `overlay-dht-steer.sh apply` first; authorized `.45` `restart-beacon` only after dial backoff; after DNAT, `.45` `ss` may show hub public `:4200` — original dest, not a leak; not a closed P2 / production product)
- Validator proxy or keystore access
- New SI commands or new hostnames
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

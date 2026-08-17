# MVP — conet-l0d

**Paired:** [中文](./MVP.zh-CN.md)  
**Revision:** 2026-08-17 (lockstep with whitepaper)

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
| L0 | Stub only — do not claim a live SI `p2p_stream_*` command |
| Docs | Whitepaper pair + these MVP pages + GitBook Applications + Developers |
| Example + unit | `config/conet-l0d.example.toml` and `systemd/conet-l0d.service` (`start`/`stop` only) |

## Out of scope (not a failed MVP)

- Live AddressPGP RPC / OpenPGP `/post` byte stream
- UDP discv4 / discv5 capture
- Validator proxy or keystore access
- New SI commands or new hostnames
- Restarting geth / beacon / validator

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

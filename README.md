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

**Maturity: under development.** The CLI, locator grammar, and TUN / iptables lifecycle are implemented. Overlay TCP over live production SI is a stub. Keep public P2P (geth `8400`, beacon `4200` / `4300`) for the 6-second slot.

## What it is not

| Other product | Difference |
| --- | --- |
| SilentPass / `SaaS_Sock5` | Device or app **egress** to a public `host:port`. Not L1 consensus P2P. |
| Current L0 UDP forward | AES frames over HTTP / SSE — not raw OS UDP, not discv4. |
| Validator client | Talks only to the **local** beacon. Do not capture its uid or read its keystore. |

Layer Minus stays a PGP / wallet-address forwarding plane. HTTP `/post` is only `{ "data": "<OpenPGP armor>" }`. This crate is an **application composition**, not a second IP network and not a new SI command.

There is **no** live SI command named `p2p_stream_*` or `listenKind: "l1p2p"` in this revision.

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

`check-config`, `resolve`, and `status` run on any OS. `start` / `stop` / `teardown` need Linux, `ip`, `iptables`, and `CAP_NET_ADMIN` (usually `sudo`).

## Commands

```bash
conet-l0d check-config --config config/conet-l0d.example.toml
conet-l0d resolve 'web3://0x1111111111111111111111111111111111111111/p2p/geth'
conet-l0d status --config /etc/conet-l0d.toml
sudo conet-l0d start --config /etc/conet-l0d.toml
sudo conet-l0d stop --config /etc/conet-l0d.toml
sudo conet-l0d teardown --config /etc/conet-l0d.toml
```

Copy `config/conet-l0d.example.toml` to `/etc/conet-l0d.toml` and set `local_vip`, `identity.locator`, and `[[peers]]`.

Optional systemd unit (`systemd/conet-l0d.service`):

```bash
sudo cp systemd/conet-l0d.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now conet-l0d
```

The unit must call `conet-l0d start` / `stop`. Do not put raw `iptables` in the unit.

## Client flags (advertise only)

After the daemon is up, point geth / beacon at the overlay **vIP**. Do not bind Engine or HTTP to it.

```bash
geth --nat extip:100.64.0.5 --bootnodes "enode://<peer-key>@100.64.0.1:8400" \
  --http.addr 127.0.0.1 --authrpc.addr 127.0.0.1 --port 8400

beacon-chain --p2p-host-ip=100.64.0.5 --p2p-tcp-port=4200 --p2p-udp-port=4300 \
  --rpc-host=127.0.0.1 --grpc-gateway-host=127.0.0.1
```

Advertise-only flags do **not** stop the clients when the TUN is down. Binding `--http.addr`, `--authrpc.addr`, `--p2p-local-ip`, or `--rpc-host` to the overlay vIP can fail startup. Details: [docs/operator-flags.md](docs/operator-flags.md).

Phase 1 uses **static** overlay peers. Do not expect discv4 / discv5 to ride L0.

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
| [MVP](docs/MVP.md) · [MVP（中文）](docs/MVP.zh-CN.md) | Current crate acceptance |
| [Operator flags](docs/operator-flags.md) | geth / beacon advertise flags |
| [RULES.md](RULES.md) | Engineering constraints |
| [GitBook Applications](https://gitbook.conet.network/applications/conet-l0d.html) | Operator how-to |
| [GitBook Developers](https://gitbook.conet.network/developers/conet-l0d.html) | CLI, config, wire contract |
| [How to use Layer Minus](https://gitbook.conet.network/l0/using-l0.html) | L0 forwarding plane |
| [Run an L1 node](https://gitbook.conet.network/developers/l1-node.html) | Public P2P (production default) |

A change to the whitepaper, `RULES.md`, or MVP must update **both** GitBook pages in the same task.

## What this revision does / does not

**Does:** overlay vIP table, `web3://` locator parse, TUN + iptables lifecycle, packet counters, L0 client **stub**.

**Does not (yet):** live AddressPGP RPC, OpenPGP `/post` byte-stream, UDP discv4 / discv5 capture, validator proxying.

## License

[MIT](LICENSE) © 2026 CoNET / Beamio

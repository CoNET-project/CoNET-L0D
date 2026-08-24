# CoNET-L0D

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitBook Applications](https://img.shields.io/badge/GitBook-web3%3A%2F%2F-1B67B3)](https://gitbook.conet.network/applications/web3-url.html)
[![GitBook Developers](https://img.shields.io/badge/GitBook-Developers-1B67B3)](https://gitbook.conet.network/developers/conet-l0d.html)

**Repository:** [https://github.com/CoNET-project/CoNET-L0D](https://github.com/CoNET-project/CoNET-L0D)

`web3://` is the **CoNET Web3 Application Protocol**: a wallet-addressed
application locator carried by the Layer Minus (L0) forwarding
infrastructure. It identifies a destination wallet or exact BeamioTag and an
application service without exposing a new public origin.

`conet-l0d` is the Linux runtime for that protocol:

- `--proxy HOST:PORT` publishes a request/response application upstream;
- `--proxyDuplex HOST:PORT` publishes a continuous bidirectional stream;
- `--clientDuplex web3://HOST:PORT` exposes remotes through `127.0.0.1`
  (the same logical port may map to several remotes).

Windows, macOS, iOS, Android, and browser applications do not need the Linux
daemon. They can implement the same `web3://` locator, signed request envelope,
entry selection, mailbox listen, and encrypted response handling in a client
library.

**Maturity:** the locator, Linux runtime, signed web request gateway, and
persistent application-stream path are implemented. The deployed `conet.network` gateway
passed a real Entry → mailbox → origin → encrypted-response acceptance test on
2026-08-20. This acceptance covers the Application Protocol; separate L1
research records do not redefine the public L1 joining path.

## Platform model

| Platform | Recommended implementation |
| --- | --- |
| Linux server | `conet-l0d --proxy` or `--proxyDuplex` |
| Linux client | `conet-l0d --clientDuplex` |
| Browser / Windows / macOS / phone | Client-side `web3://` protocol library using HTTPS/SSE and Web Crypto/OpenPGP |

## What it is not

| Other product | Difference |
| --- | --- |
| SilentPass / `SaaS_Sock5` | Device or app egress to an ordinary Internet destination, not wallet-addressed application hosting |
| L0 UDP forwarding | A separate end-to-end AES frame profile over mailbox relay |
| L1 node operation | A separate geth/Prysm operator track with its own identities and public joining guide |

Layer Minus stays a PGP / wallet-address forwarding plane. HTTP `/post` is
only `{ "data": "<OpenPGP armor>" }`. `web3://` is an application protocol
using that infrastructure, not a replacement forwarding network.

Application duplex uses SI **`l0_listen` / `l0_connect`** occupancy plus
application JSON on Chat gossip and encrypted bytes on the occupied pipe. SI
does **not** implement `duplex_*`; there is no live SI command named
`p2p_stream_*` or `listenKind: "l1p2p"`.

For `--clientDuplex`, the same logical port may map to several remotes;
each remote gets its own `127.0.0.1` listener.
Local TCP is connection-driven. Each
`TcpListener.accept()` event is the sole connection handle; its explicit
`mainWallet:port` new-line request creates a fresh temporary wallet/PGP route,
AES key, return queue, and occupied pipe before offer handling.
The same socket reuses that line until EOF/error; concurrent sockets on the
same local port receive independent lines. Raw application bytes are not
prefixed with a private header; the socket handle and encrypted
`pipe_handle` provide correlation.

## Owned SSE lifecycle

Every inbound SSE is owned by a durable `OwnedListenSession` object. The owner
retains the temporary identity, optional duplex `session_id`, listen kind,
selected entry, cancellation token, and the connection task for the entire
connection lifecycle. `ListenOwnerRegistry` registers owners by a unique
owner id and permits cancellation/removal of one connection without affecting
another.

The global inbound queue is only an event transport: each `InboundChunk`
contains the owner id, optional session id, and payload. It never owns an
anonymous SSE and never performs process-wide AES-key trials. An AES blob
without a bound session id is rejected; a bound blob is decrypted only with
that session's current key. `TemporaryIdentity` is retained by its owning
session and is not reduced to an unowned wallet string.

An SSE EOF/error, session mismatch, malformed AES plaintext, or wrong AES key
cancels that owner and clears the associated occupied-pipe state. Other owner
sessions continue unaffected. Reconnect creates or reuses only the matching
owner lifecycle; stale connection tasks cannot release another owner's pipe.

## Identity (`web3://`)

The URI is an **application locator**, not an ERC-4804 content URL.

```text
web3://0x<40-hex>/dashboard?range=7d
web3://YourExactTag.web3:9443
```

`@beamioTag` must match **exactly** (`CoNET` ≠ `CONET`). Do not take
`search-users` `results[0]`. An AA without AddressPGP is not a destination.

Routing EOA ≠ deposit keystore ≠ fee recipient.

## Build

Requires a stable Rust toolchain (`rust-toolchain.toml`).

```bash
git clone https://github.com/CoNET-project/CoNET-L0D.git
cd CoNET-L0D
cargo test
cargo build --release
# binary: target/release/conet-l0d
install -m 0755 target/release/conet-l0d ~/.local/bin/conet-l0d
```

The Rust binary targets Linux. Browser and desktop/mobile clients can
implement the protocol directly instead of launching this daemon.

## Commands

```bash
conet-l0d check-config --config config/conet-l0d.example.toml
conet-l0d resolve 'web3://0x1111111111111111111111111111111111111111/dashboard?range=7d'
conet-l0d status --config /etc/conet-l0d.toml
conet-l0d start --config /etc/conet-l0d.toml
conet-l0d gateway --config /etc/conet-l0d-gateway.toml
conet-l0d stop --config /etc/conet-l0d.toml
conet-l0d teardown --config /etc/conet-l0d.toml
```

`start` reads `[[l0.proxies]]`, `[[l0.proxy_duplex]]`, and
`[l0].client_duplex` from TOML; equivalent repeatable CLI flags can be used for
an explicit launch.

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

Copy `config/conet-l0d.example.toml` to `/etc/conet-l0d.toml`, set
`identity.locator`, and configure the server proxies or client-duplex targets
needed by the host.

Optional systemd unit (`systemd/conet-l0d.service`):

```bash
sudo cp systemd/conet-l0d.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now conet-l0d
```

The unit calls `conet-l0d start` and `stop`; application endpoint declarations
belong in the TOML file.

## L1 research status

The authorized 2026-08 lab used local endpoints `100.64.0.5` and
`100.64.0.6` to prove Geth TCP, Prysm TCP, UDP echo, DHT-port communication,
and live discv5 across L0. Those addresses are historical overlay endpoint
facts, not a requirement of the Web3 Application Protocol. This experiment
does not make L0 consensus transport the production default.

## Safety

- Bind server upstreams to loopback unless an explicit deployment requires
  another local interface.
- Keep EIP-191 and OpenPGP secret files readable only by the service account.
- Optional `validator_uid` is never captured.
- This process does not restart geth, beacon, or validator.
- Do not invent a new public hostname for this product.

## Documentation

| Document | Role |
| --- | --- |
| [Whitepaper (EN)](whitepaper/conet-l0d.md) | Design (canonical technical wording) |
| [白皮书（简体中文）](whitepaper/conet-l0d.zh-CN.md) | Paired translation |
| [MVP](docs/MVP.md) · [MVP（中文）](docs/MVP.zh-CN.md) | Accepted crate MVP |
| [P1](docs/P1.md) · [P1（中文）](docs/P1.zh-CN.md) | Encrypted `/post`, mailbox listen, request/response, and application-duplex transport |
| `systemd/conet-l0d-gateway.service` | Optional signed web request gateway unit |
| [P2](docs/P2.md) · [P2（中文）](docs/P2.zh-CN.md) | Experimental composition of selected L1 TCP streams over the persistent `web3://` application transport. Not the public L1 joining contract |
| [Operator flags](docs/operator-flags.md) | geth / beacon advertise flags |
| [RULES.md](RULES.md) | Engineering constraints |
| [Web3 Application Protocol](https://gitbook.conet.network/l0/web3-application-protocol.html) | Cross-platform protocol model and browser contract |
| [GitBook Applications](https://gitbook.conet.network/applications/web3-url.html) | `web3://` product and platform overview |
| [GitBook Developers](https://gitbook.conet.network/developers/conet-l0d.html) | Linux CLI and configuration |
| [How to use Layer Minus](https://gitbook.conet.network/l0/using-l0.html) | L0 forwarding infrastructure |
| [Run an L1 node](https://gitbook.conet.network/developers/l1-node.html) | Public P2P (production default) |

A change to the whitepaper, `RULES.md`, or MVP must update **both** GitBook pages in the same task.

## Current scope

The public product surface is:

1. the cross-platform `web3://` application locator and signed wire contract;
2. Linux server publishing through `--proxy` / `--proxyDuplex`;
3. Linux client access through `--clientDuplex`;
4. browser and native client implementations of the same protocol; and
5. the deployed signed HTTP gateway profile.

Production multi-Guardian hosting and production L1 consensus transport are
not yet claimed. Do not treat experimental SI command names as deployed wire
contracts. The crate never restarts geth, beacon, or validator.

## License

[MIT](LICENSE) © 2026 CoNET / Beamio

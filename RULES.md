# conet-l0d — subproject rules

Independent Linux command. Canonical git remote:
[https://github.com/CoNET-project/CoNET-L0D](https://github.com/CoNET-project/CoNET-L0D).
Do not `../..` import BeamioContract, SilentPassUI, CoNET-SI, or x402sdk.

## Product boundary

`web3://` is the CoNET Web3 Application Protocol. It is a wallet-addressed
application locator and signed wire contract carried by Layer Minus (L0).
`conet-l0d` is the Linux server/client runtime for that protocol.

| Platform | Implementation |
| --- | --- |
| Linux server | `--proxy` for request/response; `--proxyDuplex` for continuous streams |
| Linux client | `--clientDuplex web3://HOST:PORT` with one `127.0.0.1` listener per logical port |
| Browser / Windows / macOS / phone | Client-side `web3://` library over HTTPS/SSE, OpenPGP, and Web Crypto |

The daemon does not patch geth, Prysm `beacon-chain`, or `validator`. It must
never read validator keystores or restart chain infrastructure.

## Locator and identities

`web3://` is an application locator, not ERC-4804 content:

```text
web3://0x<40-hex>/service/path
web3://ExactBeamioTag.web3/service/path
```

BeamioTag matching is exact (`CoNET` ≠ `CONET`). Never select
`search-users.results[0]` without an exact identity match. The destination must
have a usable AddressPGP identity.

Keep these roles separate:

- application destination EOA;
- communication route identity;
- main paid wallet (`billing_eoa`);
- validator deposit keystore;
- fee recipient.

## Server proxy modes

Each `[[l0.proxies]]` or `--proxy` entry maps a logical application port to a
request/response upstream `host:port`.

Each `[[l0.proxy_duplex]]` or `--proxyDuplex` entry maps a logical application
port to a persistent bidirectional upstream. A duplex line is allocated only
after an explicit signed new-line request addressed to `mainWallet:port`.

Every line has its own:

- temporary wallet and OpenPGP route identity;
- AES key;
- opaque `pipe_handle`;
- occupied socket;
- bounded byte queues.

Temporary identities are memory-only and are **not** registered in AddressPGP.
The client announces the mailbox SI (route PGP + node wallet) that accepted
its `l0_listen` SSE inside `duplex_offer`. The server's accept packet carries
the mailbox SI of its own temporary SSE. Entry SI posts wrap the peer's
user-PGP ciphertext with that mailbox SI PGP so forwarding does not need
`searchKey`. Destroyed on EOF, failed HTTP status, timeout, or socket close.
Lines on the same logical port must not share wallets, keys, handles, queues,
or sockets.

The occupied line is a byte transport. Forward bytes unchanged to the
configured upstream with bounded asynchronous bidirectional copying. A failed
line is isolated from all other sessions.

Multi-port publishing (for example `:8400` plus `:4200`) must use one
`[[l0.channels]]` routing EOA per port because SI exclusive occupy is one line
per listen wallet. Collapsing ports onto one identity causes sustained
`l0_connect` HTTP 409 responses.

Inbound `duplex_offer` matching uses `billing_eoa` plus logical port as a
routing lookup. It does not authorize allocation. Attach only to a known,
pre-registered `pipe_handle` or temporary listen wallet. Reject unknown, stale,
or ambiguous offers without creating a session.

A host that is also a client of another wallet's same logical port keeps
those lines in different roles. Every duplex line already has an independent
`pipe_handle` / session map key `(dest, port, session_id)`. Do not treat
`session.port` as a global "this daemon is proxying" switch.

`maybe_start_proxy_drain` may attach a local upstream TCP to `--proxyDuplex`
**only** when the session was allocated by the inbound proxy handshake
(`mainWallet:port` + `firstChunk`) and therefore carries
`DuplexLineRole::Proxy`. Sessions created by `--clientDuplex` /
`l0.client_duplex` are `DuplexLineRole::Peer` and must never dial local
geth/beacon merely because they reuse the same logical application port
(for example client → hub `:4200` while this host also exposes
`proxy_duplex` for `:4200`).

A single daemon **may** run `client_duplex` and `proxy_duplex` together.
Local listen ports for clients must be free OS ports
(`web3://<billing>:8400@18400`, `@14200`, …). Offer matching still uses
`billing_eoa` as `mainWallet`, never the per-port channel `routing_eoa`.

## Client-duplex mode

`--clientDuplex web3://HOST:PORT` (or `[l0].client_duplex`)
exposes a remote application through a local TCP listener on `127.0.0.1`.

The same logical `PORT` may map to several remotes. Repeat the flag for more
lines (`:8400` to hub A and `:8400` to hub B, or `:8400` and `:4200`). The
same `(host, PORT)` listed twice is rejected. Each remote gets its own
`127.0.0.1` listener. The preferred loopback bind is `PORT`. If that port is
occupied, the runtime walks `PORT+10000`, `PORT+20000`, … An optional
Linux-only `@LOCAL` suffix pins the loopback bind and does not walk.

Each `TcpListener.accept()` event is the sole connection handle. A newly
accepted socket receives a fresh temporary wallet, OpenPGP identity, AES key,
opaque `pipe_handle`, return queue, and occupied line. Open `l0_listen` on the
configured mailbox SI without AddressPGP registration; include the temporary
user-PGP key ID so mailbox can index the local SSE pool.

All bytes from that socket stay attached to the same handle until EOF/error.
Return bytes may be written only to that socket. Concurrent sockets on one
local port therefore remain independent. Do not prefix application bytes with
a private header; the accepted socket and encrypted `pipe_handle` provide
correlation.

## firstChunk / responseChunk bootstrap

The client pauses a new local socket after its first bytes, creates exactly
one temporary identity, waits for its temporary `l0_listen` SSE handshake
(mailbox SI wallet), then sends those bytes as `firstChunk` in `duplex_offer`
together with the mailbox SI PGP/wallet. An existing handle must never allocate
a second line.

A duplex proxy may open a line only when the recovered signer, configured
`billingWallet`, `mainWallet:port`, explicit `--proxyDuplex` target, and
non-empty `firstChunk` all match.

The proxy:

1. creates and registers its own temporary route;
2. waits for that route's `l0_listen` SSE;
3. connects the configured upstream and forwards `firstChunk`;
4. pauses after the first upstream reply;
5. returns that reply as `responseChunk` in `duplex_accept`;
6. reverse-occupies the initiator route if its return line is still empty; and
7. starts upstream-to-pipe forwarding.

Do not wait for a second local protocol chunk before establishing both
directions. The client decrypts the accept with its per-socket temporary PGP
key, writes `responseChunk`, then occupies immediately. An empty first AES blob
is valid. Reject unrelated, unsigned, stale, or ambiguous offers.

## Layer Minus wire boundary

HTTP `/post` has exactly one top-level field:

```json
{"data":"<OpenPGP armor>"}
```

Do not add cleartext routing fields or hop-signature headers.

Use the deployed SI commands `l0_listen` and `l0_connect`. Application
`duplex_offer`, `duplex_accept`, `duplex_reject`, and encrypted stream frames
are peer application messages, not SI commands. Do not invent `duplex_*`,
`p2p_stream_*`, or `listenKind: "l1p2p"` SI commands.

The first `duplex_offer` may use the receiver's long-lived user PGP so the
mailbox can route it. The offer carries a dedicated listen-pipe PGP. Encrypt
`duplex_accept` to that `listenUserPgp`; the response carries the receiver's
dedicated listen-pipe PGP and negotiated AES key. After acceptance, both ends
use their dedicated identities for control traffic.

AES keys are memory-only and must never be exposed to a mailbox-decryptable
command. Outbound application data must be either:

- encrypted on an accepted occupied line; or
- encrypted to the destination user PGP and wrapped to mailbox B's route PGP.

Never POST plaintext application data.

## Opaque transport handles

Each line incarnation uses `duplex::new_pipe_handle()`: a random 64-character
lowercase hexadecimal value not derived from wallet, port, IP, or route data.

`l0_pipe_end` is accepted only on the occupied TCP connection that owns the
same handle:

```json
{"type":"l0_pipe_end","pipe_handle":"<64 lowercase hex>","reason":"transport_closed"}
```

The object must not contain `wallet`, `connector`, `sessionId`, or
`session_id`. Reject missing, malformed, or mismatched handles. Do not parse
this object in the SSE ingest path and do not use an `l0_listen_released` SSE
notice. Hop-local failures must not expose cross-hop correlation or end-to-end
AES keys.

Occupy TCP EOF must clear the active sender and enter the same retry path as an
explicit error. Install the sender only after the occupy response is HTTP 200
and remains open. If a healthy exclusive listen is rebuilt while the SSE is
still live, rebuild outbound connects for attached sessions.

## Main-wallet billing for temporary channels

`walletAddress` is the temporary communication identity. `billingWallet` is
the configured paid account and EIP-191 signer. They must never be silently
conflated.

Every mailbox command keeps the communication identity in `walletAddress` and
the paid account in `billingWallet`. The deployed SI verifier recovers against
`billingWallet` while retaining `walletAddress` for routing and mailbox
ownership.

Peer application offers/accepts are also signed by the configured paid
account. When the signer differs from the communication identity, bind both in
the signed command:

```json
{"walletAddress":"<temporary-channel-wallet>","billingWallet":"<main-paid-wallet>"}
```

Each `[[l0.channels]]` entry owns exactly one port. Configure
`[l0].billing_eoa` and `[l0].billing_eth_key_file` for the main paid account.

## Gateway profile

`conet-l0d gateway` receives signed `conet_web3_request_v1` envelopes through
mailbox SSE, validates them, forwards permitted GET/HEAD requests to a loopback
HTTP origin, and posts an encrypted `conet_web3_response_v1` through an Entry
to the requester mailbox.

Gateway requirements:

- secrets are local files with restrictive permissions;
- never pass secrets in CLI arguments, environment variables, logs, or git;
- upstream is loopback by default;
- request/response bodies and timeouts are bounded;
- the inbound mailbox stream is receive-only; and
- the requester receives the response through its own mailbox.

## L1 research boundary

The 2026-08 authorized lab proved Geth TCP, Prysm TCP, UDP echo, DHT-port
traffic, and live discv5 using local overlay endpoints such as `100.64.0.5`
and `100.64.0.6`. These are historical lab facts, not requirements of the
Web3 Application Protocol.

Do not claim L0 as the production slot-critical path until the GitBook
publication gate compares it against public P2P with multi-Guardian and
multi-mailbox diversity. Public L1 joining remains the production default.

Operational recovery belongs in the dedicated beacon recovery rule and
`developers/l1-node.md`; do not duplicate a second playbook here. Never restart
geth, beacon, validator, or wipe chain data without explicit same-message
authorization.

## Lifecycle

| Event | Required behavior |
| --- | --- |
| `start` | Validate configuration, open configured server/client endpoints, start mailbox tasks, then write process state |
| SIGINT / SIGTERM / `stop` | Stop accepting lines, close sessions and listeners, then remove process state |
| `teardown` | Remove stale daemon-owned runtime state after confirming no live process owns it |
| `gateway` | Own only mailbox tasks and the loopback origin adapter |

Cleanup must never delete another process's files or sockets.

## Documentation lockstep

The crate and public GitBook must tell one story:

1. `web3://` is the application protocol over L0;
2. Linux servers/clients may use `conet-l0d`;
3. browsers and Windows/macOS/phone apps may implement the client protocol
   directly; and
4. L1 consensus transport is under development, not the public join default.

When the whitepaper, this file, MVP, CLI, or public wire contract changes,
update in the same task:

- `src/docs/gitbook/applications/web3-url.md` — canonical product and platform page;
- `src/docs/gitbook/l0/web3-application-protocol.md` — canonical protocol;
- `src/docs/gitbook/developers/conet-l0d.md` — Linux CLI/config reference;
- `src/docs/gitbook/developers/l1-node.md` — only if L1 status changes; and
- `SUMMARY.md`, section indexes, `l0/using-l0.md`, and `resources.md`.

Do not duplicate the same setup steps across Applications, Developers, and L0
protocol pages. Link to the canonical page instead.

If an SI command or `/post` contract changes, also update the L0 protocol and
SI developer pages required by the global DePIN GitBook sync rule.

Do not run `src/docs/scripts/deployGitbook.sh` unless the user requests a
deployment.

## Build

```bash
cargo test
cargo build --release
```

Keep `cargo fmt --check`, `cargo clippy --all-targets --all-features`, and tests
green. Tests use local mocks/wiremock and must not contact production services.

## SI pool discovery
With `l0.si_pool_from_contract = true` (the default), use GuardianNodesInfoV6 discovery rather than requiring static SI URLs. Pool acquisition qualifies TCP `:80`, randomizes candidates, and applies a failure cooldown for future connections. A `pool_full` response is a mailbox-local capacity failure: the current duplex must terminate, while a later APP-created duplex may choose another candidate. Static lists are used only when the pool is disabled or unavailable; do not reintroduce a Chat mining SSE for a pure `--clientDuplex` spoke.

## SSE heartbeat and abandonment

The mailbox SSE lifecycle contract is:

- idle `l0_listen` is kept alive by the SI's `: keepalive` comment every 15 seconds;
- an L0d receiver closes and rebuilds the SSE after 180 seconds without any SSE comment, handshake, or valid frame;
- after `l0_connect`, L0d sends an encrypted `duplex_ping` every 60 seconds and SI reclaims either occupied socket after 180 seconds without input;
- `close`, `error`, EOF, failed writes, and unusable sockets release the local owner and socket;
- retrying a failed listen releases the old temporary identity and local TCP first.
- `pool_full` while establishing `l0_listen` is terminal for that duplex
  incarnation: the worker drops its ready signal, closes the APP TCP socket,
  and does not repeat the same 3-second POST.
- Any `l0_connect` occupation failure is also terminal for that duplex
  incarnation. Both sides discard the pipe handle/session; the peer receives
  an encrypted `duplex_reject` with `reason=pipe_failed` and
  `retryable=true` when a final control delivery is possible. Only the APP may
  create a new duplex.

The 180-second rule is a receive-side contract. A successful one-way SSE write is
not an application acknowledgement of a remote peer; TCP keepalive and close/error
events remain part of remote-exit cleanup.

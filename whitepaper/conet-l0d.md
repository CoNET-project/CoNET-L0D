# `web3://` over CoNET Layer Minus

Linux runtime, cross-platform client contract, and application gateway

Paired Chinese version: [`conet-l0d.zh-CN.md`](conet-l0d.zh-CN.md)

Revision: 2026-08-22

## Abstract

`web3://` is a wallet-addressed application protocol built on CoNET Layer
Minus (L0). It gives an application a stable cryptographic destination while
L0 supplies encrypted entry routing, mailbox delivery, and bidirectional
transport.

`conet-l0d` is the Linux runtime for this protocol. A Linux server can publish
a local service with `--proxy` or `--proxyDuplex`; a Linux client can expose a
remote `web3://` service through a local endpoint with `--clientDuplex`.
Windows, macOS, Android, and iOS do not need to run the Linux daemon. Browser
extensions, web applications, and native applications can implement the same
locator, caller-signed request, encrypted response correlation, and stream
contract in client code.

The protocol composes existing L0 primitives. It does not introduce a second
network, a new SI command family, or a replacement for the public CoNET L1
node-joining path.

## 1. Problem

Internet applications normally expose a DNS name, public origin, and
certificate-bound server identity. This makes the origin easy to locate and
ties application naming to conventional hosting.

CoNET already provides a different foundation:

- wallet and OpenPGP identities;
- encrypted entry routing;
- mailbox delivery;
- persistent receive sessions; and
- sender-to-recipient application encryption.

What applications need above that foundation is a small, explicit contract
for naming a destination, opening a session, carrying requests or streams,
and returning a response to the authenticated caller.

## 2. Layered model

```text
Application
  web3:// URI, request or stream semantics, errors
                         │
Client implementation
  browser / native library / conet-l0d
                         │
Layer Minus
  entry A/C, mailbox B, OpenPGP routing, SSE/duplex delivery
                         │
Local server adapter
  conet-l0d proxy or application gateway
                         │
Origin service
  HTTP API, WebSocket, or TCP service on localhost/private network
```

Each layer has one responsibility:

| Layer | Responsibility |
|---|---|
| L0 | Encrypted wallet-addressed transport |
| `web3://` | Application destination and session contract |
| `conet-l0d` | Linux server/client adapter |
| Browser/native client | Cross-platform user-facing implementation |
| Origin | Existing application logic |

The application protocol does not change the L0 HTTP envelope. Entry requests
continue to contain only `{ "data": "<OpenPGP armor>" }`.

## 3. Product roles by platform

| Platform | Recommended role |
|---|---|
| Linux server | Publish a local service with `conet-l0d --proxy` or `--proxyDuplex` |
| Linux client | Reach remotes with `conet-l0d --clientDuplex` (same logical port may map to several remotes) |
| Windows / macOS | Browser extension, browser client, or native client implementing `web3://` |
| Android / iOS | Web or native client using the same protocol over HTTPS/SSE |
| Browser | Parse, sign, encrypt, send, receive, decrypt, and render without a Linux daemon |

This separation keeps the protocol platform-neutral while providing a
production-oriented Linux reference runtime.

## 4. Destination grammar

The current Linux runtime accepts wallet-addressed endpoints:

```text
web3://0x<40-hex>:<port>
web3://<exact-tag>.web3:<port>
```

Examples:

```text
web3://0x1111111111111111111111111111111111111111:443
web3://ExampleMerchant.web3:9443
```

The host identifies the remote application owner. The port identifies a
logical application service. Exact tag resolution is required; a prefix
search result must never be selected implicitly.

A browser-facing resource adds a path and query:

```text
web3://0x1111111111111111111111111111111111111111/dashboard?range=7d
```

The signed request carries the canonical target, path, and query. Human-readable
aliases may be presented by clients, but they resolve to an exact wallet
identity before encryption.

The repository also recognizes `/p2p/geth` and `/p2p/beacon` peer locators for
controlled L1 experiments. Those locators are one application composition,
not the definition of the general protocol.

## 5. Session profiles

### 5.1 Request/response

`--proxy HOST:PORT` publishes a local request/response upstream. A signed
application request is routed to the wallet destination, validated by the
server adapter, forwarded to the configured origin, and encrypted back to the
requester's registered user PGP key.

This profile is suitable for bounded HTTP-style operations.

### 5.2 Persistent duplex

`--proxyDuplex HOST:PORT` publishes a continuous bidirectional TCP service.
`--clientDuplex web3://HOST:PORT` exposes the selected remote
service through a `127.0.0.1` TCP endpoint. The same logical port may map to
several remotes; each remote gets its own loopback listener. The preferred
bind is `PORT`; if occupied, the runtime walks `PORT+10000`, `PORT+20000`,
…. The same `(host, PORT)` listed twice is rejected.

Each accepted local connection creates a distinct application session:

```text
local TCP connection
    → duplex offer
    → remote acceptance
    → bidirectional encrypted frames
    → explicit close or reconnect
```

Session identifiers, ordering, limits, and teardown belong to the application
stream contract. L0 supplies transport; it does not interpret the origin
protocol.

## 6. Signed web request gateway

The `conet-l0d gateway` profile maps a wallet-addressed request to a loopback
HTTP origin.

The implemented v1 request includes:

- `type = "conet_web3_request_v1"`;
- a unique `requestId`;
- caller wallet `from`;
- `target = web3://<gateway-eoa>/...`;
- method, path, query, selected headers, and optional body;
- nonce and expiry; and
- an EIP-191 signature over the canonical request JSON.

The gateway:

1. decrypts the request with its user PGP key;
2. checks version, expiry, method, path, target, and signature;
3. forwards only to a configured loopback origin;
4. bounds request and response sizes and execution time;
5. encrypts `conet_web3_response_v1` to the caller's registered user PGP key;
6. sends the response through ordinary L0 entries.

The current gateway restricts methods to `GET` and `HEAD`. Broader methods,
delegation, payments, and origin identity headers require a later protocol
revision rather than undocumented behavior.

## 7. L0 routing and privacy

The protocol follows the existing A/B/C mailbox model:

| Action | Encryption target | Network entry |
|---|---|---|
| Application delivery | Recipient user PGP | Healthy entry A, distinct from mailbox B |
| Receive/listen command | Mailbox B route PGP | Healthy entry C, distinct from B |
| Response | Caller user PGP | Healthy entry selected by the responder |

Entry and mailbox nodes receive only the information required for routing.
They do not become trusted application origins and must not gain plaintext
request bodies.

Clients must not optimize by directly connecting to mailbox B. Direct mailbox
access reveals routing placement and diverges from the protocol's privacy
model.

## 8. Identity and authorization

`web3://` binds application access to cryptographic identity:

1. the target resolves to an exact wallet;
2. the payload is encrypted to the target's user PGP key;
3. the request is signed by the caller EOA;
4. the server validates that signature and target;
5. the response is encrypted to the caller's user PGP key.

An application may add its own authorization policy after identity
verification. The protocol proves who signed the request; it does not grant
every signer access to every resource.

Private keys, complete PGP ciphertexts, and plaintext application bodies must
not be written to logs.

## 9. Linux runtime configuration

The public configuration centers on application endpoints:

```toml
[l0]
entries = ["https://example-entry.conet.network"]
listen_entries = ["https://another-entry.conet.network"]
routing_eoa = "0x..."
routing_key_file = "/etc/conet-l0d/app-secret.asc"
routing_eth_key_file = "/etc/conet-l0d/app-eip191.key"
mailbox_route_pgp_file = "/etc/conet-l0d/mailbox-route-public.asc"
client_duplex = ["web3://ExactPeer.web3:9443"]

[[l0.proxy_duplex]]
host = "127.0.0.1"
port = 9443
```

Operators should keep origin services on loopback or a private network and
publish only the intended logical ports.

## 10. Lifecycle and observability

The Linux runtime exposes:

| Command | Purpose |
|---|---|
| `check-config` | Validate configuration without opening sessions |
| `resolve` | Parse and resolve a `web3://` locator |
| `start` | Run configured server proxies and client endpoints |
| `gateway` | Run the signed web request gateway |
| `status` | Report recorded runtime state |
| `stop` | Signal the recorded process and clean runtime state |
| `teardown` | Remove stale daemon-owned runtime state |

Useful evidence includes:

- exact wallet or tag resolution;
- published and local endpoint addresses;
- accepted request or duplex session IDs;
- encrypted frame counters and bounded queue status;
- response status or stream close reason; and
- reconnect attempts.

A process being alive is not proof that an application request or stream
completed.

## 11. Failure model

Clients and operators should distinguish:

| Failure | Meaning |
|---|---|
| Locator resolution fails | Destination is invalid, ambiguous, or unregistered |
| Entry request fails | Selected entry is unavailable; try another healthy entry |
| Mailbox rejects routing | Destination route does not match that mailbox |
| Signature fails | Caller identity or canonical request bytes do not match |
| Origin connect fails | Published local service is unavailable |
| Stream closes | Reconnect according to bounded client policy |
| Response timeout | No trustworthy application response was completed |

Transport failure must not be converted into a successful empty response.
Applications preserve their last trusted data according to their own cache
policy.

## 12. Optional L1 composition

Selected geth or Prysm TCP streams can be used as a controlled Linux-to-Linux
duplex experiment. This composition:

- reuses the same wallet destination and stream contract;
- preserves geth and Prysm identities;
- requires independent verification at the L1 client layer; and
- remains separate from the public L1 node-joining guide.

It does not mean that CoNET L1 consensus has generally moved to L0. See
[`docs/P2.md`](../docs/P2.md) for the bounded laboratory record.

## 13. Maturity

| Capability | Status |
|---|---|
| Wallet/tag locator parsing | Implemented |
| Linux request/response proxy | Implemented |
| Linux duplex server/client runtime | Implemented |
| Signed v1 GET/HEAD gateway | Implemented |
| Browser extension/client composition | Early implementation / evolving |
| Cross-platform protocol SDK | Destination |
| Delegation, payment scopes, formal canonical-byte specification | Draft |
| L1 TCP composition | Laboratory-proven, not the public default |

Documentation must preserve these distinctions. A working locator or Linux
runtime is not proof that every browser feature or future protocol extension
is production-ready.

## 14. Non-goals

The protocol is not:

- a general-purpose network interface;
- a VPN product;
- a new public SI command family;
- a reason to expose origin services directly;
- a replacement for TLS on ordinary web endpoints;
- a replacement for the public L1 P2P joining path; or
- permission to invent new domains or centralized routing services.

## Conclusion

The durable abstraction is the application protocol, not one operating-system
adapter. Layer Minus supplies private wallet-addressed transport;
`web3://` defines how applications name and exchange data; `conet-l0d`
provides the Linux runtime; and browser or native clients provide the
cross-platform user experience.

### GuardianNodesInfoV6 SI selection
The default SI transport is an on-chain pool. The daemon pages GuardianNodesInfoV6 through the configured RPC, randomizes candidates, performs a bounded TCP port-80 qualification, and cools failures before retrying. Static entries are optional for pool-off deployments. This transport selection is independent of duplex line roles: a pure clientDuplex spoke avoids a permanent Chat SSE while preserving its exclusive `l0_listen` ownership.

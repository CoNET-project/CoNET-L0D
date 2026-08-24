# `web3://` application runtime — MVP

Paired Chinese version: [`MVP.zh-CN.md`](MVP.zh-CN.md)

Revision: 2026-08-22

## 1. Product boundary

`web3://` is a wallet-addressed application protocol built on CoNET Layer Minus
(L0). It gives applications a stable destination name while L0 supplies
encrypted entry routing, mailbox delivery, and bidirectional transport.

`conet-l0d` is the Linux runtime for that protocol:

- Linux servers publish local services with `--proxy` or `--proxyDuplex`;
- Linux clients reach a `web3://<wallet-or-tag>:<port>` destination with
  `--clientDuplex`;
- browsers and native applications on Windows, macOS, Android, and iOS
  implement the same application protocol in client code and use existing L0
  entries. They do not need the Linux daemon.

The public L1 node joining path remains the existing public P2P path.
Carrying selected L1 streams through L0 is a separate, experimental use of the
same application transport.

## 2. MVP capabilities

### 2.1 Addressing

The runtime accepts explicit wallet-addressed targets:

```text
web3://0x1111111111111111111111111111111111111111:4200
web3://ExactTag.web3:4200
```

An EOA is the unambiguous destination. A BeamioTag is resolved by exact
case-sensitive match; ambiguous search results are rejected.

The application locator, billing wallet, communication identity, validator
identity, and fee recipient are separate roles.

### 2.2 Linux server profiles

Request/response services use:

```bash
conet-l0d start \
  --mainWallet 0x<main-paid-wallet> \
  --proxy 127.0.0.1:8080 \
  --config /etc/conet-l0d.toml
```

Continuous bidirectional services use:

```bash
conet-l0d start \
  --mainWallet 0x<main-paid-wallet> \
  --proxyDuplex 127.0.0.1:4200 \
  --config /etc/conet-l0d.toml
```

`--proxy` carries bounded request/response exchanges.
`--proxyDuplex` carries a persistent raw byte stream and preserves write order.

### 2.3 Linux client profile

```bash
conet-l0d start \
  --mainWallet 0x<main-paid-wallet> \
  --clientDuplex web3://0x<destination-wallet>:4200 \
  --config /etc/conet-l0d.toml
```

Each `--clientDuplex` target creates one `127.0.0.1` TCP
endpoint. The same logical port may map to several remotes; each remote
gets its own loopback listener. The daemon opens a
paid L0 line to that destination and forwards bytes in both directions until
either side closes.

### 2.4 Browser and native clients

A browser or native client performs the same protocol steps directly:

1. parse the `web3://` destination;
2. resolve an exact wallet identity;
3. select an existing Entry A for outbound work and Entry C for mailbox work;
4. encrypt commands for the required user or route key;
5. verify the caller-signed request contract and correlate each decrypted
   response by request ID, nonce, and expiry;
6. preserve the last trusted state when a network attempt fails.

The browser implementation is the portable client path for Windows, macOS,
Android, and iOS. Product code must not expose private keys, session keys,
plaintext payloads, or complete encrypted payloads in logs.

## 3. Runtime-to-L0 mapping

The Linux runtime composes its application profiles from deployed Layer Minus
attachment commands and versioned application messages:

| Application need | Runtime or wire mechanism |
|---|---|
| publish a local request/response service | `--proxy` / `[[l0.proxies]]` runtime profile |
| publish a continuous bidirectional service | `--proxyDuplex` / `[[l0.proxy_duplex]]` runtime profile |
| open a paid line to a destination | deployed SI command `l0_connect` |
| receive a line | deployed SI command `l0_listen` |
| coordinate duplex attachment | application messages `duplex_offer` / `duplex_accept` |
| close an occupied line | `l0_pipe_end` on that line |

`--proxy`, `--proxyDuplex`, and `duplex_*` are not SI commands. They are
`conet-l0d` runtime profiles or peer application messages layered on the
existing L0 attachment contract.

Outbound application work goes through an existing Entry A. Mailbox listen and
route commands go through an existing Entry C. Neither entry is the
destination mailbox B.

The HTTP body remains exactly:

```json
{ "data": "<OpenPGP armor>" }
```

Mailbox instructions are encrypted work packages, never additional plaintext
HTTP fields.

## 4. Identity and billing

The main paid wallet signs paid line commands. Multi-port servers use a
dedicated communication identity per logical port because SI exclusive
occupancy is one line per listen wallet.

Recommended ownership:

| Secret | Recommended owner |
|---|---|
| main wallet signing key | root-only service secret |
| main wallet PGP key | root-only service secret |
| per-port communication EOA key | root-only service secret |
| per-port communication PGP key | root-only service secret |
| mailbox route PGP key | root-only service secret |

No private key is printed in command output or logs.

## 5. Configuration

The public sample is [`../config/conet-l0d.example.toml`](../config/conet-l0d.example.toml).
Its primary profiles are:

```toml
[l0]
enabled = true
client_duplex = [
  "web3://0x<destination-wallet>:4200",
]

[[l0.proxies]]
host = "127.0.0.1"
port = 8080

[[l0.proxy_duplex]]
host = "127.0.0.1"
port = 4200
```

Use separate configuration files for distinct server and client roles in
production.

## 6. CLI contract

```bash
conet-l0d check-config --config /etc/conet-l0d.toml
conet-l0d resolve web3://0x1111111111111111111111111111111111111111:4200 \
  --config /etc/conet-l0d.toml
conet-l0d start --config /etc/conet-l0d.toml
conet-l0d status --config /etc/conet-l0d.toml
conet-l0d stop --config /etc/conet-l0d.toml
conet-l0d teardown --config /etc/conet-l0d.toml
```

`check-config` and `resolve` are non-mutating. `start`, `stop`, and `teardown`
manage only this daemon's runtime state.

## 7. Acceptance criteria

The MVP is accepted when:

1. the example configuration parses and validates;
2. `--proxy` forwards a request and returns the correlated response;
3. `--proxyDuplex` forwards a continuous ordered stream;
4. `--clientDuplex` exposes a local endpoint and reaches the exact
   `web3://` destination;
5. Entry A / Entry C routing and mailbox-B exclusion are enforced;
6. duplicate or stale line control frames do not corrupt another session;
7. `l0_pipe_end` and socket close release line ownership deterministically;
8. process restart does not require restarting the published application;
9. logs contain route and session metadata but no secret material;
10. English and Chinese public documents describe the same protocol.

## 8. Out of scope

- replacing the public L1 node joining path;
- defining a new L0 wire protocol when existing primitives suffice;
- inventing new domains or SI commands;
- embedding billing, validator, or fee-recipient roles into the application
  locator;
- promising generic UDP semantics from a TCP application profile.

## 9. Delivery order

1. exact `web3://` parsing and configuration validation;
2. request/response server profile;
3. duplex server profile;
4. duplex Linux client profile;
5. browser/native client interoperability;
6. replay, reconnect, close, and failure-path tests;
7. optional L1 research profiles after the application path is stable.

## GuardianNodesInfoV6 SI pool
L0 defaults to `si_pool_from_contract = true`. It pages GuardianNodesInfoV6 through the configured RPC, selects a random TCP-`:80`-qualified SI, and cools down failed entries. Static entries are optional fallbacks. This does not change the current duplex line roles or multi-remote local-bind semantics.

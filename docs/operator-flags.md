# geth / beacon advertise flags

These flags **advertise** an overlay IP. They do not bind RPC or Engine to that IP.

Do not run `iptables` yourself. `conet-l0d start` / `stop` owns the chain.

```bash
# Only after a bidirectional overlay frame is proven on the peer TUN.
# Lab hosts keep --nat / --p2p-host-ip on the public IP until then.

geth \
  --port 8400 \
  --discovery.port 8400 \
  --nat extip:100.64.0.5 \
  --bootnodes "enode://<peer-nodekey>@100.64.0.1:8400" \
  --http --http.addr 127.0.0.1 --http.port 8545 \
  --authrpc.addr 127.0.0.1 --authrpc.port 8551 \
  --authrpc.jwtsecret ./jwtsecret

beacon-chain \
  --p2p-host-ip=100.64.0.5 \
  --p2p-tcp-port=4200 \
  --p2p-udp-port=4300 \
  --rpc-host=127.0.0.1 \
  --grpc-gateway-host=127.0.0.1 \
  --execution-endpoint=http://127.0.0.1:8551
```

**Do not** switch `--nat=extip` or `--p2p-host-ip` to the overlay vIP until a bidirectional overlay frame is written on the peer TUN. A stub that only counts local TUN IPv4 is not enough; advertise stays on the public IP.

Never set `--http.addr`, `--authrpc.addr`, `--p2p-local-ip`, or `--rpc-host` to the overlay vIP. That `bind()` fails if the TUN is down and can take Engine off loopback.

Public how-to: [Applications](https://gitbook.conet.network/applications/conet-l0d.html) · [Developers](https://gitbook.conet.network/developers/conet-l0d.html) · [Run an L1 node](https://gitbook.conet.network/developers/l1-node.html)

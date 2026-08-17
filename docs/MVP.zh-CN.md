# MVP — conet-l0d

**成对：** [English](./MVP.md)  
**Revision：** 2026-08-17（里程碑评估 21:50Z：crate MVP 已验收；P1 出站 + 入站解密/TUN 写回已在 crate；未打开现役 mailbox SSE；实验室二进制 `[l0]` 关 — 见 [P1.zh-CN.md](./P1.zh-CN.md)）

公开 how-to：[Applications](https://gitbook.conet.network/applications/conet-l0d.html) · [Developers](https://gitbook.conet.network/developers/conet-l0d.html)

## 目标

交付独立 **Linux 命令** `conet-l0d`：启动创建 TUN + iptables，停止/teardown **只**拆除这些对象。操作员不用手写 `iptables`。

## 范围内

| 项 | 验收 |
| --- | --- |
| 二进制 | `cargo build --release` → `conet-l0d` |
| `check-config` / `resolve` | 任意 OS 可跑；精确解析 `web3://` |
| `start` | Linux + `CAP_NET_ADMIN`：TUN `conet-l0`、本机 vIP `/32`、路由 `100.64.0.0/10`、链 `CONET_L0D` 且 loopback `RETURN` |
| `stop` / SIGINT / SIGTERM | 与 start 相反；pid 来自 state 文件 |
| `teardown` | 守护进程已死后仍能走同一反向路径 |
| 收包循环 | 统计 TUN 上的 IPv4；记录目的 vIP（不含密钥） |
| L0 | crate 桩已验收：统计 TUN IPv4 并记录目的 vIP。不得声称现役 SI `p2p_stream_*`。现役 `/post` 字节流见 [P1](./P1.zh-CN.md) |
| 文档 | 成对白皮书 + 本 MVP + GitBook Applications + Developers |
| 示例 + unit | `config/conet-l0d.example.toml` 与 `systemd/conet-l0d.service`（仅 `start`/`stop`） |

## 范围外（不算 MVP 失败）

- 生产 mailbox 投递 / 现役 listen SSE（[P1](./P1.zh-CN.md) crate 已有出站 encrypt + wrap + POST **以及**入站解密 + TUN 写回；实验室可装该二进制；`[l0]` 保持 **关** — 不是现役 mailbox 客户端）
- 捕获 UDP discv4 / discv5
- 代理 validator 或读取 keystore
- 新 SI 命令或新域名
- 重启 geth / beacon / validator

## 命令

```bash
conet-l0d check-config --config config/conet-l0d.example.toml
conet-l0d resolve 'web3://0x1111111111111111111111111111111111111111/p2p/geth'
sudo conet-l0d start --config /etc/conet-l0d.toml
sudo conet-l0d stop --config /etc/conet-l0d.toml
sudo conet-l0d teardown --config /etc/conet-l0d.toml
conet-l0d status --config /etc/conet-l0d.toml
```

## 测试

```bash
cargo test
```

`resolve` / 配置单测须在 macOS 通过。`start` 仅 Linux。

## 同步规则

改本文件、白皮书或 `RULES.md` 时，同一任务更新 GitBook **Applications** 与 **Developers** 的 `conet-l0d` 页。

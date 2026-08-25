# 基于 CoNET Layer Minus 的 `web3://`

Linux 运行时、跨平台客户端合同与应用网关

对应英文版：[`conet-l0d.md`](conet-l0d.md)

修订：2026-08-22

## 摘要

`web3://` 是构建于 CoNET Layer Minus（L0）之上的钱包地址化应用协议。
它为应用提供稳定的密码学目标，由 L0 提供加密入口路由、mailbox 投递和双向传输。

`conet-l0d` 是该协议的 Linux 运行时。Linux 服务器可用 `--proxy` 或
`--proxyDuplex` 发布本地服务；Linux 客户端可用 `--clientDuplex`
把远端 `web3://` 服务提供为本地 endpoint。Windows、macOS、Android
与 iOS 无需运行 Linux daemon。浏览器扩展、Web 应用和原生应用可在客户端代码中
实现相同的 locator、调用方签名请求、加密响应关联与 stream 合同。

该协议组合现有 L0 原语，不会引入第二套网络、新 SI 命令族，也不会替代公开
CoNET L1 节点加入路径。

## 1. 问题

互联网应用通常暴露 DNS 名称、公开 origin 与绑定证书的服务器身份。这使 origin
容易被定位，也把应用命名绑定到传统托管方式。

CoNET 已经提供另一种基础：

- 钱包与 OpenPGP 身份；
- 加密入口路由；
- mailbox 投递；
- 持续接收 session；
- 发件人与收件人之间的应用加密。

应用在此基础之上还需要一份小而明确的合同，用于命名目标、打开 session、
承载 request 或 stream，并把响应返回给已认证调用方。

## 2. 分层模型

```text
Application
  web3:// URI、request 或 stream 语义、错误
                         │
Client implementation
  browser / native library / conet-l0d
                         │
Layer Minus
  entry A/C、mailbox B、OpenPGP 路由、SSE/duplex 投递
                         │
Local server adapter
  conet-l0d proxy 或 application gateway
                         │
Origin service
  localhost/private network 上的 HTTP API、WebSocket 或 TCP 服务
```

每层只承担一种职责：

| 层 | 职责 |
|---|---|
| L0 | 加密的钱包地址化传输 |
| `web3://` | 应用目标与 session 合同 |
| `conet-l0d` | Linux server/client adapter |
| 浏览器/原生客户端 | 跨平台用户侧实现 |
| Origin | 现有应用逻辑 |

应用协议不修改 L0 HTTP 信封。Entry request 仍然只包含
`{ "data": "<OpenPGP armor>" }`。

## 3. 各平台产品角色

| 平台 | 推荐角色 |
|---|---|
| Linux server | 用 `conet-l0d --proxy` 或 `--proxyDuplex` 发布本地服务 |
| Linux client | 用 `conet-l0d --clientDuplex` 连接远端（同一逻辑口可对应多条远端） |
| Windows / macOS | 实现 `web3://` 的浏览器扩展、浏览器客户端或原生客户端 |
| Android / iOS | 通过 HTTPS/SSE 使用同一协议的 Web 或原生客户端 |
| Browser | 无需 Linux daemon，完成 parse、sign、encrypt、send、receive、decrypt 与 render |

这种分工让协议保持平台中立，同时提供面向生产的 Linux 参考运行时。

## 4. 目标语法

当前 Linux 运行时接受钱包地址化 endpoint：

```text
web3://0x<40-hex>:<port>
web3://<exact-tag>.web3:<port>
```

例如：

```text
web3://0x1111111111111111111111111111111111111111:443
web3://ExampleMerchant.web3:9443
```

Host 标识远端应用 owner，port 标识逻辑应用服务。必须精确解析 tag；
不得隐式选取前缀搜索的第一条结果。

面向浏览器的资源可增加 path 与 query：

```text
web3://0x1111111111111111111111111111111111111111/dashboard?range=7d
```

签名 request 承载 canonical target、path 与 query。客户端可以展示人类可读别名，
但加密前必须解析到精确钱包身份。

仓库还识别 `/p2p/geth` 与 `/p2p/beacon` peer locator，用于受控 L1 实验。
这些 locator 只是应用组合之一，不是通用协议的定义。

## 5. Session profile

### 5.1 Request/response

`--proxy HOST:PORT` 发布本地 request/response upstream。签名应用 request
路由到钱包目标，由 server adapter 校验，转发到配置的 origin，再加密给调用方
已登记的 user PGP key。

该 profile 适合有边界的 HTTP 风格操作。

### 5.2 持续双向传输

`--proxyDuplex HOST:PORT` 发布持续双向 TCP 服务。
`--clientDuplex web3://HOST:PORT` 把选定远端服务提供为
`127.0.0.1` TCP endpoint。同一逻辑口可对应多条远端；每条远端各自一个
loopback 监听。首选绑定 `PORT`；若已被占用则依次尝试 `PORT+10000`、
`PORT+20000`……。同一 `(host, PORT)` 重复列出则拒绝。

每个被接受的本地连接都会创建独立应用 session：

```text
local TCP connection
    → duplex offer
    → remote acceptance
    → bidirectional encrypted frames
    → explicit close or reconnect
```

Session ID、顺序、上限与关闭行为属于应用 stream 合同。L0 提供传输，
不解释 origin 协议。

## 6. 签名 Web request 网关

`conet-l0d gateway` profile 把钱包地址化 request 映射到 loopback HTTP origin。

已实现的 v1 request 包含：

- `type = "conet_web3_request_v1"`；
- 唯一 `requestId`；
- 调用方钱包 `from`；
- `target = web3://<gateway-eoa>/...`；
- method、path、query、选定 headers 与可选 body；
- nonce 与 expiry；
- 对 canonical request JSON 的 EIP-191 签名。

网关执行：

1. 用自身 user PGP key 解密 request；
2. 检查 version、expiry、method、path、target 与 signature；
3. 只转发到已配置的 loopback origin；
4. 限制 request/response 大小与执行时间；
5. 把 `conet_web3_response_v1` 加密给调用方已登记的 user PGP key；
6. 通过普通 L0 entry 发送 response。

当前网关只允许 `GET` 与 `HEAD`。更广泛的 method、delegation、payment
与 origin identity header 必须通过后续协议版本定义，不得依靠未文档化行为。

## 7. L0 路由与隐私

该协议遵循现有 A/B/C mailbox 模型：

| 动作 | 加密目标 | 网络入口 |
|---|---|---|
| 应用投递 | 收件人 user PGP | 与 mailbox B 不同的健康 entry A |
| Receive/listen command | mailbox B route PGP | 与 B 不同的健康 entry C |
| Response | 调用方 user PGP | 响应方选择的健康 entry |

Entry 与 mailbox 节点只获得路由所必需的信息。它们不会成为受信应用 origin，
也不得获得 request body 明文。

客户端不得通过直连 mailbox B 进行“优化”。直连会暴露路由位置，
并偏离协议隐私模型。

## 8. 身份与授权

`web3://` 把应用访问绑定到密码学身份：

1. target 解析为精确钱包；
2. payload 加密给 target 的 user PGP key；
3. request 由调用方 EOA 签名；
4. server 校验签名与 target；
5. response 加密给调用方 user PGP key。

应用可在身份校验后增加自身授权策略。协议证明谁签署了 request，
不代表每位签署者自动拥有所有资源权限。

日志不得写入私钥、完整 PGP 密文或应用 body 明文。

## 9. Linux 运行时配置

公开配置以应用 endpoint 为中心：

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

运营者应让 origin service 只监听 loopback 或 private network，
并且只发布预期的逻辑 port。

## 10. 生命周期与可观测性

Linux 运行时提供：

| 命令 | 用途 |
|---|---|
| `check-config` | 不打开 session，仅校验配置 |
| `resolve` | 解析并解析到 `web3://` locator |
| `start` | 运行已配置的 server proxy 与 client endpoint |
| `gateway` | 运行签名 Web request 网关 |
| `status` | 报告已记录 runtime state |
| `stop` | 向已记录进程发信号并清理 runtime state |
| `teardown` | 删除遗留的 daemon-owned runtime state |

有效证据包括：

- 精确钱包或 tag 解析；
- 已发布与本地 endpoint 地址；
- 被接受的 request 或 duplex session ID；
- 加密 frame 计数与有界 queue 状态；
- response status 或 stream close reason；
- reconnect attempt。

进程存活不能证明应用 request 或 stream 已完成。

## 11. SSE 心跳与废弃策略

mailbox SI 的 `l0_listen` 是长期 SSE。空闲阶段由 SI 每 15 秒发送
`: keepalive`；L0d 以最后收到的 comment、握手或合法 frame 为活动时间，
连续 180 秒没有任何输入就关闭该 SSE、释放临时 session，并从链上 SI 池
重新随机选择入口。`pool_full` 是单个 SI 的本地 256 槽位容量错误；
对于当前 duplex incarnation 它是终止性错误：listen worker 丢弃 ready
信号、关闭 APP TCP socket，不能用相同临时钱包每 3 秒重复 POST。

`l0_connect` 占用后不再发送 comment，L0d 每 60 秒发送加密
`duplex_ping`；SI 的 occupied 两端连续 180 秒没有输入即释放 entry 并
关闭两端 socket。`close`、`error`、EOF、失败写入和明确不可用的 socket
都立即触发释放。

这是接收端超时合同。单向 SSE 中发送方的成功写入不是接收确认；半开 TCP
仍需依靠 TCP keepalive、close/error 事件和另一端的 180 秒接收超时回收。
重试前必须先释放旧的临时 identity、本地 TCP 和 SSE pump，避免重试制造
重复 listen。如果 `l0_connect` 占用失败，同一 duplex 在双方都视为失效：
L0d 丢弃 pipe handle 并关闭 APP stream；尽力发送一次加密的
`duplex_reject`（`reason=pipe_failed`、`retryable=true`）。只有 APP 使用
新 duplex 重连。该策略只影响 L0d 自己的 session，不要求重启 geth、
beacon 或 validator。

## 12. 故障模型

客户端与运营者应区分：

| 故障 | 含义 |
|---|---|
| Locator 解析失败 | 目标无效、有歧义或未登记 |
| Entry request 失败 | 所选 entry 不可用；尝试另一健康 entry |
| Mailbox 拒绝路由 | 目标 route 不属于该 mailbox |
| Signature 失败 | 调用方身份或 canonical request bytes 不匹配 |
| Origin connect 失败 | 已发布的本地服务不可用 |
| Stream close | 按有界客户端策略重连 |
| Response timeout | 没有完成可信应用响应 |

传输失败不得转换为“成功但空”的响应。应用应根据自身缓存策略保留上次可信数据。

## 13. 可选 L1 组合

选定 geth 或 Prysm TCP 数据流可用于受控 Linux-to-Linux duplex 实验。
该组合：

- 复用同一钱包目标与 stream 合同；
- 保留 geth 与 Prysm identity；
- 要求在 L1 客户端层独立验收；
- 与公开 L1 节点加入指南分离。

这不代表 CoNET L1 共识已普遍迁移到 L0。有限实验记录见
[`docs/P2.zh-CN.md`](../docs/P2.zh-CN.md)。

## 14. 成熟度

| 能力 | 状态 |
|---|---|
| 钱包/tag locator 解析 | 已实现 |
| Linux request/response proxy | 已实现 |
| Linux duplex server/client runtime | 已实现 |
| 签名 v1 GET/HEAD gateway | 已实现 |
| 浏览器扩展/client 组合 | 早期实现 / 持续演进 |
| 跨平台协议 SDK | 目标 |
| Delegation、payment scope、正式 canonical-byte 规范 | Draft |
| L1 TCP 组合 | 实验室已验证，不是公开默认路径 |

文档必须保留这些区别。Locator 或 Linux runtime 可用，不代表所有浏览器能力
或未来协议扩展都已达到生产状态。

## 15. 非目标

该协议不是：

- 通用网络接口；
- VPN 产品；
- 新公开 SI 命令族；
- 直接暴露 origin service 的理由；
- 普通 Web endpoint 上 TLS 的替代品；
- 公开 L1 P2P 加入路径的替代品；
- 发明新域名或中心化路由服务的许可。

## 结论

持久抽象是应用协议，而不是某个操作系统 adapter。Layer Minus 提供私密的钱包地址化传输；
`web3://` 定义应用如何命名和交换数据；`conet-l0d` 提供 Linux 运行时；
浏览器或原生客户端提供跨平台用户体验。

### GuardianNodesInfoV6 SI 选择
默认 SI 传输使用链上池：daemon 通过配置 RPC 分页读取 GuardianNodesInfoV6，随机选择候选节点、对 TCP 80 做有限资格检查，并冷却失败节点后重试。静态 entries 仅供关闭池的部署使用。该选择与 duplex 线路角色独立：纯 clientDuplex spoke 不建立常驻 Chat SSE，但保留独占的 `l0_listen` 所有权。

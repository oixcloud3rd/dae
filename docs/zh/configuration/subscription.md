# 订阅

dae 支持 HTTP(S)、本地文件、SIP008、Base64 和未加密的 Clash YAML 订阅。
Clash YAML 会自动识别根级 `proxies`，导入 Shadowsocks、SOCKS5、HTTP(S)、
VMess、VLESS、Trojan、Hysteria2、TUIC、AnyTLS 和 Snell 节点；策略组、
规则、DNS 和 provider 不会被导入。构建产物嵌入
`OIXCLOUD_SUBSCRIPTION_HMAC_KEY` 后，还可以读取 oixCloud 托管配置。

解析器只保留对应 outbound 链接能够无损表达的选项。节点带有无法表达的
非空传输或安全选项时会被跳过并计入汇总告警；`udp` 和 `tfo` 作为能力提示
可被接受。普通 TLS 节点的逐节点指纹不会被静默降级，仅 VLESS Reality 和
Snell ECH-TLS 保留 `client-fingerprint`。

Clash 中的 Snell ECH-TLS 节点默认使用 Identity v2、ALPN
`snell-ech/1`、模仿 `chrome_auto` ClientHello 的 uTLS，不启用旧协议回退，
也不预连接。解析器会无损映射 `obfs-opts` 中的 `alpn`、`protocol`、
`identity-version`、`legacy-fallback`、`preconnect`、`host`/`sni`、
`ech-config` 和 `client-fingerprint`。旧协议名 `oix-snell/1` 会规范化为
`snell-ech/1`。Clash 指纹名称 `chrome`、`firefox`、`safari`、`iOS`、
`android`、`edge`、`360`、`qq` 和 `random` 会转换为 outbound 支持的 uTLS
ClientHello ID。

默认的 Snell ECH-TLS 使用 TLS 握手后的原始字节流，不使用 WebSocket。旧的顶层单值
或单元素 `alpn: [h2]` 会迁移为 `snell-ech/1` 并显式启用
`legacy-fallback: true`；只有 ALPN 不兼容才会回退，Identity v2 在该次重试中
使用 Identity v1。连接旧服务器时也应采用这一显式回退配置。嵌套 ALPN 与
顶层 ALPN 冲突时节点会被拒绝。未写 ALPN 或 Identity 的直接 `snell://` 链接
仍保留旧的隐式默认行为。

证书校验不可关闭。`obfs-opts` 中显式的 `skip-cert-verify: false` 和
`insecure: false` 可以接受，生成的链接会显式覆盖全局 insecure；任一字段为
`true` 时节点会被拒绝。`preconnect` 必须在 0–4 之间，非零值要求 v4/v5
兼容 wire、ECH-TLS 和 `reuse: true`。由于 outbound 链接无法安全表达，非空的
`ech-config-file`、`ca-file`、`fingerprint`、`certificate`、`private-key` 和
`headers` 会导致节点被拒绝。旧 `path` 和 `ws-host` 仅作为 ECH-TLS 兼容字段
接受并忽略，生成的规范化链接不会保留它们。

## Snell HTTP/3

`obfs-opts.transport` 支持 `tcp`（默认）、`h3` 和 `auto`。这是自定义
HTTP/3 Extended CONNECT 隧道，不是官方 Snell v5 QUIC 模式。
它要求 v4/v5 兼容 wire、ECH-TLS、证书校验和 Identity v2。H3 订阅默认使用
Identity v2，旧字段 `identity: true` 可以与 `identity-version: 2` 共存。
显式关闭 Identity、指定 v1、使用 v6/simple-obfs 或启用 `legacy-fallback`
时，H3 节点会被拒绝。

```yaml
proxies:
  - name: snell-h3
    type: snell
    server: server.example
    port: 443
    version: 4
    psk: password
    reuse: true
    obfs-opts:
      mode: ech-tls
      transport: auto
      identity-version: 2
      sni: origin.example
      ech-config: "<base64 ECHConfigList>"
      preconnect: 1
      congestion-controller: bbr3
```

`h3` 的建隧道预算为 10 秒，不回退；`auto` 对齐 `oixcloud3rd/sing-box`
的 Snell Happy Eyeballs：先启动 H3，无可用会话时延迟 250 毫秒启动
同地址、同端口的 ECH-TLS TCP；已有会话时采用两倍平滑 RTT，限制在
100–1000 毫秒。H3 提前失败则立即启动 TCP，首个成功的传输获胜。
TCP 获胜后，H3 在原有 2 秒预算内继续探测；成功则保留 QUIC 会话并清除
冷却，失败则冷却 30 秒，未使用的 H3 流会关闭。H3 获胜则取消 TCP
并关闭迟到连接。选出获胜连接前，调用方取消或超时会停止竞速；
关闭或重载 dialer 也会停止后台探测。共享 QUIC 握手独立限时，
单个等待者取消不影响其他等待者。仅获胜连接发送 Snell 数据。
TCP 仍校验证书并使用 Identity v2，默认 ALPN 为 `snell-ech/1`。
QUIC 传输参数使用依赖库默认值。指纹/uTLS 仅用于 TCP，
H3 使用 Go TLS 1.3 和 `h3` ALPN。旧 `path/ws-host` 仍被忽略。

`obfs-opts.cc-override` 优先于 `congestion-controller`；也接受
`cc_override`、`congestion_control` 拼写，但同义字段冲突时拒绝节点。
默认算法为实验性 BBR3，支持 `bbr`、`bbr3`、`brutal` 和 `reno/new_reno`。
未知的 `congestion-controller` 值（包括尚未实现的 `cubic`）会在构建节点时
告警并使用 BBR3；无效的 override 会拒绝节点。`cwnd` 单位为字节/秒，
表示 Brutal 必填的正数目标速率或 BBR3 可选的带宽上界提示。这些字段只
控制客户端 QUIC 发送，要求使用 `h3/auto`。本次不支持 BBR profile，显式
填写该字段会拒绝节点。

## oixCloud 托管配置

将 oixCloud token 放在 URL host 中；query 参数会转发给托管配置 API：

```shell
subscription {
    cloud: 'oixcloud://your-token?client=dae'
}
```

dae 会认证请求、生成临时 age X25519 身份、校验服务端提供的响应签名、解密 YAML，然后交给与普通订阅相同的 Clash 解析器。

订阅日志和错误会隐藏 token、节点凭据与 HMAC key。

## 带缓存的订阅

`oixcloud+file` 必须配置订阅 tag：

```shell
subscription {
    cloud: 'oixcloud+file://your-token?client=dae'
}
```

响应通过认证、解密和节点转换后，dae 会用 `0600` 权限将解密 YAML 原子写入 `persist.d/cloud.sub`。后续刷新在 HTTP、验签、解密或解析阶段失败时，会使用该缓存重新转换。失败或无效的远端配置不会覆盖最后一份有效缓存。

源码构建时通过环境变量注入原始 HMAC key：

```shell
OIXCLOUD_SUBSCRIPTION_HMAC_KEY='<subscription-hmac-key>' make
```

普通本地构建可以不提供 key，但使用 oixCloud 订阅时会明确报错；发布与 Docker 构建要求必须提供。该 key 会存入最终二进制文件，能够读取二进制的攻击者仍可能提取它。

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

Snell ECH-TLS 使用 TLS 握手后的原始字节流，不使用 WebSocket。旧的顶层单值
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

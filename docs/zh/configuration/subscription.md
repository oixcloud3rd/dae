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

Clash 中的 Snell ECH-TLS 节点会在未显式指定 TLS 实现时自动使用 uTLS，
并默认模仿 `chrome_auto` ClientHello。显式设置的
`tls-implementation` 或 `client-fingerprint` 优先。Clash 指纹名称
`chrome`、`firefox`、`safari`、`iOS`、`android`、`edge`、`360`、`qq` 和
`random` 会自动转换为 outbound 支持的 uTLS ClientHello ID。

Snell ECH-TLS 使用 TLS 握手后的原始字节流，不再使用 WebSocket。ALPN 固定
为 `h2`，但应用数据不是 HTTP/2 帧。旧配置中的 `path` 和 `ws-host` 会被接受
但忽略，生成的规范化节点链接不会保留这些字段。显式 `alpn: [h2]` 可以省略；
其他 ALPN 值会被拒绝。

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

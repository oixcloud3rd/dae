# DNS

dae 拦截目标端口为 53 的 UDP 流量并嗅探 DNS，以下为 DNS 配置的示例和模板。

# Schema

DoH3

```
h3://<host>:<port>/<path>
http3://<host>:<port>/<path>

默认端口: 443
默认 path: /dns-query
```

DoH

```
https://<host>:<port>/<path>

默认端口: 443
默认 path: /dns-query
```

DoT

```
tls://<host>:<port>

默认端口: 853
```

DoQ

```
quic://<host>:<port>

默认端口: 853
```

UDP
  
```
udp://<host>:<port>

默认端口: 53
```

TCP

```
tcp://<host>:<port>

默认端口: 53
```

TCP and UDP

```
tcp+udp://<host>:<port>

默认端口: 53
```

## oixCloud 查询认证

在任意远程 DNS 协议前添加 `oixcloud+` 即可启用查询认证：

```text
oixcloud+udp://dns.example.com:53
oixcloud+tcp+udp://dns.example.com:53
oixcloud+https://dns.example.com:443/dns-query
```

该前缀支持 `udp`、`tcp`、`tcp+udp`、`udp+tcp`、`tls`、`https`、`quic`、`h3` 和 `http3`。dae 使用构建时嵌入的 Ed25519 私钥和固定的 300 秒时间窗为每个查询域名签名；签名编码为两个小写 Base32 标签并添加到查询名之前。响应进入路由和缓存前，其中匹配的名称会被恢复。

此功能认证查询，但不加密 DNS 报文。如需传输保密性，请使用 `oixcloud+tls`、`oixcloud+https`、`oixcloud+quic` 或 `oixcloud+h3`。

构建产物必须包含有效的 oixCloud 私钥。配置包含 oixCloud 上游但密钥缺失或无效时，加载配置会失败；签名后无法形成合法 DNS 名称的请求也会直接失败，不会以未签名形式发送。

源码构建时可通过环境变量注入 Base64 编码的 32 字节 Ed25519 seed：

```shell
OIXCLOUD_DNS_AUTH_PRIVATE_KEY='<base64-ed25519-seed>' make
```

也可以将仓库根目录的 `.env.example` 复制为 `.env` 后填写密钥。私钥会存入最终二进制文件，能够访问二进制文件的攻击者仍可能提取它。

## 示例

```shell
dns {
    # 若 ipversion_prefer 设为 4，且域名同时有 A 和 AAAA 记录，dae 只回应 A 类型的请求，并返回空回复给 AAAA 请求。
    ipversion_prefer: 4

    # 为域名设定固定的 ttl。若设为 0，dae 不缓存该域名 DNS 记录，收到请求时每次向上游查询。
    fixed_domain_ttl {
        ddns.example.org: 10
        test.example.org: 3600
    }

    # 绑定到本地地址以监听 DNS 查询请求
    #bind: '127.0.0.1:5353'

    upstream {
        # 支持协议：tcp, udp, tcp+udp, https, tls, http3, h3, quic, 详情见上面的 Schema。
        # 在远程协议前添加 oixcloud+ 可启用 oixCloud 查询认证。
        # 若主机为域名且具有 A 和 AAAA 记录，dae 自动选择 IPv4 或 IPv6 进行连接,
        # 是否走代理取决于全局的 routing（不是下面 dns 配置部分的 routing），节点选择取决于 group 的策略。
        # 请确保DNS流量经过dae且由dae转发，按域名分流需要如此！
        # 若 dial_mode 设为 'ip'，请确保上游 DNS 无污染，不推荐使用国内公共 DNS。

        alidns: 'udp://dns.alidns.com:53'
        googledns: 'tcp+udp://dns.google:53'
        # oixcloud_dns: 'oixcloud+udp://dns.example.com:53'
        # oixcloud_doh: 'oixcloud+https://dns.example.com:443/dns-query'

        # alih3: 'h3://dns.alidns.com:443'
        # alih3_path: 'h3://dns.alidns.com:443/dns-query'
        # alihttp3: 'http3://dns.alidns.com:443'
        # alihttp3_path: 'http3://dns.alidns.com:443/dns-query'
        # ali_quic: 'quic://dns.alidns.com:853'

        # h3_custom_path: 'h3://dns.example.com:443/custom-path'
        # http3_custom_path: 'http3://dns.example.com:443/custom-path'

        # ali_doh: 'https://dns.alidns.com:443'
        # ali_dot: 'tls://dns.alidns.com:853'

        # doh_custom_path: 'https://dns.example.com:443/custom-path'
    }
    # 'request' 和 'response' 的 routing 格式和全局的 'routing' 类似。
    # 参考 https://github.com/daeuniverse/dae/blob/main/docs/zh/configuration/routing.md
    routing {
        # 根据 DNS 查询，决定使用哪个 DNS 上游。
        # 按由上到下的顺序匹配。
        request {
            # 'request' 具有预置出站：asis, reject。
            # asis 即向收到的 DNS 请求中的目标服务器查询，请勿将其他局域网设备 DNS 服务器设为 dae:53（小心回环）。
            # 你可以使用在 upstream 中配置的 DNS 上游。

            # 普通 DNS 请求可使用: qname, qtype。
            # 同一个块里还支持 dae 自身使用的内部选择器: sub, node, subnode。
            # - sub(): 订阅拉取时的解析请求
            # - node(): 节点地址解析请求
            # - subnode(): 订阅节点的地址解析请求，并且优先级高于 node()
            # node/subnode 的地址条件匹配解析后的代理主机名，而不是原始链接:
            # - address_keyword: 忽略大小写的包含匹配
            # - address_regex: 正则匹配
            # - address_suffix: 忽略大小写、遵循 DNS 标签边界的后缀匹配
            # 这些内部选择器:
            # - 只影响 dae 自身发起的解析
            # - 目标只能是 dns.upstream 中定义的名称
            # - 不使用 fallback
            # - 不能和 qname/qtype 混写在同一条规则里

            # DNS 查询域名（省略后缀点 '.'）。
            qname(geosite:category-ads-all) -> reject
            qname(geosite:google@cn) -> alidns # 参考: https://github.com/v2fly/domain-list-community#attributes
            qname(suffix: abc.com, keyword: google) -> googledns
            qname(full: ok.com, regex: '^yes') -> googledns
            # DNS 查询类型
            qtype(a, aaaa) -> alidns
            qtype(cname) -> googledns
            # 禁用 ECH 避免影响分流
            qtype(https) -> reject

            # 将 dae 自身拉取订阅时的 DNS 查询发到 googledns。
            # sub(my_sub) -> googledns
            # 名称里包含 "hk" 的节点解析走 googledns。
            # node(name_keyword: hk) -> googledns
            # 即使节点链接不透明（例如 VMess），也可按解析后的主机名后缀匹配。
            # node(address_suffix: example.com) -> googledns
            # 来自订阅 "my_sub" 的节点优先走 alidns，再考虑 node()。
            # subnode(subtag: my_sub) -> alidns
            # subnode(subtag: my_sub) && subnode(address_regex: '^hk[0-9]+\.example\.com$') -> alidns

            # fallback 意为 default。
            # 如果上面的都不匹配，使用这个 upstream。
            fallback: asis
        }
        # 根据 DNS 查询的回复， 决定接受或使用其他 upstream 重新查询。
        # 按由上到下的顺序匹配。
        response {
            # 具有预置出站：accept, reject。
            # 你可以使用在 upstream 中配置的 DNS 上游。

            # 可以使用: qname, qtype, upstream, ip。
            # 接受upstream 'googledns' 回复的 DNS 响应。 有助于避免回环。
            upstream(googledns) -> accept
            # 若 DNS 请求的域名不属于 CN 且回复包含私有 IP， 大抵是被污染了，向 'googledns' 重查。
            ip(geoip:private) && !qname(geosite:cn) -> googledns
            fallback: accept
        }
    }

}
```

## 模板

```shell
# 对于中国大陆域名使用 alidns，其他使用 googledns 查询。
dns {
  upstream {
    googledns: 'tcp+udp://dns.google:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    # 根据 DNS 查询，决定使用哪个 DNS 上游。
    # 按由上到下的顺序匹配。
    request {
      # 对于中国大陆域名使用 alidns，其他使用 googledns 查询。
      qname(geosite:cn) -> alidns
      # fallback 意为 default。
      fallback: googledns
    }
  }
}
```

```shell
# 默认使用 alidns，如果疑似污染使用 googledns 重查。
dns {
  upstream {
    googledns: 'tcp+udp://dns.google:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    # 根据 DNS 查询，决定使用哪个 DNS 上游。
    # 按由上到下的顺序匹配。
    request {
      # fallback 意为 default。
      fallback: alidns
    }
    # 根据 DNS 查询的回复， 决定接受或使用其他 upstream 重新查询。
    # 按由上到下的顺序匹配。
    response {
      # 可信的 upstream。总是接受它的回复。
      upstream(googledns) -> accept
      # 疑似被污染结果，向 'googledns' 重查。
      ip(geoip:private) && !qname(geosite:cn) -> googledns
      # fallback 意为 default。
      fallback: accept
    }
  }
}
```

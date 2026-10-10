# Subscriptions

dae supports HTTP(S), local file, SIP008, Base64, and unencrypted Clash YAML
subscriptions. Plain Clash YAML is detected by its root `proxies` list and
converts Shadowsocks, SOCKS5, HTTP(S), VMess, VLESS, Trojan, Hysteria2, TUIC,
AnyTLS, and Snell nodes. Groups, rules, DNS settings, and providers are not
imported. It also supports oixCloud managed configurations when the executable
contains an `OIXCLOUD_SUBSCRIPTION_HMAC_KEY`.

The parser preserves only options that the corresponding outbound link can
represent. A proxy with non-empty unsupported transport or security options is
skipped and included in the summarized warning; `udp` and `tfo` are accepted as
capability hints. Ordinary per-node TLS client fingerprints are rejected rather
than silently downgraded, except for VLESS Reality and Snell ECH-TLS.

Clash Snell ECH-TLS nodes default to Identity v2, ALPN `snell-ech/1`, uTLS with
the `chrome_auto` ClientHello, no legacy fallback, and no preconnections. The
parser maps `alpn`, `protocol`, `identity-version`, `legacy-fallback`,
`preconnect`, `host`/`sni`, `ech-config`, and `client-fingerprint` from
`obfs-opts`. The deprecated `oix-snell/1` protocol name is normalized to
`snell-ech/1`. Clash fingerprint names `chrome`, `firefox`, `safari`, `iOS`,
`android`, `edge`, `360`, `qq`, and `random` are translated to the
corresponding outbound uTLS ClientHello IDs.

By default, Snell ECH-TLS uses the raw byte stream after the TLS handshake and does not use
WebSocket framing. A legacy top-level scalar or single-item `alpn: [h2]` is
migrated to `snell-ech/1` with explicit `legacy-fallback: true`; fallback is
attempted only for ALPN incompatibility, and Identity v2 uses Identity v1 on
that retry. Use the same explicit `legacy-fallback` setting for old servers.
Nested and top-level ALPN settings that conflict are rejected. Direct
`snell://` links that omit ALPN or Identity retain their old implicit defaults.

Certificate verification is mandatory. Explicit `skip-cert-verify: false` and
`insecure: false` values under `obfs-opts` are accepted, and generated links
explicitly disable the global insecure setting; either value set to `true`
rejects the node. `preconnect` must be between 0 and 4, and a non-zero value
requires Snell v4/v5-compatible wire, ECH-TLS, and `reuse: true`. The parser
rejects non-empty `ech-config-file`, `ca-file`, `fingerprint`, `certificate`,
`private-key`, and `headers` options because outbound links cannot represent
them safely. Legacy `path` and `ws-host` values are accepted only as ignored
ECH-TLS compatibility fields and are removed from generated links.

## Snell HTTP/3

`obfs-opts.transport` accepts `tcp` (default), `h3`, or `auto`. This is a
custom HTTP/3 Extended CONNECT tunnel, not official Snell v5 QUIC mode.
It requires v4/v5-compatible wire, ECH-TLS, certificate verification, and
Identity v2. H3 subscriptions default to Identity v2; legacy `identity: true`
can coexist with `identity-version: 2`. Explicit Identity v1/disabled, v6,
simple-obfs, and `legacy-fallback: true` are rejected for H3.

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

`h3` has a 10-second tunnel establishment budget and does not fall back.
`auto` tries H3 for 2 seconds, then uses ECH-TLS TCP at the same address/port,
with a 30-second cooldown before retrying H3. Caller deadlines take precedence.
Fallback retains certificate verification and Identity v2, defaults to
`snell-ech/1` ALPN, and never replays Snell data. Fingerprints/uTLS apply only
to TCP; H3 uses Go TLS 1.3 and `h3` ALPN. Legacy `path/ws-host` remain ignored.

Under `obfs-opts`, `cc-override` overrides `congestion-controller`; aliases
`cc_override` and `congestion_control` are accepted, but conflicting aliases
are rejected. The default is experimental BBR3. Supported values are `bbr`,
`bbr3`, `brutal`, and `reno`/`new_reno`. Unknown `congestion-controller` values
(including `cubic`) warn when the node is built and use BBR3; invalid overrides
reject the node. `cwnd` is a positive target rate for Brutal or an optional
bandwidth upper-bound hint for BBR3, in bytes/second. These settings affect
only client QUIC sending and require `h3/auto`. BBR profile fields are rejected.

## oixCloud managed configuration

Use the oixCloud token as the URL host. Query parameters are forwarded to the managed configuration API:

```shell
subscription {
    cloud: 'oixcloud://your-token?client=dae'
}
```

dae authenticates the request, generates a temporary age X25519 identity,
verifies a response signature when supplied, decrypts the returned YAML, and
passes it to the same Clash parser used for plain subscriptions.

The token, proxy credentials, and HMAC key are redacted from subscription logs and errors.

## Cached subscriptions

The `oixcloud+file` scheme requires a subscription tag:

```shell
subscription {
    cloud: 'oixcloud+file://your-token?client=dae'
}
```

After a response passes authentication, decryption, and proxy conversion, dae atomically stores the decrypted YAML as `persist.d/cloud.sub` with mode `0600`. If a later refresh fails during HTTP, signature verification, decryption, or parsing, dae retries the same conversion using this cache. A failed or invalid refresh never replaces the last valid cache.

See the [build guide](../user-guide/build-by-yourself.md#oixcloud-subscription-hmac-key) for key injection.

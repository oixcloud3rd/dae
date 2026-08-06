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

Snell ECH-TLS uses the raw byte stream after the TLS handshake and does not use
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

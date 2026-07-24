# Subscriptions

dae resolves ordinary HTTP(S), local file, SIP008, and Base64 subscriptions as before. It also supports oixCloud managed configurations when the executable contains an `OIXCLOUD_SUBSCRIPTION_HMAC_KEY`.

## oixCloud managed configuration

Use the oixCloud token as the URL host. Query parameters are forwarded to the managed configuration API:

```shell
subscription {
    cloud: 'oixcloud://your-token?client=dae'
}
```

dae authenticates the request, generates a temporary age X25519 identity, verifies a response signature when supplied, decrypts the returned YAML, and imports the root `proxies` list. This initial implementation supports only `type: anytls` and `type: snell`. Other proxy types are skipped with a summarized warning. Clash groups, rules, DNS settings, and providers are not imported.

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

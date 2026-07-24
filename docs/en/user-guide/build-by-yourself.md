# Build Guide

## Build

### Make Dependencies

```shell
clang >= 10
llvm >= 10 (optional)
golang >= 1.24
make
```

### Compilation

```shell
git clone https://github.com/daeuniverse/dae.git
cd dae
git submodule update --init
## Minimal dependency build
make GOFLAGS="-buildvcs=false" \
  CC=clang

## Normal build
#make

## Cross compile
# To armv7 CPU architect:
#make CGO_ENABLED=0 GOARCH=arm GOARM=7
# To mips CPU architect:
#make CGO_ENABLED=0 GOARCH=mips
```

## oixCloud DNS auth private key

oixCloud DNS authentication requires a Base64-encoded 32-byte Ed25519 seed embedded at link time. The standard Makefile reads it from `OIXCLOUD_DNS_AUTH_PRIVATE_KEY`:

```shell
OIXCLOUD_DNS_AUTH_PRIVATE_KEY='<base64-ed25519-seed>' make
```

Alternatively, copy `.env.example` to `.env` in the repository root and set the key there. `.env` is ignored by Git, and a value supplied through the environment or on the Make command line takes precedence. Ordinary local builds may omit the key, but configurations containing an `oixcloud+` DNS upstream then fail during startup.

For a direct Go build, inject the linker variable explicitly:

```shell
go build -ldflags "-X github.com/daeuniverse/dae/common/consts.OIXCloudDNSAuthPrivateKey=<base64-ed25519-seed>" .
```

## oixCloud subscription HMAC key

Managed oixCloud subscriptions use a raw HMAC key embedded at link time. The key signs requests to and verifies signed responses from the managed configuration API. It has no runtime configuration source:

```shell
OIXCLOUD_SUBSCRIPTION_HMAC_KEY='<subscription-hmac-key>' make
```

The equivalent direct Go build flag is:

```shell
go build -ldflags "-X github.com/daeuniverse/dae/common/consts.OIXCloudSubscriptionHMACKey=<subscription-hmac-key>" .
```

Ordinary local builds may omit this key, but `oixcloud://` and `oixcloud+file://` subscriptions then fail with an explicit error. Distributed release and Docker builds require it.

For a local Docker build, pass both oixCloud keys as BuildKit secrets:

```shell
export OIXCLOUD_DNS_AUTH_PRIVATE_KEY='<base64-ed25519-seed>'
export OIXCLOUD_SUBSCRIPTION_HMAC_KEY='<subscription-hmac-key>'
docker build \
  --secret id=oixcloud_dns_auth_private_key,env=OIXCLOUD_DNS_AUTH_PRIVATE_KEY \
  --secret id=oixcloud_subscription_hmac_key,env=OIXCLOUD_SUBSCRIPTION_HMAC_KEY \
  .
```

Distributed builds require both keys and fail when either is missing or invalid. Both values are stored in the resulting executable and can be extracted by an attacker with access to the binary. Compile-time injection prevents runtime configuration but is not secure hardware-backed key storage.

## Run

### Runtime Dependencies

For traffic splitting, dae relies on the following data sources, [geoip.dat](https://github.com/v2fly/geoip/releases/latest) and [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest).

```shell
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
popd
```

### Run

Download the example config file:

```shell
curl -L -o example.dae https://github.com/daeuniverse/dae/raw/main/example.dae
```

See [example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae).

After fine tuning, run dae:

```shell
./dae run -c example.dae
```

> **Note**: Alternatively, you may run dae as a daemon (systemd) service. Check out more details [HERE](run-as-daemon.md).

# Build Guide

## Build

### Build Dependencies

```shell
clang >= 10
llvm >= 10 (optional)
golang >= 1.26
make
```

### Compilation

```shell
git clone https://github.com/daeuniverse/dae.git
cd dae
git submodule update --init
## Minimal dependency build
make GOFLAGS="-buildvcs=false" \
  CLANG=clang

## Normal build
#make

## Cross compile
# To armv7 CPU architect:
#make CGO_ENABLED=0 GOARCH=arm GOARM=7
# To mips CPU architect:
#make CGO_ENABLED=0 GOARCH=mips
```

### Trace Support per Architecture

`make` builds the optional `dae trace` eBPF program when the toolchain supports
it. The result is recorded in `.build_tags`: `trace` when built, or an empty
file otherwise.

`arm`, `mips`, `mips64`, `mips64le`, `mipsle`, and `s390x` builds do not include
`dae trace`; see `TRACE_UNSUPPORTED_GOARCH` in the Makefile. For these
architectures, the build prints a `WARNING`, omits the `trace` build tag, and
continues. For every other `GOARCH`, trace generation failure is an error, so
a binary cannot silently lose `dae trace`.

The BPF Test workflow verifies this list with
`./scripts/check-trace-arch-matrix.sh`. Reproduce the failures per architecture with:

```shell
git submodule update --init
GOARCH=mips BPF_CLANG=clang go generate ./trace/trace.go    # fails: no compiler specified
GOARCH=mips64 BPF_CLANG=clang go generate ./trace/trace.go  # fails: unsupported target
```

Do not remove an architecture from the list just because
`github.com/cilium/ebpf`'s `gen.FindTarget()` accepts it. Target lookup and
compilation are separate steps: `mips` passes lookup but fails compilation.
Its `bpf_tracing.h` selects the mips `pt_regs` layout, while the vendored
`vmlinux.h` from the `dae_bpf_headers` submodule falls back to x86.

`dae trace` requires kernel version 5.15 or later; the rest of dae requires 5.17 or later.

### oixCloud DNS auth private key

oixCloud DNS authentication requires a Base64-encoded 32-byte Ed25519 seed embedded at link time. The standard Makefile reads it from `OIXCLOUD_DNS_AUTH_PRIVATE_KEY`:

```shell
OIXCLOUD_DNS_AUTH_PRIVATE_KEY='<base64-ed25519-seed>' make
```

Alternatively, copy `.env.example` to `.env` in the repository root and set the key there. `.env` is ignored by Git, and a value supplied through the environment or on the Make command line takes precedence. Ordinary local builds may omit the key, but configurations containing an `oixcloud+` DNS upstream then fail during startup.

For a direct Go build, inject the linker variable explicitly:

```shell
go build -ldflags "-X github.com/daeuniverse/dae/common/consts.OIXCloudDNSAuthPrivateKey=<base64-ed25519-seed>" .
```

For a local Docker build, pass the key as a BuildKit secret:

```shell
export OIXCLOUD_DNS_AUTH_PRIVATE_KEY='<base64-ed25519-seed>'
docker build --secret id=oixcloud_dns_auth_private_key,env=OIXCLOUD_DNS_AUTH_PRIVATE_KEY .
```

Distributed builds require the key and fail when it is missing or invalid. The private key is stored in the resulting executable and can be extracted by an attacker with access to the binary. Compile-time injection prevents runtime configuration but is not secure hardware-backed key storage.

## Run

### Runtime Dependencies

For traffic splitting, dae relies on [geoip.dat](https://github.com/v2fly/geoip/releases/latest) and [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest).

```shell
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
popd
```

### Run

Download the example configuration:

```shell
curl -L -o example.dae https://github.com/daeuniverse/dae/raw/main/example.dae
```

See [example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae).

After editing the configuration, run dae:

```shell
./dae run -c example.dae
```

Alternatively, [run dae as a systemd service](run-as-daemon.md).

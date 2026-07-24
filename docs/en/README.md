# Quick Start Guide

[**简体中文**](../zh/README.md) | [**English**](README.md)

## Linux Kernel Requirement

## Kernel Version

Use `uname -r` to check the kernel version on your machine.

> **Note**
> If you find your kernel version is `< 5.17`, follow the [**Upgrade Guide**](user-guide/kernel-upgrade.md) to upgrade the kernel to the minimum required version.

`Bind to LAN: >= 5.17`

You need bind dae to LAN interface, if you want to provide network service for LAN as an intermediate device.

This feature requires the kernel version of machine on which dae install >= 5.17.

Note that if you bind dae to LAN only, dae only provide network service for traffic from LAN, and not impact local programs.

`Bind to WAN: >= 5.17`

You need bind dae to WAN interface, if you want dae to provide network service for local programs.

This feature requires kernel version of the machine >= 5.17.

Note that if you bind dae to WAN only, dae only provide network service for local programs and not impact traffic coming in from other interfaces.

`Use trace command`

If you want to use `dae trace` command to triage network connectivity issue, the kernel version is required to be >= 5.15.

## Kernel Configurations

Usually, mainstream desktop distributions have these items turned on. But in order to reduce kernel size, some items are turned off by default on embedded device distributions like OpenWRT, Armbian, etc.

Use following command to show kernel configuration items on your machine.

```shell
zcat /proc/config.gz || cat /boot/{config,config-$(uname -r)}
```

dae needs:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_CGROUPS=y
CONFIG_KPROBES=y
CONFIG_NET_INGRESS=y
CONFIG_NET_EGRESS=y
CONFIG_NET_SCH_INGRESS=m
CONFIG_NET_CLS_BPF=m
CONFIG_NET_CLS_ACT=y
CONFIG_BPF_STREAM_PARSER=y
CONFIG_DEBUG_INFO=y
# CONFIG_DEBUG_INFO_REDUCED is not set
CONFIG_DEBUG_INFO_BTF=y
CONFIG_KPROBE_EVENTS=y
CONFIG_BPF_EVENTS=y
```

Check them using command like:

for bash and other POSIX compliant shell:

```shell
(zcat /proc/config.gz || cat /boot/{config,config-$(uname -r)}) | grep -E 'CONFIG_(DEBUG_INFO|DEBUG_INFO_BTF|KPROBES|KPROBE_EVENTS|BPF|BPF_SYSCALL|BPF_JIT|BPF_STREAM_PARSER|NET_CLS_ACT|NET_SCH_INGRESS|NET_INGRESS|NET_EGRESS|NET_CLS_BPF|BPF_EVENTS|CGROUPS)=|# CONFIG_DEBUG_INFO_REDUCED is not set'
```

for fish shell:

```fish
begin; zcat /proc/config.gz || bat /boot/config "/boot/config-"(uname -r); end | grep -E 'CONFIG_(DEBUG_INFO|DEBUG_INFO_BTF|KPROBES|KPROBE_EVENTS|BPF|BPF_SYSCALL|BPF_JIT|BPF_STREAM_PARSER|NET_CLS_ACT|NET_SCH_INGRESS|NET_INGRESS|NET_EGRESS|NET_CLS_BPF|BPF_EVENTS|CGROUPS)=|# CONFIG_DEBUG_INFO_REDUCED is not set'
```

> **Note**: `Armbian` users can follow the [**Upgrade Guide**](user-guide/kernel-upgrade.md) to upgrade the kernel to meet the kernel configuration requirement.

## Installation

### Debian

```shell
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://apt.oixcloud3rd.akinokaede.com/gpg.key \
  | sudo tee /etc/apt/keyrings/oixcloud3rd.asc >/dev/null
sudo chmod 0644 /etc/apt/keyrings/oixcloud3rd.asc

echo '
Types: deb
URIs: https://apt.oixcloud3rd.akinokaede.com/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/oixcloud3rd.asc
' | sudo tee /etc/apt/sources.list.d/oixcloud3rd.sources >/dev/null

sudo apt-get update
sudo apt-get install dae
```

### Red Hat (DNF 5)

```shell
sudo dnf config-manager addrepo --from-repofile=https://public.oixcloud3rd.akinokaede.com/oixcloud3rd.repo
sudo dnf install dae
```

### Red Hat (DNF 4)

```shell
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --add-repo https://public.oixcloud3rd.akinokaede.com/oixcloud3rd.repo
sudo dnf install dae
```

After installing dae from a package repository, use `systemctl` to manage the service:

```shell
# Start dae.
sudo systemctl start dae

# Start dae automatically at boot.
sudo systemctl enable dae
```

### Alpine

See [run on alpine](tutorials/run-on-alpine.md).

### macOS

We provide a hacky way to run dae on your macOS. See [run on macOS](tutorials/run-on-macos.md).

### Docker

Pre-built images are published to the [GitHub Container Registry](https://github.com/oixcloud3rd/dae/pkgs/container/dae):

```shell
docker pull ghcr.io/oixcloud3rd/dae:latest
```

Alternatively, you can use `docker compose`:

```shell
git clone --depth=1 https://github.com/oixcloud3rd/dae
cd dae
docker compose up -d --build
```

## Manual installation

> **Note**: This approach is **ONLY** recommended for `advanced` users. With this approach, users may have flexibility to test various versions of dae. Noted that newly introduced features are sometimes buggy, do it at your own risk.

dae can run as a daemon (systemd) service. See [run-as-daemon](user-guide/run-as-daemon.md).

### Installation Script

See [daeuniverse/dae-installer](https://github.com/daeuniverse/dae-installer) (or [mirror](https://hubmirror.v2raya.org/daeuniverse/dae-installer)).

### Build from scratch

See [Build Guide](user-guide/build-by-yourself.md).

## Minimal Configuration

For minimal bootable config:

```shell
global{}
routing{}
```

However, this config leaves dae no-load state. If you want dae to be in working state, following is a best practice for small config:

```shell
global {
  # Bind to LAN and/or WAN as you want. Replace the interface name to your own.
  #lan_interface: docker0
  wan_interface: auto # Use "auto" to auto detect WAN interface.

  log_level: info
  allow_insecure: false
  auto_config_kernel_parameter: true
}

subscription {
  # Fill in your subscription links here.
}

# See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/dns.md for full examples.
dns {
  upstream {
    googledns: 'tcp+udp://dns.google:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    request {
      qtype(https) -> reject
      fallback: alidns
    }
    response {
      upstream(googledns) -> accept
      ip(geoip:private) && !qname(geosite:cn) -> googledns
      fallback: accept
    }
  }
}

group {
  proxy {
    #filter: name(keyword: HK, keyword: SG)
    policy: min_moving_avg
  }
}

# See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/routing.md for full examples.
routing {
  pname(NetworkManager) -> direct
  dip(224.0.0.0/3, 'ff00::/8') -> direct

  ### Write your rules below.

  # Disable h3 because it usually consumes too much cpu/mem resources.
  l4proto(udp) && dport(443) -> block
  dip(geoip:private) -> direct
  dip(geoip:cn) -> direct
  domain(geosite:cn) -> direct

  fallback: proxy
}
```

See more at [example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae).

If you use PVE, refer to [#37](https://github.com/daeuniverse/dae/discussions/37).

## PPPoE Interface
If you want to proxy PPPoE interface, please set wan/lan_interface to the interface generated by pppd (i.e., ppp0 / pppoe-wan) instead of the physical interface.
If you just using PPPoE interface for wan, simply set wan_interface to "auto".

## Reload and suspend

When the configuration changes, it is convenient to use command to hot reload the configuration, and the existing connection will not be interrupted in the process. When you want to suspend dae, you can use command to pause.

See [Reload and suspend](user-guide/reload-and-suspend.md).

## Troubleshooting

See [Troubleshooting](troubleshooting.md).

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"testing"

	outboundHTTP "github.com/daeuniverse/outbound/dialer/http"
	outboundHysteria2 "github.com/daeuniverse/outbound/dialer/hysteria2"
	outboundShadowsocks "github.com/daeuniverse/outbound/dialer/shadowsocks"
	outboundSnell "github.com/daeuniverse/outbound/dialer/snell"
	outboundSocks "github.com/daeuniverse/outbound/dialer/socks"
	outboundTrojan "github.com/daeuniverse/outbound/dialer/trojan"
	outboundTUIC "github.com/daeuniverse/outbound/dialer/tuic"
	outboundV2Ray "github.com/daeuniverse/outbound/dialer/v2ray"
	protocolSnell "github.com/daeuniverse/outbound/protocol/snell"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestResolveSubscriptionAsClash(t *testing.T) {
	t.Parallel()
	logger := logrus.New()
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	logger.SetLevel(logrus.WarnLevel)
	yamlConfig := `
proxies:
  - name: anytls-node
    type: anytls
    server: 2001:db8::1
    port: 443
    password: anytls-password
    sni: anytls.example
    skip-cert-verify: true
    udp: true
    tfo: false
  - name: snell-node
    type: snell
    server: snell.example
    port: 8443
    psk: snell-password
    version: 4
    reuse: true
    identity: true
    alpn: [h2]
    udp: true
    tfo: false
    obfs-opts:
      mode: ech-tls
      sni: cover.example
      path: /ws
      ech-config: "AAQ+DAAA"
      skip-cert-verify: false
  - name: ignored
    type: vmess
    server: ignored.example
    port: 443
`

	nodes, err := ResolveSubscriptionAsClash(logger, []byte(yamlConfig))
	require.NoError(t, err)
	require.Len(t, nodes, 2)

	anyTLSURL, err := url.Parse(nodes[0])
	require.NoError(t, err)
	require.Equal(t, "anytls", anyTLSURL.Scheme)
	require.Equal(t, "[2001:db8::1]:443", anyTLSURL.Host)
	require.Equal(t, "anytls-password", anyTLSURL.User.Username())
	require.Equal(t, "anytls.example", anyTLSURL.Query().Get("sni"))
	require.Equal(t, "1", anyTLSURL.Query().Get("insecure"))
	require.Equal(t, "anytls-node", anyTLSURL.Fragment)

	snellConfig, err := outboundSnell.ParseURL(nodes[1])
	require.NoError(t, err)
	require.Equal(t, "snell-node", snellConfig.Name)
	require.Equal(t, "ech-tls", snellConfig.Obfs)
	require.NotContains(t, nodes[1], "path=")
	require.True(t, snellConfig.Reuse)
	require.Equal(t, protocolSnell.IdentityV1, snellConfig.Identity)
	require.Equal(t, "snell-ech/1", snellConfig.ALPN)
	require.True(t, snellConfig.LegacyFallback)
	require.Equal(t, 0, snellConfig.Preconnect)
	canonicalSnellURL, err := url.Parse(nodes[1])
	require.NoError(t, err)
	require.Equal(t, "0", canonicalSnellURL.Query().Get("preconnect"))
	require.True(t, snellConfig.SkipVerifyExplicit)
	require.False(t, snellConfig.SkipCertVerify)
	require.Equal(t, "utls", snellConfig.TLSImplementation)
	require.Equal(t, "chrome_auto", snellConfig.ClientFingerprint)
	require.Contains(t, logs.String(), "vmess=1")
	require.NotContains(t, logs.String(), "snell-password")
}

func TestResolveSubscriptionAsClashSnellECHTLSRespectsExplicitTLSSettings(t *testing.T) {
	t.Parallel()
	yamlConfig := `
proxies:
  - name: explicit-tls
    type: snell
    server: snell.example
    port: 443
    psk: password
    version: 4
    obfs-opts:
      mode: ech-tls
      ech-config: "AAQ+DAAA"
      tls-implementation: tls
  - name: explicit-utls
    type: snell
    server: snell.example
    port: 443
    psk: password
    version: 4
    obfs-opts:
      mode: ech-tls
      ech-config: "AAQ+DAAA"
      tls-implementation: utls
      client-fingerprint: firefox_auto
`

	nodes, err := ResolveSubscriptionAsClash(logrus.New(), []byte(yamlConfig))
	require.NoError(t, err)
	require.Len(t, nodes, 2)

	standardTLS, err := outboundSnell.ParseURL(nodes[0])
	require.NoError(t, err)
	require.Equal(t, "tls", standardTLS.TLSImplementation)
	require.Empty(t, standardTLS.ClientFingerprint)
	require.Equal(t, protocolSnell.IdentityV2, standardTLS.Identity)
	require.Equal(t, "snell-ech/1", standardTLS.ALPN)
	require.True(t, standardTLS.SkipVerifyExplicit)
	require.False(t, standardTLS.SkipCertVerify)
	require.Equal(t, 0, standardTLS.Preconnect)

	explicitUTLS, err := outboundSnell.ParseURL(nodes[1])
	require.NoError(t, err)
	require.Equal(t, "utls", explicitUTLS.TLSImplementation)
	require.Equal(t, "firefox_auto", explicitUTLS.ClientFingerprint)
}

func TestNormalizeClashClientFingerprint(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"chrome":   "chrome_auto",
		"firefox":  "firefox_auto",
		"safari":   "safari_auto",
		"iOS":      "ios_auto",
		"android":  "android_11_okhttp",
		"edge":     "edge_auto",
		"360":      "360_auto",
		"qq":       "qq_auto",
		"random":   "random",
		"ios_auto": "ios_auto",
	}
	for clashFingerprint, outboundFingerprint := range tests {
		clashFingerprint := clashFingerprint
		outboundFingerprint := outboundFingerprint
		t.Run(clashFingerprint, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, outboundFingerprint, normalizeClashClientFingerprint(clashFingerprint))
		})
	}
}

func TestResolveClashSnellIdentityCompatibility(t *testing.T) {
	t.Parallel()
	falseValue := false
	trueValue := true
	disabled := 0
	v1 := 1
	v2 := 2

	identity, err := resolveClashSnellIdentity(nil, nil)
	require.NoError(t, err)
	require.Equal(t, 2, identity)
	identity, err = resolveClashSnellIdentity(&falseValue, nil)
	require.NoError(t, err)
	require.Equal(t, 0, identity)
	identity, err = resolveClashSnellIdentity(&trueValue, nil)
	require.NoError(t, err)
	require.Equal(t, 1, identity)
	for expected, nested := range map[int]*int{0: &disabled, 1: &v1, 2: &v2} {
		identity, err = resolveClashSnellIdentity(nil, nested)
		require.NoError(t, err)
		require.Equal(t, expected, identity)
	}
	_, err = resolveClashSnellIdentity(&trueValue, &v2)
	require.ErrorContains(t, err, "conflict")
}

func TestResolveSubscriptionAsClashSnellECHTLSFields(t *testing.T) {
	t.Parallel()
	nodes, err := ResolveSubscriptionAsClash(logrus.New(), []byte(`
proxies:
  - name: all-fields
    type: snell
    server: snell.example
    port: 443
    psk: password
    version: 5
    reuse: true
    alpn: snell-ech/1
    obfs-opts:
      mode: ech-tls
      host: host.example
      sni: sni.example
      alpn: oix-snell/1
      protocol: snell-ech/1
      identity-version: 2
      legacy-fallback: true
      preconnect: 4
      ech-config: "AAQ+DAAA"
      insecure: false
      skip-cert-verify: false
      client-fingerprint: firefox
`))
	require.NoError(t, err)
	require.Len(t, nodes, 1)

	configuration, err := outboundSnell.ParseURL(nodes[0])
	require.NoError(t, err)
	require.Equal(t, 5, configuration.Version)
	require.True(t, configuration.Reuse)
	require.Equal(t, "host.example", configuration.ObfsHost)
	require.Equal(t, "sni.example", configuration.SNI)
	require.Equal(t, "snell-ech/1", configuration.ALPN)
	require.Equal(t, protocolSnell.IdentityV2, configuration.Identity)
	require.True(t, configuration.LegacyFallback)
	require.Equal(t, 4, configuration.Preconnect)
	require.True(t, configuration.SkipVerifyExplicit)
	require.False(t, configuration.SkipCertVerify)
	require.Equal(t, "utls", configuration.TLSImplementation)
	require.Equal(t, "firefox_auto", configuration.ClientFingerprint)
}

func TestResolveSubscriptionAsClashSnellECHTLSRejectsUnsafeOrConflictingOptions(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"unsupported ALPN":                  "alpn: [http/1.1]",
		"multiple top-level ALPN":           "alpn: [snell-ech/1, h2]",
		"nested and top-level conflict":     "alpn: [h2]\n    obfs-opts: {mode: ech-tls, alpn: http/1.1, ech-config: 'AAQ+DAAA'}",
		"identity conflict":                 "identity: true\n    obfs-opts: {mode: ech-tls, identity-version: 2, ech-config: 'AAQ+DAAA'}",
		"insecure":                          "obfs-opts: {mode: ech-tls, insecure: true, ech-config: 'AAQ+DAAA'}",
		"skip certificate verification":     "obfs-opts: {mode: ech-tls, skip-cert-verify: true, ech-config: 'AAQ+DAAA'}",
		"preconnect without reuse":          "obfs-opts: {mode: ech-tls, preconnect: 1, ech-config: 'AAQ+DAAA'}",
		"preconnect above limit":            "reuse: true\n    obfs-opts: {mode: ech-tls, preconnect: 5, ech-config: 'AAQ+DAAA'}",
		"version 6":                         "version: 6\n    reuse: true\n    obfs-opts: {mode: ech-tls, ech-config: 'AAQ+DAAA'}",
		"ECH config file":                   "obfs-opts: {mode: ech-tls, ech-config-file: /tmp/ech.pem, ech-config: 'AAQ+DAAA'}",
		"CA file":                           "obfs-opts: {mode: ech-tls, ca-file: /tmp/ca.pem, ech-config: 'AAQ+DAAA'}",
		"certificate fingerprint":           "obfs-opts: {mode: ech-tls, fingerprint: abc, ech-config: 'AAQ+DAAA'}",
		"client certificate":                "obfs-opts: {mode: ech-tls, certificate: cert, ech-config: 'AAQ+DAAA'}",
		"client private key":                "obfs-opts: {mode: ech-tls, private-key: key, ech-config: 'AAQ+DAAA'}",
		"headers":                           "obfs-opts: {mode: ech-tls, headers: {X-Test: value}, ech-config: 'AAQ+DAAA'}",
		"legacy h2 explicitly disabled":     "alpn: h2\n    obfs-opts: {mode: ech-tls, legacy-fallback: false, ech-config: 'AAQ+DAAA'}",
		"nested protocol and ALPN conflict": "obfs-opts: {mode: ech-tls, alpn: snell-ech/1, protocol: invalid/1, ech-config: 'AAQ+DAAA'}",
	}
	for name, options := range tests {
		name := name
		options := options
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			config := fmt.Sprintf(`
proxies:
  - name: invalid
    type: snell
    server: snell.example
    port: 443
    psk: password
    %s
`, options)
			_, err := ResolveSubscriptionAsClash(logrus.New(), []byte(config))
			require.ErrorContains(t, err, "no valid supported proxies")
		})
	}
}

func TestResolveSubscriptionAsClashSkipsUnsupportedOptions(t *testing.T) {
	t.Parallel()
	yamlConfig := `
proxies:
  - name: unsupported-anytls
    type: anytls
    server: anytls.example
    port: 443
    password: password
    alpn: [h2]
  - name: valid-snell
    type: snell
    server: snell.example
    port: 443
    psk: password
    version: 4
  - name: malformed-anytls
    type: anytls
    server: anytls.example
    port: not-a-number
    password: password
`
	nodes, err := ResolveSubscriptionAsClash(logrus.New(), []byte(yamlConfig))
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	require.True(t, strings.HasPrefix(nodes[0], "snell://"))

	_, err = ResolveSubscriptionAsClash(logrus.New(), []byte(`proxies: [{name: bad, type: anytls, server: a, port: 443, password: p, alpn: [h2]}]`))
	require.ErrorContains(t, err, "no valid supported proxies")
}

func TestResolveSubscriptionAsClashFullProtocolIntersection(t *testing.T) {
	t.Parallel()
	config := `
proxies:
  - {name: ss-node, type: ss, server: 127.0.0.1, port: 10001, cipher: aes-128-gcm, password: secret, udp: true, tfo: true}
  - {name: socks-node, type: socks5, server: 127.0.0.1, port: 10002, username: user, password: pass, udp: true}
  - {name: http-node, type: http, server: 127.0.0.1, port: 10003, username: user, password: pass, tls: true, sni: proxy.example, skip-cert-verify: true}
  - {name: vmess-node, type: vmess, server: 127.0.0.1, port: 10004, uuid: 00000000-0000-0000-0000-000000000001, alterId: 0, cipher: auto, network: tcp, udp: true}
  - {name: vless-node, type: vless, server: 127.0.0.1, port: 10005, uuid: 00000000-0000-0000-0000-000000000002, encryption: none, network: tcp, udp: true}
  - name: trojan-node
    type: trojan
    server: 127.0.0.1
    port: 10006
    password: secret
    sni: example.com
    skip-cert-verify: true
    network: ws
    ws-opts: {path: /trojan, headers: {Host: ws.example.com}}
  - {name: anytls-node, type: anytls, server: 127.0.0.1, port: 10007, password: secret, sni: example.com, skip-cert-verify: true}
  - {name: hysteria2-node, type: hysteria2, server: 127.0.0.1, port: 10008, ports: '10008,10018-10019', password: secret, sni: example.com, skip-cert-verify: true, up: 100 Mbps, down: 200 Mbps, fingerprint: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}
  - {name: tuic-node, type: tuic, server: 127.0.0.1, port: 10009, uuid: 00000000-0000-0000-0000-000000000003, password: secret, sni: example.com, skip-cert-verify: true, congestion-controller: bbr, udp-relay-mode: quic, alpn: [h3]}
  - {name: snell-node, type: snell, server: 127.0.0.1, port: 10010, psk: secret, version: 4}
`

	nodes, err := ResolveSubscriptionAsClash(logrus.New(), []byte(config))
	require.NoError(t, err)
	require.Len(t, nodes, 10)

	links := clashLinksByName(t, nodes)
	ss, err := outboundShadowsocks.ParseSSURL(links["ss-node"])
	require.NoError(t, err)
	require.Equal(t, "aes-128-gcm", ss.Cipher)

	socks, err := outboundSocks.ParseSocksURL(links["socks-node"])
	require.NoError(t, err)
	require.Equal(t, "user", socks.Username)

	httpProxy, err := outboundHTTP.ParseHTTPURL(links["http-node"])
	require.NoError(t, err)
	require.Equal(t, "https", httpProxy.Protocol)
	require.True(t, httpProxy.AllowInsecure)

	vmess, err := outboundV2Ray.ParseVmessURL(links["vmess-node"])
	require.NoError(t, err)
	require.Equal(t, "tcp", vmess.Net)

	vless, err := outboundV2Ray.ParseVlessURL(links["vless-node"])
	require.NoError(t, err)
	require.Equal(t, "tcp", vless.Net)

	trojan, err := outboundTrojan.ParseTrojanURL(links["trojan-node"])
	require.NoError(t, err)
	require.Equal(t, "ws", trojan.Type)
	require.Equal(t, "/trojan", trojan.Path)

	hysteria2, err := outboundHysteria2.ParseHysteria2URL(links["hysteria2-node"])
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:10008,10018-10019", hysteria2.Server)
	require.EqualValues(t, 12_500_000, hysteria2.MaxTx)
	require.EqualValues(t, 25_000_000, hysteria2.MaxRx)

	tuic, err := outboundTUIC.ParseTuicURL(links["tuic-node"])
	require.NoError(t, err)
	require.Equal(t, "quic", tuic.UdpRelayMode)
	require.Equal(t, []string{"h3"}, tuic.Alpn)
}

func clashLinksByName(t *testing.T, nodes []string) map[string]string {
	t.Helper()
	links := make(map[string]string, len(nodes))
	for _, link := range nodes {
		switch {
		case strings.HasPrefix(link, "vmess://"):
			configuration, err := outboundV2Ray.ParseVmessURL(link)
			require.NoError(t, err)
			links[configuration.Ps] = link
		case strings.HasPrefix(link, "hysteria2://"), strings.HasPrefix(link, "hy2://"):
			configuration, err := outboundHysteria2.ParseHysteria2URL(link)
			require.NoError(t, err)
			links[configuration.Name] = link
		default:
			u, err := url.Parse(link)
			require.NoError(t, err)
			links[u.Fragment] = link
		}
	}
	return links
}

func TestResolveSubscriptionAsClashV2RayTransportMatrix(t *testing.T) {
	t.Parallel()
	config := `
proxies:
  - name: vmess-ws
    type: vmess
    server: vmess.example
    port: 443
    uuid: 00000000-0000-0000-0000-000000000011
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    servername: tls.example
    ws-opts: {path: /ws, headers: {Host: ws.example}}
  - name: vmess-grpc
    type: vmess
    server: vmess.example
    port: 443
    uuid: 00000000-0000-0000-0000-000000000012
    network: grpc
    tls: true
    grpc-opts: {grpc-service-name: service}
  - name: vmess-http
    type: vmess
    server: vmess.example
    port: 443
    uuid: 00000000-0000-0000-0000-000000000013
    network: http
    tls: true
    alpn: [h2]
    http-opts: {method: GET, path: [/http], headers: {Host: [http.example]}}
  - name: vless-h2
    type: vless
    server: vless.example
    port: 443
    uuid: 00000000-0000-0000-0000-000000000014
    network: h2
    tls: true
    alpn: [h2]
    h2-opts: {path: /h2, host: [h2.example]}
  - name: vless-httpupgrade
    type: vless
    server: vless.example
    port: 443
    uuid: 00000000-0000-0000-0000-000000000015
    network: ws
    tls: true
    ws-opts: {path: /upgrade, headers: {Host: upgrade.example}, v2ray-http-upgrade: true}
  - name: vless-reality
    type: vless
    server: reality.example
    port: 443
    uuid: 00000000-0000-0000-0000-000000000016
    network: tcp
    servername: cover.example
    client-fingerprint: chrome
    reality-opts: {public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, short-id: 0123456789abcdef}
  - name: trojan-grpc
    type: trojan
    server: trojan.example
    port: 443
    password: secret
    sni: cover.example
    network: grpc
    grpc-opts: {grpc-service-name: trojan-service}
  - name: trojan-httpupgrade
    type: trojan
    server: trojan.example
    port: 443
    password: secret
    network: ws
    ws-opts: {path: /upgrade, headers: {Host: upgrade.example}, v2ray-http-upgrade: true}
`

	nodes, err := ResolveSubscriptionAsClash(logrus.New(), []byte(config))
	require.NoError(t, err)
	require.Len(t, nodes, 8)
	links := clashLinksByName(t, nodes)

	expectedV2Ray := map[string]struct {
		network string
		path    string
		host    string
	}{
		"vmess-ws":          {network: "ws", path: "/ws", host: "ws.example"},
		"vmess-grpc":        {network: "grpc", path: "service"},
		"vmess-http":        {network: "http", path: "/http", host: "http.example"},
		"vless-h2":          {network: "h2", path: "/h2", host: "h2.example"},
		"vless-httpupgrade": {network: "httpupgrade", path: "/upgrade", host: "upgrade.example"},
	}
	for name, expected := range expectedV2Ray {
		link := links[name]
		var configuration *outboundV2Ray.V2Ray
		if strings.HasPrefix(link, "vmess://") {
			configuration, err = outboundV2Ray.ParseVmessURL(link)
		} else {
			configuration, err = outboundV2Ray.ParseVlessURL(link)
		}
		require.NoError(t, err, name)
		require.Equal(t, expected.network, configuration.Net, name)
		require.Equal(t, expected.path, configuration.Path, name)
		require.Equal(t, expected.host, configuration.Host, name)
	}

	reality, err := outboundV2Ray.ParseVlessURL(links["vless-reality"])
	require.NoError(t, err)
	require.Equal(t, "reality", reality.TLS)
	require.Equal(t, "chrome_auto", reality.Fingerprint)
	require.Equal(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", reality.PublicKey)

	grpcTrojan, err := outboundTrojan.ParseTrojanURL(links["trojan-grpc"])
	require.NoError(t, err)
	require.Equal(t, "grpc", grpcTrojan.Type)
	require.Equal(t, "trojan-service", grpcTrojan.ServiceName)

	upgradeTrojan, err := outboundTrojan.ParseTrojanURL(links["trojan-httpupgrade"])
	require.NoError(t, err)
	require.Equal(t, "httpupgrade", upgradeTrojan.Type)
	require.Equal(t, "/upgrade", upgradeTrojan.Path)
}

func TestResolveSubscriptionAsClashShadowsocksPlugins(t *testing.T) {
	t.Parallel()
	config := `
proxies:
  - name: obfs-node
    type: ss
    server: ss.example
    port: 443
    cipher: aes-128-gcm
    password: secret
    plugin: obfs
    plugin-opts: {mode: tls, host: cover.example}
  - name: v2ray-node
    type: ss
    server: ss.example
    port: 443
    cipher: chacha20-ietf-poly1305
    password: secret
    plugin: v2ray-plugin
    plugin-opts: {mode: websocket, tls: true, host: ws.example, path: /}
`

	nodes, err := ResolveSubscriptionAsClash(logrus.New(), []byte(config))
	require.NoError(t, err)
	require.Len(t, nodes, 2)
	links := clashLinksByName(t, nodes)

	obfs, err := outboundShadowsocks.ParseSSURL(links["obfs-node"])
	require.NoError(t, err)
	require.Equal(t, "simple-obfs", obfs.Plugin.Name)
	require.Equal(t, "tls", obfs.Plugin.Opts.Obfs)
	require.Equal(t, "cover.example", obfs.Plugin.Opts.Host)

	v2ray, err := outboundShadowsocks.ParseSSURL(links["v2ray-node"])
	require.NoError(t, err)
	require.Equal(t, "v2ray-plugin", v2ray.Plugin.Name)
	require.Equal(t, "tls", v2ray.Plugin.Opts.Tls)
	require.Equal(t, "ws.example", v2ray.Plugin.Opts.Host)
}

func TestResolveSubscriptionAsClashStrictlySkipsLossyNodes(t *testing.T) {
	t.Parallel()
	logger := logrus.New()
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	logger.SetLevel(logrus.WarnLevel)
	config := `
proxies:
  - {name: valid, type: ss, server: ss.example, port: 443, cipher: aes-128-gcm, password: secret, udp: true, tfo: true, mptcp: false}
  - {name: unknown-semantic, type: ss, server: ss.example, port: 443, cipher: aes-128-gcm, password: secret, mptcp: true}
  - {name: vmess-fingerprint, type: vmess, server: vmess.example, port: 443, uuid: 00000000-0000-0000-0000-000000000021, network: tcp, tls: true, client-fingerprint: chrome}
  - {name: vless-insecure, type: vless, server: vless.example, port: 443, uuid: 00000000-0000-0000-0000-000000000022, network: tcp, tls: true, skip-cert-verify: true}
  - {name: trojan-alpn, type: trojan, server: trojan.example, port: 443, password: secret, alpn: [h2]}
  - {name: hysteria-obfs, type: hysteria2, server: hy.example, port: 443, password: secret, obfs: salamander, obfs-password: secret}
  - {name: tuic-rtt, type: tuic, server: tuic.example, port: 443, uuid: 00000000-0000-0000-0000-000000000023, password: secret, reduce-rtt: true}
`

	nodes, err := ResolveSubscriptionAsClash(logger, []byte(config))
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	valid, err := outboundShadowsocks.ParseSSURL(nodes[0])
	require.NoError(t, err)
	require.Equal(t, "valid", valid.Name)
	require.Contains(t, logs.String(), "ss=1")
	require.Contains(t, logs.String(), "vmess=1")
	require.Contains(t, logs.String(), "vless=1")
	require.Contains(t, logs.String(), "trojan=1")
	require.Contains(t, logs.String(), "hysteria2=1")
	require.Contains(t, logs.String(), "tuic=1")
}

func TestResolveSubscriptionAsClashSyntheticSnellFixture(t *testing.T) {
	t.Parallel()
	var fixture strings.Builder
	fixture.WriteString("proxies:\n")
	for index := 0; index < 136; index++ {
		fmt.Fprintf(&fixture, "  - {name: 'node-%03d', type: snell, server: node-%03d.example, port: 14888, psk: fixture-password, version: 4, reuse: true, udp: true, tfo: false, identity: true, obfs-opts: {mode: ech-tls, sni: cover.example, path: /ws, ech-config: 'AAQ+DAAA', skip-cert-verify: false}}\n", index, index)
	}
	nodes, err := ResolveSubscriptionAsClash(logrus.New(), []byte(fixture.String()))
	require.NoError(t, err)
	require.Len(t, nodes, 136)
}

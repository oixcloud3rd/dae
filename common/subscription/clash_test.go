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

	outboundSnell "github.com/daeuniverse/outbound/dialer/snell"
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
	require.Equal(t, "/ws", snellConfig.Path)
	require.True(t, snellConfig.Reuse)
	require.True(t, snellConfig.Identity)
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
      path: /ws
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
      path: /ws
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
	require.ErrorContains(t, err, "no valid AnyTLS or Snell")
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

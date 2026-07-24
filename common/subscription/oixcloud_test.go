/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	outboundSnell "github.com/daeuniverse/outbound/dialer/snell"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const testOIXCloudHMACKey = "test-oixcloud-subscription-key"

func TestRedactSubscription(t *testing.T) {
	t.Parallel()
	require.Equal(t, "cloud:oixcloud://<redacted>", RedactSubscription("cloud:oixcloud://secret-token?foo=bar"))
	require.Equal(t, "oixcloud+file://<redacted>", RedactSubscription("oixcloud+file://secret-token"))
	require.Equal(t, "oixcloud://<redacted>", RedactSubscription("oixcloud://bad%token"))
	require.Equal(t, "https://example.com/sub", RedactSubscription("https://example.com/sub"))
}

func TestResolveSubscriptionAsOIXCloud(t *testing.T) {
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

	nodes, err := ResolveSubscriptionAsOIXCloud(logger, []byte(yamlConfig))
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
	require.Contains(t, logs.String(), "vmess=1")
	require.NotContains(t, logs.String(), "snell-password")
}

func TestResolveSubscriptionAsOIXCloudSkipsUnsupportedOptions(t *testing.T) {
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
	nodes, err := ResolveSubscriptionAsOIXCloud(logrus.New(), []byte(yamlConfig))
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	require.True(t, strings.HasPrefix(nodes[0], "snell://"))

	_, err = ResolveSubscriptionAsOIXCloud(logrus.New(), []byte(`proxies: [{name: bad, type: anytls, server: a, port: 443, password: p, alpn: [h2]}]`))
	require.ErrorContains(t, err, "no valid AnyTLS or Snell")
}

func TestResolveSubscriptionAsOIXCloudSyntheticSnellFixture(t *testing.T) {
	t.Parallel()
	var fixture strings.Builder
	fixture.WriteString("proxies:\n")
	for index := 0; index < 136; index++ {
		fmt.Fprintf(&fixture, "  - {name: 'node-%03d', type: snell, server: node-%03d.example, port: 14888, psk: fixture-password, version: 4, reuse: true, udp: true, tfo: false, identity: true, obfs-opts: {mode: ech-tls, sni: cover.example, path: /ws, ech-config: 'AAQ+DAAA', skip-cert-verify: false}}\n", index, index)
	}
	nodes, err := ResolveSubscriptionAsOIXCloud(logrus.New(), []byte(fixture.String()))
	require.NoError(t, err)
	require.Len(t, nodes, 136)
}

func TestFetchOIXCloudConfigPlainAndSigned(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_750_000_000, 0)
	plain := []byte("proxies: []\n")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "Bearer token-value", request.Header.Get("Authorization"))
		require.Equal(t, oixCloudUserAgent, request.Header.Get("User-Agent"))
		require.Equal(t, "value", request.URL.Query().Get("key"))
		timestamp := request.Header.Get("X-Flclash-Timestamp")
		pubKey := request.Header.Get("X-Flclash-Age-Pubkey")
		require.Equal(t, oixCloudHMAC(testOIXCloudHMACKey, timestamp+"."+pubKey), request.Header.Get("X-Flclash-Signature"))
		encoded := base64.StdEncoding.EncodeToString(plain)
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Flclash-Response-Signature", oixCloudHMAC(testOIXCloudHMACKey, timestamp+"."+encoded))
		require.NoError(t, json.NewEncoder(writer).Encode(oixCloudAPIResponse{Config: encoded}))
	}))
	defer server.Close()

	got, err := fetchOIXCloudConfig(context.Background(), server.Client(), server.URL, "token-value", url.Values{"key": {"value"}}, testOIXCloudHMACKey, now)
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

func TestFetchOIXCloudConfigDecryptsAgeArmor(t *testing.T) {
	t.Parallel()
	plain := []byte("proxies: []\n")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recipient, err := age.ParseX25519Recipient(request.Header.Get("X-Flclash-Age-Pubkey"))
		require.NoError(t, err)
		var encrypted bytes.Buffer
		armored := armor.NewWriter(&encrypted)
		ciphertext, err := age.Encrypt(armored, recipient)
		require.NoError(t, err)
		_, err = ciphertext.Write(plain)
		require.NoError(t, err)
		require.NoError(t, ciphertext.Close())
		require.NoError(t, armored.Close())
		encoded := base64.StdEncoding.EncodeToString(encrypted.Bytes())
		require.NoError(t, json.NewEncoder(writer).Encode(oixCloudAPIResponse{Config: encoded}))
	}))
	defer server.Close()

	got, err := fetchOIXCloudConfig(context.Background(), server.Client(), server.URL, "token", nil, testOIXCloudHMACKey, time.Unix(1, 0))
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

func TestFetchOIXCloudConfigRejectsInvalidSignature(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Flclash-Response-Signature", "invalid")
		require.NoError(t, json.NewEncoder(writer).Encode(oixCloudAPIResponse{Config: base64.StdEncoding.EncodeToString([]byte("proxies: []"))}))
	}))
	defer server.Close()
	_, err := fetchOIXCloudConfig(context.Background(), server.Client(), server.URL, "token", nil, testOIXCloudHMACKey, time.Unix(1, 0))
	require.ErrorContains(t, err, "invalid oixCloud response signature")
}

func TestOIXCloudFileSubscriptionCachesAndFallsBack(t *testing.T) {
	t.Parallel()
	configDir := t.TempDir()
	yamlConfig := []byte("proxies: [{name: cached, type: snell, server: snell.example, port: 443, psk: password, version: 4}]\n")
	workingServer := newOIXCloudTestServer(t, yamlConfig, http.StatusOK)
	u, err := url.Parse("oixcloud+file://token?variant=test")
	require.NoError(t, err)
	tag, nodes, err := resolveOIXCloudSubscriptionWithOptions(logrus.New(), workingServer.Client(), configDir, "cloud", u, workingServer.URL, testOIXCloudHMACKey, time.Unix(1, 0))
	require.NoError(t, err)
	require.Equal(t, "cloud", tag)
	require.Len(t, nodes, 1)
	workingServer.Close()

	cachePath := filepath.Join(configDir, "persist.d", "cloud.sub")
	info, err := os.Stat(cachePath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	require.Equal(t, yamlConfig, mustReadFile(t, cachePath))

	failingServer := newOIXCloudTestServer(t, nil, http.StatusBadGateway)
	defer failingServer.Close()
	tag, nodes, err = resolveOIXCloudSubscriptionWithOptions(logrus.New(), failingServer.Client(), configDir, "cloud", u, failingServer.URL, testOIXCloudHMACKey, time.Unix(2, 0))
	require.NoError(t, err)
	require.Equal(t, "cloud", tag)
	require.Len(t, nodes, 1)
}

func TestOIXCloudFileSubscriptionRequiresTag(t *testing.T) {
	t.Parallel()
	u, err := url.Parse("oixcloud+file://token")
	require.NoError(t, err)
	_, _, err = resolveOIXCloudSubscriptionWithOptions(logrus.New(), http.DefaultClient, t.TempDir(), "", u, "https://example.invalid", testOIXCloudHMACKey, time.Unix(1, 0))
	require.EqualError(t, err, "tag is required for oixcloud+file subscription")
}

func TestOIXCloudFileSubscriptionKeepsLastValidCache(t *testing.T) {
	t.Parallel()
	configDir := t.TempDir()
	cachedConfig := []byte("proxies: [{name: cached, type: snell, server: cached.example, port: 443, psk: password, version: 4}]\n")
	require.NoError(t, writeOIXCloudCache(configDir, "cloud", cachedConfig))
	invalidServer := newOIXCloudTestServer(t, []byte("proxies: []\n"), http.StatusOK)
	defer invalidServer.Close()
	u, err := url.Parse("oixcloud+file://token")
	require.NoError(t, err)
	_, nodes, err := resolveOIXCloudSubscriptionWithOptions(logrus.New(), invalidServer.Client(), configDir, "cloud", u, invalidServer.URL, testOIXCloudHMACKey, time.Unix(1, 0))
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	require.Contains(t, nodes[0], "cached.example")
	require.Equal(t, cachedConfig, mustReadFile(t, filepath.Join(configDir, "persist.d", "cloud.sub")))
}

func TestOIXCloudSubscriptionRequiresEmbeddedKey(t *testing.T) {
	t.Parallel()
	u, err := url.Parse("oixcloud://token")
	require.NoError(t, err)
	_, _, err = resolveOIXCloudSubscriptionWithOptions(logrus.New(), http.DefaultClient, t.TempDir(), "cloud", u, "https://example.invalid", "", time.Unix(1, 0))
	require.ErrorContains(t, err, "inject OIXCLOUD_SUBSCRIPTION_HMAC_KEY")
}

func newOIXCloudTestServer(t *testing.T, plain []byte, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if status < 200 || status >= 300 {
			writer.WriteHeader(status)
			return
		}
		encoded := base64.StdEncoding.EncodeToString(plain)
		timestamp := request.Header.Get("X-Flclash-Timestamp")
		writer.Header().Set("X-Flclash-Response-Signature", oixCloudHMAC(testOIXCloudHMACKey, timestamp+"."+encoded))
		writer.WriteHeader(status)
		require.NoError(t, json.NewEncoder(writer).Encode(oixCloudAPIResponse{Config: encoded}))
	}))
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

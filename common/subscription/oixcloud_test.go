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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const testOIXCloudHMACKey = "test-oixcloud-subscription-key"

func TestOIXCloudManagedConfigEndpoints(t *testing.T) {
	t.Parallel()
	require.Equal(t, "https://oics.net/api/v1/managed/flclash/direct", oixCloudPrimaryAPIEndpoint)
	require.Equal(t, "https://oix-api.dler.io/api/v1/managed/flclash/direct", oixCloudFallbackAPIEndpoint)
}

func TestRedactSubscription(t *testing.T) {
	t.Parallel()
	require.Equal(t, "cloud:oixcloud://<redacted>", RedactSubscription("cloud:oixcloud://secret-token?foo=bar"))
	require.Equal(t, "oixcloud+file://<redacted>", RedactSubscription("oixcloud+file://secret-token"))
	require.Equal(t, "oixcloud://<redacted>", RedactSubscription("oixcloud://bad%token"))
	require.Equal(t, "https://example.com/sub", RedactSubscription("https://example.com/sub"))
}

func TestSanitizedOIXCloudRequestErrorKeepsCauseWithoutURL(t *testing.T) {
	t.Parallel()
	err := sanitizedOIXCloudRequestError(&url.Error{
		Op:  "Get",
		URL: "https://oix-api.dler.io/path?secret=query-value",
		Err: errors.New("dial timeout"),
	})
	require.ErrorContains(t, err, "dial timeout")
	require.NotContains(t, err.Error(), "query-value")
	require.NotContains(t, err.Error(), "oix-api.dler.io/path")
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

func TestResolveOIXCloudSubscriptionFallsBackToBackupAPI(t *testing.T) {
	t.Parallel()
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer primary.Close()

	yamlConfig := []byte("proxies: [{name: backup, type: snell, server: backup.example, port: 443, psk: password, version: 4}]\n")
	backup := newOIXCloudTestServer(t, yamlConfig, http.StatusOK)
	defer backup.Close()
	u, err := url.Parse("oixcloud://token?client=dae")
	require.NoError(t, err)
	_, nodes, err := resolveOIXCloudSubscriptionWithEndpoints(
		logrus.New(),
		backup.Client(),
		t.TempDir(),
		"cloud",
		u,
		[]string{primary.URL, backup.URL},
		testOIXCloudHMACKey,
		time.Unix(1, 0),
	)
	require.NoError(t, err)
	require.EqualValues(t, 1, primaryCalls.Load())
	require.Len(t, nodes, 1)
	require.Contains(t, nodes[0], "backup.example")
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

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
)

const (
	oixCloudManagedConfigPath   = "/api/v1/managed/flclash/direct"
	oixCloudPrimaryAPIEndpoint  = "https://" + consts.OIXCloudManagedConfigHost + oixCloudManagedConfigPath
	oixCloudFallbackAPIEndpoint = "https://" + consts.OIXCloudManagedConfigFallbackHost + oixCloudManagedConfigPath
	oixCloudUserAgent           = "FlClash for oixCloud"
	oixCloudResponseLimit       = 16 * 1024 * 1024
	oixCloudConfigLimit         = 10 * 1024 * 1024
)

var (
	oixCloudAgeArmorPrefix         = []byte("-----BEGIN AGE ENCRYPTED FILE-----")
	oixCloudManagedConfigEndpoints = []string{oixCloudPrimaryAPIEndpoint, oixCloudFallbackAPIEndpoint}
)

type oixCloudAPIResponse struct {
	Ret      any    `json:"ret"`
	Config   string `json:"config"`
	Userinfo string `json:"userinfo"`
	Message  string `json:"message"`
	Msg      string `json:"msg"`
	Error    string `json:"error"`
}

// RedactSubscription hides credentials carried by oixCloud subscription URLs.
// Other subscription formats retain their historical log representation.
func RedactSubscription(raw string) string {
	tag, link := common.GetTagFromLinkLikePlaintext(raw)
	lowerLink := strings.ToLower(link)
	for _, scheme := range []string{"oixcloud", "oixcloud+file"} {
		if strings.HasPrefix(lowerLink, scheme+":") {
			redacted := scheme + "://<redacted>"
			if tag != "" {
				return tag + ":" + redacted
			}
			return redacted
		}
	}
	u, err := url.Parse(link)
	if err != nil || !isOIXCloudScheme(u.Scheme) {
		return raw
	}
	redacted := strings.ToLower(u.Scheme) + "://<redacted>"
	if tag != "" {
		return tag + ":" + redacted
	}
	return redacted
}

func isOIXCloudScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "oixcloud", "oixcloud+file":
		return true
	default:
		return false
	}
}

func resolveOIXCloudSubscription(log *logrus.Logger, client *http.Client, configDir, tag string, u *url.URL) (string, []string, error) {
	return resolveOIXCloudSubscriptionWithEndpoints(
		log,
		client,
		configDir,
		tag,
		u,
		oixCloudManagedConfigEndpoints,
		consts.OIXCloudSubscriptionHMACKey,
		time.Now(),
	)
}

func resolveOIXCloudSubscriptionWithOptions(log *logrus.Logger, client *http.Client, configDir, tag string, u *url.URL, endpoint, key string, now time.Time) (string, []string, error) {
	return resolveOIXCloudSubscriptionWithEndpoints(log, client, configDir, tag, u, []string{endpoint}, key, now)
}

func resolveOIXCloudSubscriptionWithEndpoints(log *logrus.Logger, client *http.Client, configDir, tag string, u *url.URL, endpoints []string, key string, now time.Time) (string, []string, error) {
	persist := strings.EqualFold(u.Scheme, "oixcloud+file")
	if persist && tag == "" {
		return "", nil, errors.New("tag is required for oixcloud+file subscription")
	}
	if u.User != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.Fragment != "" {
		return "", nil, errors.New("invalid oixCloud subscription URL")
	}
	if strings.TrimSpace(key) == "" {
		return "", nil, errors.New("missing oixCloud subscription HMAC key: inject OIXCLOUD_SUBSCRIPTION_HMAC_KEY at build time")
	}
	if len(endpoints) == 0 {
		return "", nil, errors.New("oixCloud managed configuration API is not configured")
	}

	var remoteErr error
	for endpointIndex, endpoint := range endpoints {
		plain, fetchErr := fetchOIXCloudConfig(
			context.Background(),
			client,
			endpoint,
			u.Host,
			u.Query(),
			key,
			now,
		)
		if fetchErr == nil {
			nodes, parseErr := ResolveSubscriptionAsClash(log, plain)
			if parseErr == nil {
				if persist {
					if err := writeOIXCloudCache(configDir, tag, plain); err != nil {
						return "", nil, fmt.Errorf("persist oixCloud subscription: %w", err)
					}
				}
				return tag, nodes, nil
			}
			remoteErr = parseErr
		} else {
			remoteErr = fetchErr
		}
		if endpointIndex+1 < len(endpoints) && log != nil {
			log.Warnln("oixCloud managed configuration API failed; trying fallback API")
		}
	}

	if !persist {
		return "", nil, remoteErr
	}
	log.Warnln("failed to refresh oixCloud subscription; trying cached configuration")
	cached, cacheErr := readOIXCloudCache(configDir, tag)
	if cacheErr != nil {
		return "", nil, fmt.Errorf("oixCloud subscription refresh failed and cache is unavailable: %w", cacheErr)
	}
	nodes, cacheErr := ResolveSubscriptionAsClash(log, cached)
	if cacheErr != nil {
		return "", nil, fmt.Errorf("oixCloud subscription refresh failed and cache is invalid: %w", cacheErr)
	}
	return tag, nodes, nil
}

func fetchOIXCloudConfig(ctx context.Context, client *http.Client, endpoint, token string, query url.Values, key string, now time.Time) ([]byte, error) {
	if client == nil {
		return nil, errors.New("nil HTTP client")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("empty oixCloud token")
	}
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("empty oixCloud subscription HMAC key")
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate age identity: %w", err)
	}
	pubKey := identity.Recipient().String()
	timestamp := strconv.FormatInt(now.Unix(), 10)

	target, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("invalid oixCloud managed configuration endpoint")
	}
	target.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create oixCloud request: %w", err)
	}
	req.Header.Set("User-Agent", oixCloudUserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Flclash-Timestamp", timestamp)
	req.Header.Set("X-Flclash-Signature", oixCloudHMAC(key, timestamp+"."+pubKey))
	req.Header.Set("X-Flclash-Age-Pubkey", pubKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, sanitizedOIXCloudRequestError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readLimited(resp.Body, oixCloudResponseLimit)
	if err != nil {
		return nil, fmt.Errorf("read oixCloud response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("oixCloud managed configuration returned HTTP %d", resp.StatusCode)
	}

	var payload oixCloudAPIResponse
	if err = json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse oixCloud response: %w", err)
	}
	if payload.Config == "" {
		return nil, errors.New("oixCloud response has empty configuration")
	}
	if responseSignature := strings.TrimSpace(resp.Header.Get("X-Flclash-Response-Signature")); responseSignature != "" {
		expected := oixCloudHMAC(key, timestamp+"."+payload.Config)
		if !hmac.Equal([]byte(responseSignature), []byte(expected)) {
			return nil, errors.New("invalid oixCloud response signature")
		}
	}
	configBytes, err := base64.StdEncoding.DecodeString(payload.Config)
	if err != nil {
		return nil, errors.New("decode oixCloud configuration")
	}
	if len(configBytes) > oixCloudConfigLimit {
		return nil, fmt.Errorf("oixCloud configuration exceeds %d bytes", oixCloudConfigLimit)
	}
	trimmed := bytes.TrimSpace(configBytes)
	if bytes.HasPrefix(trimmed, oixCloudAgeArmorPrefix) {
		configBytes, err = decryptOIXCloudAge(trimmed, identity)
		if err != nil {
			return nil, err
		}
	}
	return configBytes, nil
}

func sanitizedOIXCloudRequestError(err error) error {
	var urlError *url.Error
	if errors.As(err, &urlError) && urlError.Err != nil {
		err = urlError.Err
	}
	return fmt.Errorf("request oixCloud managed configuration failed: %w", err)
}

func decryptOIXCloudAge(ciphertext []byte, identity *age.X25519Identity) ([]byte, error) {
	reader, err := age.Decrypt(armor.NewReader(bytes.NewReader(ciphertext)), identity)
	if err != nil {
		return nil, errors.New("decrypt oixCloud configuration")
	}
	plain, err := readLimited(reader, oixCloudConfigLimit)
	if err != nil {
		return nil, fmt.Errorf("read decrypted oixCloud configuration: %w", err)
	}
	return plain, nil
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("content exceeds %d bytes", limit)
	}
	return data, nil
}

func oixCloudHMAC(key, message string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func oixCloudCachePath(configDir, tag string) (string, error) {
	dir := filepath.Join(configDir, "persist.d")
	path := filepath.Join(dir, tag+".sub")
	if err := common.EnsureFileInSubDir(path, configDir); err != nil {
		return "", err
	}
	return path, nil
}

func writeOIXCloudCache(configDir, tag string, data []byte) error {
	path, err := oixCloudCachePath(configDir, tag)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".oixcloud-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(data)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(temporaryPath, path)
}

func readOIXCloudCache(configDir, tag string) ([]byte, error) {
	path, err := oixCloudCachePath(configDir, tag)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, errors.New("cached subscription is a directory")
	}
	if info.Mode()&0o037 != 0 {
		return nil, fmt.Errorf("cached subscription permissions %04o are too open", info.Mode()&0o777)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return readLimited(file, oixCloudConfigLimit)
}

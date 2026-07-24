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
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	outboundSnell "github.com/daeuniverse/outbound/dialer/snell"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
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

type oixCloudConfig struct {
	Proxies []yaml.Node `yaml:"proxies"`
}

type oixCloudProxy struct {
	Name               string             `yaml:"name"`
	Type               string             `yaml:"type"`
	Server             string             `yaml:"server"`
	Port               int                `yaml:"port"`
	Password           string             `yaml:"password"`
	PSK                string             `yaml:"psk"`
	Version            int                `yaml:"version"`
	UserKey            string             `yaml:"userkey"`
	UserKeyDashed      string             `yaml:"user-key"`
	Mode               string             `yaml:"mode"`
	Reuse              *bool              `yaml:"reuse"`
	Identity           *bool              `yaml:"identity"`
	SNI                string             `yaml:"sni"`
	ServerName         string             `yaml:"server-name"`
	SkipCertVerify     *bool              `yaml:"skip-cert-verify"`
	ALPN               stringList         `yaml:"alpn"`
	ClientFingerprint  string             `yaml:"client-fingerprint"`
	UDP                *bool              `yaml:"udp"`
	TFO                *bool              `yaml:"tfo"`
	ObfsOpts           *oixCloudSnellObfs `yaml:"obfs-opts"`
	UnsupportedOptions map[string]any     `yaml:",inline"`
}

type oixCloudSnellObfs struct {
	Mode               string         `yaml:"mode"`
	Host               string         `yaml:"host"`
	SNI                string         `yaml:"sni"`
	WSHost             string         `yaml:"ws-host"`
	Path               string         `yaml:"path"`
	ECHConfig          string         `yaml:"ech-config"`
	SkipCertVerify     *bool          `yaml:"skip-cert-verify"`
	TLSImplementation  string         `yaml:"tls-implementation"`
	ClientFingerprint  string         `yaml:"client-fingerprint"`
	UnsupportedOptions map[string]any `yaml:",inline"`
}

// stringList accepts either a YAML scalar or sequence. Clash-compatible
// configurations use both forms for ALPN.
type stringList []string

func (list *stringList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if strings.TrimSpace(node.Value) == "" {
			*list = nil
		} else {
			*list = []string{node.Value}
		}
		return nil
	case yaml.SequenceNode:
		var values []string
		if err := node.Decode(&values); err != nil {
			return err
		}
		*list = values
		return nil
	default:
		return errors.New("ALPN must be a string or string list")
	}
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
			nodes, parseErr := ResolveSubscriptionAsOIXCloud(log, plain)
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
	nodes, cacheErr := ResolveSubscriptionAsOIXCloud(log, cached)
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

// ResolveSubscriptionAsOIXCloud converts the supported Clash proxy entries to
// canonical outbound links. Unsupported types and malformed supported entries
// are skipped so one bad node does not make the complete subscription unusable.
func ResolveSubscriptionAsOIXCloud(log *logrus.Logger, data []byte) ([]string, error) {
	var config oixCloudConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse oixCloud YAML: %w", err)
	}
	if config.Proxies == nil {
		return nil, errors.New("oixCloud YAML does not contain proxies")
	}

	nodes := make([]string, 0, len(config.Proxies))
	unsupported := make(map[string]int)
	invalid := make(map[string]int)
	for _, proxyNode := range config.Proxies {
		var header struct {
			Type string `yaml:"type"`
		}
		if err := proxyNode.Decode(&header); err != nil {
			invalid["<missing>"]++
			continue
		}
		proxyType := strings.ToLower(strings.TrimSpace(header.Type))
		if proxyType != "anytls" && proxyType != "snell" {
			if proxyType == "" {
				proxyType = "<missing>"
			}
			unsupported[proxyType]++
			continue
		}
		var proxy oixCloudProxy
		if err := proxyNode.Decode(&proxy); err != nil {
			invalid[proxyType]++
			if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
				log.WithError(err).Debugf("Skipping invalid oixCloud %s proxy", proxyType)
			}
			continue
		}
		var (
			link string
			err  error
		)
		switch proxyType {
		case "anytls":
			link, err = proxy.anyTLSLink()
		case "snell":
			link, err = proxy.snellLink()
		}
		if err != nil {
			invalid[proxyType]++
			if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
				log.WithError(err).Debugf("Skipping invalid oixCloud %s proxy", proxyType)
			}
			continue
		}
		nodes = append(nodes, link)
	}
	logOIXCloudSkipped(log, "unsupported", unsupported)
	logOIXCloudSkipped(log, "invalid", invalid)
	if len(nodes) == 0 {
		return nil, errors.New("oixCloud YAML contains no valid AnyTLS or Snell proxies")
	}
	return nodes, nil
}

func (proxy oixCloudProxy) anyTLSLink() (string, error) {
	if err := proxy.validateBase("password"); err != nil {
		return "", err
	}
	if len(proxy.UnsupportedOptions) != 0 {
		return "", fmt.Errorf("unsupported AnyTLS fields: %s", joinedMapKeys(proxy.UnsupportedOptions))
	}
	if len(proxy.ALPN) != 0 {
		return "", errors.New("per-node AnyTLS ALPN is not supported by the pinned outbound")
	}
	if proxy.ClientFingerprint != "" {
		return "", errors.New("per-node AnyTLS client fingerprint is not supported by the pinned outbound")
	}
	sni, err := coalesceField("sni", proxy.SNI, proxy.ServerName)
	if err != nil {
		return "", err
	}
	u := &url.URL{
		Scheme:   "anytls",
		User:     url.User(proxy.Password),
		Host:     net.JoinHostPort(proxy.Server, strconv.Itoa(proxy.Port)),
		Fragment: proxy.Name,
	}
	query := u.Query()
	if sni != "" {
		query.Set("sni", sni)
	}
	if proxy.SkipCertVerify != nil && *proxy.SkipCertVerify {
		query.Set("insecure", "1")
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func (proxy oixCloudProxy) snellLink() (string, error) {
	if err := proxy.validateBase("psk"); err != nil {
		return "", err
	}
	if len(proxy.UnsupportedOptions) != 0 {
		return "", fmt.Errorf("unsupported Snell fields: %s", joinedMapKeys(proxy.UnsupportedOptions))
	}
	if len(proxy.ALPN) != 0 || proxy.ClientFingerprint != "" || proxy.SNI != "" || proxy.ServerName != "" || proxy.SkipCertVerify != nil {
		return "", errors.New("Snell TLS options must be nested under obfs-opts")
	}
	userKey, err := coalesceField("user key", proxy.UserKey, proxy.UserKeyDashed)
	if err != nil {
		return "", err
	}
	version := proxy.Version
	if version == 0 {
		version = 4
	}
	u := &url.URL{
		Scheme:   "snell",
		User:     url.User(proxy.PSK),
		Host:     net.JoinHostPort(proxy.Server, strconv.Itoa(proxy.Port)),
		Fragment: proxy.Name,
	}
	query := u.Query()
	query.Set("version", strconv.Itoa(version))
	if userKey != "" {
		query.Set("userkey", userKey)
	}
	if proxy.Reuse != nil {
		query.Set("reuse", strconv.FormatBool(*proxy.Reuse))
	}
	if proxy.Identity != nil {
		query.Set("identity", strconv.FormatBool(*proxy.Identity))
	}
	if proxy.Mode != "" {
		query.Set("mode", proxy.Mode)
	}
	if proxy.ObfsOpts != nil {
		if err := addSnellObfsQuery(query, proxy.ObfsOpts); err != nil {
			return "", err
		}
	}
	u.RawQuery = query.Encode()
	configuration, err := outboundSnell.ParseURL(u.String())
	if err != nil {
		return "", err
	}
	return configuration.ExportToURL(), nil
}

func addSnellObfsQuery(query url.Values, obfs *oixCloudSnellObfs) error {
	if len(obfs.UnsupportedOptions) != 0 {
		return fmt.Errorf("unsupported Snell obfs fields: %s", joinedMapKeys(obfs.UnsupportedOptions))
	}
	if obfs.Mode == "" {
		return errors.New("Snell obfs-opts.mode is required")
	}
	query.Set("obfs", obfs.Mode)
	if obfs.Host != "" {
		query.Set("obfs-host", obfs.Host)
	}
	if obfs.SNI != "" {
		query.Set("sni", obfs.SNI)
	}
	if obfs.WSHost != "" {
		query.Set("ws-host", obfs.WSHost)
	}
	if obfs.Path != "" {
		query.Set("path", obfs.Path)
	}
	if obfs.ECHConfig != "" {
		query.Set("ech-config", obfs.ECHConfig)
	}
	if obfs.SkipCertVerify != nil {
		query.Set("skip-cert-verify", strconv.FormatBool(*obfs.SkipCertVerify))
	}
	if obfs.TLSImplementation != "" {
		query.Set("tls-implementation", obfs.TLSImplementation)
	}
	if obfs.ClientFingerprint != "" {
		query.Set("client-fingerprint", obfs.ClientFingerprint)
	}
	return nil
}

func (proxy oixCloudProxy) validateBase(credential string) error {
	if strings.TrimSpace(proxy.Name) == "" || strings.TrimSpace(proxy.Server) == "" {
		return errors.New("name and server are required")
	}
	if proxy.Port < 1 || proxy.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	switch credential {
	case "password":
		if proxy.Password == "" {
			return errors.New("password is required")
		}
	case "psk":
		if proxy.PSK == "" {
			return errors.New("PSK is required")
		}
	}
	return nil
}

func coalesceField(name, first, second string) (string, error) {
	if first != "" && second != "" && first != second {
		return "", fmt.Errorf("conflicting %s fields", name)
	}
	if first != "" {
		return first, nil
	}
	return second, nil
}

func joinedMapKeys(values map[string]any) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func logOIXCloudSkipped(log *logrus.Logger, reason string, counts map[string]int) {
	if log == nil || len(counts) == 0 {
		return
	}
	types := make([]string, 0, len(counts))
	for proxyType, count := range counts {
		types = append(types, fmt.Sprintf("%s=%d", proxyType, count))
	}
	sort.Strings(types)
	log.Warnf("Skipped %s oixCloud proxies: %s", reason, strings.Join(types, ", "))
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

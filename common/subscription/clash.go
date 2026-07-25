/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	outboundSnell "github.com/daeuniverse/outbound/dialer/snell"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type clashConfig struct {
	Proxies []yaml.Node `yaml:"proxies"`
}

type clashProxy struct {
	Name               string          `yaml:"name"`
	Type               string          `yaml:"type"`
	Server             string          `yaml:"server"`
	Port               int             `yaml:"port"`
	Password           string          `yaml:"password"`
	PSK                string          `yaml:"psk"`
	Version            int             `yaml:"version"`
	UserKey            string          `yaml:"userkey"`
	UserKeyDashed      string          `yaml:"user-key"`
	Mode               string          `yaml:"mode"`
	Reuse              *bool           `yaml:"reuse"`
	Identity           *bool           `yaml:"identity"`
	SNI                string          `yaml:"sni"`
	ServerName         string          `yaml:"server-name"`
	SkipCertVerify     *bool           `yaml:"skip-cert-verify"`
	ALPN               stringList      `yaml:"alpn"`
	ClientFingerprint  string          `yaml:"client-fingerprint"`
	UDP                *bool           `yaml:"udp"`
	TFO                *bool           `yaml:"tfo"`
	ObfsOpts           *clashSnellObfs `yaml:"obfs-opts"`
	UnsupportedOptions map[string]any  `yaml:",inline"`
}

type clashSnellObfs struct {
	// The "ech-tls" mode value is an oixCloud-specific Clash extension.
	Mode string `yaml:"mode"`
	Host string `yaml:"host"`

	// The following ECH-TLS transport options are oixCloud-specific Clash
	// extensions, not fields from standard Clash Snell.
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

// ResolveSubscriptionAsClash converts supported proxies from a plain Clash
// YAML configuration to canonical outbound links. Unsupported types and
// malformed supported entries are skipped so one bad node does not make the
// complete subscription unusable.
func ResolveSubscriptionAsClash(log *logrus.Logger, data []byte) ([]string, error) {
	var config clashConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse Clash YAML: %w", err)
	}
	if config.Proxies == nil {
		return nil, errors.New("Clash YAML does not contain proxies")
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
		var proxy clashProxy
		if err := proxyNode.Decode(&proxy); err != nil {
			invalid[proxyType]++
			if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
				log.WithError(err).Debugf("Skipping invalid Clash %s proxy", proxyType)
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
				log.WithError(err).Debugf("Skipping invalid Clash %s proxy", proxyType)
			}
			continue
		}
		nodes = append(nodes, link)
	}
	logClashSkipped(log, "unsupported", unsupported)
	logClashSkipped(log, "invalid", invalid)
	if len(nodes) == 0 {
		return nil, errors.New("Clash YAML contains no valid AnyTLS or Snell proxies")
	}
	return nodes, nil
}

// ResolveSubscriptionAsOIXCloud is kept for source compatibility.
// Deprecated: use ResolveSubscriptionAsClash.
func ResolveSubscriptionAsOIXCloud(log *logrus.Logger, data []byte) ([]string, error) {
	return ResolveSubscriptionAsClash(log, data)
}

func (proxy clashProxy) anyTLSLink() (string, error) {
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

func (proxy clashProxy) snellLink() (string, error) {
	if err := proxy.validateBase("psk"); err != nil {
		return "", err
	}
	if len(proxy.UnsupportedOptions) != 0 {
		return "", fmt.Errorf("unsupported Snell fields: %s", joinedMapKeys(proxy.UnsupportedOptions))
	}
	if len(proxy.ALPN) != 0 || proxy.ClientFingerprint != "" || proxy.SNI != "" || proxy.ServerName != "" || proxy.SkipCertVerify != nil {
		return "", errors.New("snell TLS options must be nested under obfs-opts")
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

func addSnellObfsQuery(query url.Values, obfs *clashSnellObfs) error {
	if len(obfs.UnsupportedOptions) != 0 {
		return fmt.Errorf("unsupported Snell obfs fields: %s", joinedMapKeys(obfs.UnsupportedOptions))
	}
	if obfs.Mode == "" {
		return errors.New("snell obfs-opts.mode is required")
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
	tlsImplementation := obfs.TLSImplementation
	clientFingerprint := normalizeClashClientFingerprint(obfs.ClientFingerprint)
	if strings.EqualFold(obfs.Mode, "ech-tls") {
		if tlsImplementation == "" {
			tlsImplementation = "utls"
		}
		if tlsImplementation == "utls" && clientFingerprint == "" {
			clientFingerprint = "chrome_auto"
		}
	}
	if tlsImplementation != "" {
		query.Set("tls-implementation", tlsImplementation)
	}
	if clientFingerprint != "" {
		query.Set("client-fingerprint", clientFingerprint)
	}
	return nil
}

// normalizeClashClientFingerprint translates Clash fingerprint names to the
// canonical uTLS ClientHello IDs understood by outbound. Unknown values are
// preserved so newer outbound fingerprints can pass through unchanged.
func normalizeClashClientFingerprint(fingerprint string) string {
	switch strings.ToLower(strings.TrimSpace(fingerprint)) {
	case "chrome":
		return "chrome_auto"
	case "firefox":
		return "firefox_auto"
	case "safari":
		return "safari_auto"
	case "ios":
		return "ios_auto"
	case "android":
		return "android_11_okhttp"
	case "edge":
		return "edge_auto"
	case "360":
		return "360_auto"
	case "qq":
		return "qq_auto"
	case "random":
		return "random"
	default:
		return fingerprint
	}
}

func (proxy clashProxy) validateBase(credential string) error {
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

func logClashSkipped(log *logrus.Logger, reason string, counts map[string]int) {
	if log == nil || len(counts) == 0 {
		return
	}
	types := make([]string, 0, len(counts))
	for proxyType, count := range counts {
		types = append(types, fmt.Sprintf("%s=%d", proxyType, count))
	}
	sort.Strings(types)
	log.Warnf("Skipped %s Clash proxies: %s", reason, strings.Join(types, ", "))
}

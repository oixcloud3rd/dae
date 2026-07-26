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
	"reflect"
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

type clashProxyHeader struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
}

type clashProxyBase struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Server string `yaml:"server"`
	Port   int    `yaml:"port"`
	UDP    *bool  `yaml:"udp"`
	TFO    *bool  `yaml:"tfo"`
}

type clashAnyTLSProxy struct {
	clashProxyBase     `yaml:",inline"`
	Password           string          `yaml:"password"`
	SNI                string          `yaml:"sni"`
	ServerName         string          `yaml:"server-name"`
	SkipCertVerify     *bool           `yaml:"skip-cert-verify"`
	ALPN               clashStringList `yaml:"alpn"`
	ClientFingerprint  string          `yaml:"client-fingerprint"`
	UnsupportedOptions map[string]any  `yaml:",inline"`
}

type clashSnellProxy struct {
	clashProxyBase     `yaml:",inline"`
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
	ALPN               clashStringList `yaml:"alpn"`
	ClientFingerprint  string          `yaml:"client-fingerprint"`
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
	ECHConfig          string         `yaml:"ech-config"`
	SkipCertVerify     *bool          `yaml:"skip-cert-verify"`
	TLSImplementation  string         `yaml:"tls-implementation"`
	ClientFingerprint  string         `yaml:"client-fingerprint"`
	UnsupportedOptions map[string]any `yaml:",inline"`

	// Deprecated: raw ECH-TLS ignores WebSocket transport options.
	WSHost string `yaml:"ws-host"`
	// Deprecated: raw ECH-TLS ignores WebSocket transport options.
	Path string `yaml:"path"`
}

// clashStringList accepts either a YAML scalar or sequence.
type clashStringList []string

func (list *clashStringList) UnmarshalYAML(node *yaml.Node) error {
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
		return errors.New("expected a string or string list")
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
		return nil, errors.New("clash YAML does not contain proxies")
	}

	nodes := make([]string, 0, len(config.Proxies))
	unsupported := make(map[string]int)
	invalid := make(map[string]int)
	for _, proxyNode := range config.Proxies {
		var header clashProxyHeader
		if err := proxyNode.Decode(&header); err != nil {
			invalid["<missing>"]++
			continue
		}
		proxyType := strings.ToLower(strings.TrimSpace(header.Type))
		if !isSupportedClashProxyType(proxyType) {
			if proxyType == "" {
				proxyType = "<missing>"
			}
			unsupported[proxyType]++
			continue
		}
		link, err := convertClashProxy(proxyType, proxyNode)
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
		return nil, errors.New("clash YAML contains no valid supported proxies")
	}
	return nodes, nil
}

// ResolveSubscriptionAsOIXCloud is kept for source compatibility.

// Deprecated: use ResolveSubscriptionAsClash.
func ResolveSubscriptionAsOIXCloud(log *logrus.Logger, data []byte) ([]string, error) {
	return ResolveSubscriptionAsClash(log, data)
}

func isSupportedClashProxyType(proxyType string) bool {
	switch proxyType {
	case "ss", "socks5", "http", "vmess", "vless", "trojan", "hysteria2", "hy2", "tuic", "anytls", "snell":
		return true
	default:
		return false
	}
}

func convertClashProxy(proxyType string, node yaml.Node) (string, error) {
	switch proxyType {
	case "ss":
		return decodeClashShadowsocks(node)
	case "socks5":
		return decodeClashSocks5(node)
	case "http":
		return decodeClashHTTP(node)
	case "vmess":
		return decodeClashVMess(node)
	case "vless":
		return decodeClashVLESS(node)
	case "trojan":
		return decodeClashTrojan(node)
	case "hysteria2", "hy2":
		return decodeClashHysteria2(node)
	case "tuic":
		return decodeClashTUIC(node)
	case "anytls":
		var proxy clashAnyTLSProxy
		if err := node.Decode(&proxy); err != nil {
			return "", err
		}
		return proxy.anyTLSLink()
	case "snell":
		var proxy clashSnellProxy
		if err := node.Decode(&proxy); err != nil {
			return "", err
		}
		return proxy.snellLink()
	default:
		return "", fmt.Errorf("unsupported Clash proxy type %q", proxyType)
	}
}

func (proxy clashAnyTLSProxy) anyTLSLink() (string, error) {
	if err := proxy.validateBase(); err != nil {
		return "", err
	}
	if proxy.Password == "" {
		return "", errors.New("password is required")
	}
	if err := validateUnsupportedClashOptions(proxy.UnsupportedOptions); err != nil {
		return "", fmt.Errorf("unsupported AnyTLS fields: %w", err)
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

func (proxy clashSnellProxy) snellLink() (string, error) {
	if err := proxy.validateBase(); err != nil {
		return "", err
	}
	if proxy.PSK == "" {
		return "", errors.New("psk is required")
	}
	if err := validateUnsupportedClashOptions(proxy.UnsupportedOptions); err != nil {
		return "", fmt.Errorf("unsupported Snell fields: %w", err)
	}
	isECHTLS := proxy.ObfsOpts != nil && strings.EqualFold(proxy.ObfsOpts.Mode, "ech-tls")
	if len(proxy.ALPN) != 0 && (!isECHTLS || len(proxy.ALPN) != 1 || proxy.ALPN[0] != "h2") {
		return "", errors.New("Snell ECH-TLS ALPN is fixed to h2")
	}
	if proxy.ClientFingerprint != "" || proxy.SNI != "" || proxy.ServerName != "" || proxy.SkipCertVerify != nil {
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
	if err := validateUnsupportedClashOptions(obfs.UnsupportedOptions); err != nil {
		return fmt.Errorf("unsupported Snell obfs fields: %w", err)
	}
	if obfs.Mode == "" {
		return errors.New("snell obfs-opts.mode is required")
	}
	isECHTLS := strings.EqualFold(obfs.Mode, "ech-tls")
	if !isECHTLS && (obfs.WSHost != "" || obfs.Path != "") {
		return errors.New("Snell WebSocket options are only accepted as ignored legacy ECH-TLS fields")
	}
	query.Set("obfs", obfs.Mode)
	if obfs.Host != "" {
		query.Set("obfs-host", obfs.Host)
	}
	if obfs.SNI != "" {
		query.Set("sni", obfs.SNI)
	}
	if obfs.ECHConfig != "" {
		query.Set("ech-config", obfs.ECHConfig)
	}
	if obfs.SkipCertVerify != nil {
		query.Set("skip-cert-verify", strconv.FormatBool(*obfs.SkipCertVerify))
	}
	tlsImplementation := obfs.TLSImplementation
	clientFingerprint := normalizeClashClientFingerprint(obfs.ClientFingerprint)
	if isECHTLS {
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

func (proxy clashProxyBase) validateBase() error {
	if strings.TrimSpace(proxy.Name) == "" || strings.TrimSpace(proxy.Server) == "" {
		return errors.New("name and server are required")
	}
	if proxy.Port < 1 || proxy.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func validateUnsupportedClashOptions(options map[string]any) error {
	keys := make([]string, 0, len(options))
	for key, value := range options {
		if !isEmptyClashOption(value) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	return fmt.Errorf("non-empty options: %s", strings.Join(keys, ", "))
}

func isEmptyClashOption(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	for reflected.Kind() == reflect.Interface || reflected.Kind() == reflect.Pointer {
		if reflected.IsNil() {
			return true
		}
		reflected = reflected.Elem()
	}
	switch reflected.Kind() {
	case reflect.Bool:
		return !reflected.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflected.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return reflected.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return reflected.Float() == 0
	case reflect.String, reflect.Slice:
		return reflected.Len() == 0
	case reflect.Array:
		for i := 0; i < reflected.Len(); i++ {
			if !isEmptyClashOption(reflected.Index(i).Interface()) {
				return false
			}
		}
		return true
	case reflect.Map:
		if reflected.Len() == 0 {
			return true
		}
		iterator := reflected.MapRange()
		for iterator.Next() {
			if !isEmptyClashOption(iterator.Value().Interface()) {
				return false
			}
		}
		return true
	case reflect.Struct:
		for i := 0; i < reflected.NumField(); i++ {
			if !reflected.Field(i).CanInterface() || !isEmptyClashOption(reflected.Field(i).Interface()) {
				return false
			}
		}
		return true
	default:
		return false
	}
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

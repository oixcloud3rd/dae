/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/common/bandwidth"
	outboundHTTP "github.com/daeuniverse/outbound/dialer/http"
	outboundHysteria2 "github.com/daeuniverse/outbound/dialer/hysteria2"
	outboundShadowsocks "github.com/daeuniverse/outbound/dialer/shadowsocks"
	outboundSocks "github.com/daeuniverse/outbound/dialer/socks"
	outboundTUIC "github.com/daeuniverse/outbound/dialer/tuic"
	"gopkg.in/yaml.v3"
)

type clashShadowsocksProxy struct {
	clashProxyBase     `yaml:",inline"`
	Cipher             string               `yaml:"cipher"`
	Password           string               `yaml:"password"`
	Plugin             string               `yaml:"plugin"`
	PluginOpts         clashSSPluginOptions `yaml:"plugin-opts"`
	UDPOverTCP         bool                 `yaml:"udp-over-tcp"`
	UnsupportedOptions map[string]any       `yaml:",inline"`
}

type clashSSPluginOptions struct {
	Mode               string         `yaml:"mode"`
	Host               string         `yaml:"host"`
	Path               string         `yaml:"path"`
	TLS                bool           `yaml:"tls"`
	UnsupportedOptions map[string]any `yaml:",inline"`
}

func decodeClashShadowsocks(node yaml.Node) (string, error) {
	var proxy clashShadowsocksProxy
	if err := node.Decode(&proxy); err != nil {
		return "", err
	}
	if err := proxy.validateBase(); err != nil {
		return "", err
	}
	if err := validateUnsupportedClashOptions(proxy.UnsupportedOptions); err != nil {
		return "", err
	}
	if proxy.Password == "" {
		return "", errors.New("password is required")
	}
	cipher := strings.ToLower(strings.TrimSpace(proxy.Cipher))
	if cipher == "dummy" {
		cipher = "none"
	}
	if !isSupportedShadowsocksCipher(cipher) {
		return "", fmt.Errorf("unsupported Shadowsocks cipher %q", proxy.Cipher)
	}
	if proxy.UDPOverTCP {
		return "", errors.New("shadowsocks udp-over-tcp is not supported")
	}

	plugin, err := clashShadowsocksPlugin(proxy.Plugin, proxy.PluginOpts)
	if err != nil {
		return "", err
	}
	configuration := &outboundShadowsocks.Shadowsocks{
		Name:     proxy.Name,
		Server:   proxy.Server,
		Port:     proxy.Port,
		Password: proxy.Password,
		Cipher:   cipher,
		Plugin:   plugin,
		UDP:      plugin.Name == "",
		Protocol: "shadowsocks",
	}
	return configuration.ExportToURL(), nil
}

func clashShadowsocksPlugin(name string, options clashSSPluginOptions) (outboundShadowsocks.Sip003, error) {
	if err := validateUnsupportedClashOptions(options.UnsupportedOptions); err != nil {
		return outboundShadowsocks.Sip003{}, fmt.Errorf("unsupported Shadowsocks plugin options: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "":
		if options.Mode != "" || options.Host != "" || options.Path != "" || options.TLS {
			return outboundShadowsocks.Sip003{}, errors.New("shadowsocks plugin options require a plugin")
		}
		return outboundShadowsocks.Sip003{}, nil
	case "obfs", "obfs-local", "simple-obfs", "simpleobfs":
		mode := strings.ToLower(options.Mode)
		if mode != "http" && mode != "tls" {
			return outboundShadowsocks.Sip003{}, fmt.Errorf("unsupported simple-obfs mode %q", options.Mode)
		}
		if options.Path != "" || options.TLS {
			return outboundShadowsocks.Sip003{}, errors.New("simple-obfs path and tls options are not supported")
		}
		return outboundShadowsocks.Sip003{
			Name: "simple-obfs",
			Opts: outboundShadowsocks.Sip003Opts{Obfs: mode, Host: options.Host},
		}, nil
	case "v2ray-plugin":
		mode := strings.ToLower(options.Mode)
		if mode != "" && mode != "websocket" {
			return outboundShadowsocks.Sip003{}, fmt.Errorf("unsupported v2ray-plugin mode %q", options.Mode)
		}
		if options.Path != "" && options.Path != "/" {
			return outboundShadowsocks.Sip003{}, errors.New("v2ray-plugin custom paths are not supported")
		}
		tlsMode := ""
		if options.TLS {
			tlsMode = "tls"
		}
		return outboundShadowsocks.Sip003{
			Name: "v2ray-plugin",
			Opts: outboundShadowsocks.Sip003Opts{Tls: tlsMode, Host: options.Host},
		}, nil
	default:
		return outboundShadowsocks.Sip003{}, fmt.Errorf("unsupported Shadowsocks plugin %q", name)
	}
}

func isSupportedShadowsocksCipher(cipher string) bool {
	switch cipher {
	case "aes-256-gcm", "aes-128-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
		"2022-blake3-aes-256-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-chacha20-poly1305",
		"aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
		"aes-128-ofb", "aes-192-ofb", "aes-256-ofb", "des-cfb", "bf-cfb", "cast5-cfb", "rc4-md5",
		"rc4-md5-6", "chacha20", "chacha20-ietf", "salsa20", "camellia-128-cfb", "camellia-192-cfb",
		"camellia-256-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "rc4", "none", "plain":
		return true
	default:
		return false
	}
}

type clashSocks5Proxy struct {
	clashProxyBase     `yaml:",inline"`
	Username           string         `yaml:"username"`
	Password           string         `yaml:"password"`
	TLS                bool           `yaml:"tls"`
	UnsupportedOptions map[string]any `yaml:",inline"`
}

func decodeClashSocks5(node yaml.Node) (string, error) {
	var proxy clashSocks5Proxy
	if err := node.Decode(&proxy); err != nil {
		return "", err
	}
	if err := proxy.validateBase(); err != nil {
		return "", err
	}
	if err := validateUnsupportedClashOptions(proxy.UnsupportedOptions); err != nil {
		return "", err
	}
	if proxy.TLS {
		return "", errors.New("socks5 TLS is not supported")
	}
	configuration := &outboundSocks.Socks{
		Name: proxy.Name, Server: proxy.Server, Port: proxy.Port,
		Username: proxy.Username, Password: proxy.Password, Protocol: "socks5",
	}
	return configuration.ExportToURL(), nil
}

type clashHTTPProxy struct {
	clashProxyBase     `yaml:",inline"`
	Username           string            `yaml:"username"`
	Password           string            `yaml:"password"`
	TLS                bool              `yaml:"tls"`
	SNI                string            `yaml:"sni"`
	SkipCertVerify     bool              `yaml:"skip-cert-verify"`
	Headers            map[string]string `yaml:"headers"`
	Fingerprint        string            `yaml:"fingerprint"`
	Certificate        string            `yaml:"certificate"`
	PrivateKey         string            `yaml:"private-key"`
	UnsupportedOptions map[string]any    `yaml:",inline"`
}

func decodeClashHTTP(node yaml.Node) (string, error) {
	var proxy clashHTTPProxy
	if err := node.Decode(&proxy); err != nil {
		return "", err
	}
	if err := proxy.validateBase(); err != nil {
		return "", err
	}
	if err := validateUnsupportedClashOptions(proxy.UnsupportedOptions); err != nil {
		return "", err
	}
	if len(proxy.Headers) != 0 || proxy.Fingerprint != "" || proxy.Certificate != "" || proxy.PrivateKey != "" {
		return "", errors.New("http headers, certificate pinning, and client certificates are not supported")
	}
	protocol := "http"
	sni := proxy.SNI
	if proxy.TLS {
		protocol = "https"
		if sni == "" {
			sni = proxy.Server
		}
	} else if proxy.SNI != "" || proxy.SkipCertVerify {
		return "", errors.New("http TLS options require tls")
	}
	configuration := &outboundHTTP.HTTP{
		Name: proxy.Name, Server: proxy.Server, Port: proxy.Port,
		Username: proxy.Username, Password: proxy.Password,
		SNI: sni, Protocol: protocol, AllowInsecure: proxy.SkipCertVerify,
	}
	return configuration.ExportToURL(), nil
}

type clashHysteria2Proxy struct {
	clashProxyBase     `yaml:",inline"`
	Password           string          `yaml:"password"`
	SNI                string          `yaml:"sni"`
	SkipCertVerify     bool            `yaml:"skip-cert-verify"`
	Up                 string          `yaml:"up"`
	Down               string          `yaml:"down"`
	Ports              clashStringList `yaml:"ports"`
	HopInterval        string          `yaml:"hop-interval"`
	Obfs               string          `yaml:"obfs"`
	ObfsPassword       string          `yaml:"obfs-password"`
	ALPN               clashStringList `yaml:"alpn"`
	Fingerprint        string          `yaml:"fingerprint"`
	Certificate        string          `yaml:"certificate"`
	PrivateKey         string          `yaml:"private-key"`
	BBRProfile         string          `yaml:"bbr-profile"`
	ECHOpts            map[string]any  `yaml:"ech-opts"`
	RealmOpts          map[string]any  `yaml:"realm-opts"`
	UnsupportedOptions map[string]any  `yaml:",inline"`
}

func decodeClashHysteria2(node yaml.Node) (string, error) {
	var proxy clashHysteria2Proxy
	if err := node.Decode(&proxy); err != nil {
		return "", err
	}
	if err := proxy.validateBase(); err != nil {
		return "", err
	}
	if err := validateUnsupportedClashOptions(proxy.UnsupportedOptions); err != nil {
		return "", err
	}
	if proxy.Password == "" {
		return "", errors.New("password is required")
	}
	if proxy.HopInterval != "" || proxy.Obfs != "" || proxy.ObfsPassword != "" || len(proxy.ALPN) != 0 ||
		proxy.Certificate != "" || proxy.PrivateKey != "" || proxy.BBRProfile != "" ||
		!isEmptyClashOption(proxy.ECHOpts) || !isEmptyClashOption(proxy.RealmOpts) {
		return "", errors.New("unsupported Hysteria2 transport or TLS options")
	}
	var maxTx, maxRx uint64
	if (proxy.Up == "") != (proxy.Down == "") {
		return "", errors.New("hysteria2 up and down must be specified together")
	}
	if proxy.Up != "" {
		var err error
		maxTx, err = bandwidth.Parse(proxy.Up)
		if err != nil {
			return "", fmt.Errorf("parse Hysteria2 up bandwidth: %w", err)
		}
		maxRx, err = bandwidth.Parse(proxy.Down)
		if err != nil {
			return "", fmt.Errorf("parse Hysteria2 down bandwidth: %w", err)
		}
	}
	port := strconv.Itoa(proxy.Port)
	if len(proxy.Ports) != 0 {
		port = strings.ReplaceAll(strings.Join(proxy.Ports, ","), " ", "")
		if !validPortUnion(port) {
			return "", errors.New("invalid Hysteria2 ports")
		}
	}
	if proxy.Fingerprint != "" {
		normalized := strings.NewReplacer(":", "", "-", "").Replace(proxy.Fingerprint)
		if len(normalized) != 64 {
			return "", errors.New("invalid Hysteria2 certificate fingerprint")
		}
		if _, err := hex.DecodeString(normalized); err != nil {
			return "", errors.New("invalid Hysteria2 certificate fingerprint")
		}
	}
	configuration := &outboundHysteria2.Hysteria2{
		Name: proxy.Name, User: proxy.Password,
		Server: net.JoinHostPort(proxy.Server, port), Insecure: proxy.SkipCertVerify,
		Sni: proxy.SNI, PinSHA256: proxy.Fingerprint, MaxTx: maxTx, MaxRx: maxRx,
	}
	return configuration.ExportToURL(), nil
}

func validPortUnion(value string) bool {
	for _, item := range strings.Split(value, ",") {
		bounds := strings.Split(item, "-")
		if len(bounds) < 1 || len(bounds) > 2 {
			return false
		}
		for _, bound := range bounds {
			port, err := strconv.Atoi(strings.TrimSpace(bound))
			if err != nil || port < 1 || port > 65535 {
				return false
			}
		}
	}
	return true
}

type clashTUICProxy struct {
	clashProxyBase       `yaml:",inline"`
	UUID                 string          `yaml:"uuid"`
	Password             string          `yaml:"password"`
	Token                string          `yaml:"token"`
	SNI                  string          `yaml:"sni"`
	SkipCertVerify       bool            `yaml:"skip-cert-verify"`
	DisableSNI           bool            `yaml:"disable-sni"`
	CongestionController string          `yaml:"congestion-controller"`
	ALPN                 clashStringList `yaml:"alpn"`
	UDPRelayMode         string          `yaml:"udp-relay-mode"`
	ReduceRTT            bool            `yaml:"reduce-rtt"`
	HeartbeatInterval    int             `yaml:"heartbeat-interval"`
	UDPOverStream        bool            `yaml:"udp-over-stream"`
	Fingerprint          string          `yaml:"fingerprint"`
	Certificate          string          `yaml:"certificate"`
	PrivateKey           string          `yaml:"private-key"`
	ECHOpts              map[string]any  `yaml:"ech-opts"`
	UnsupportedOptions   map[string]any  `yaml:",inline"`
}

func decodeClashTUIC(node yaml.Node) (string, error) {
	var proxy clashTUICProxy
	if err := node.Decode(&proxy); err != nil {
		return "", err
	}
	if err := proxy.validateBase(); err != nil {
		return "", err
	}
	if err := validateUnsupportedClashOptions(proxy.UnsupportedOptions); err != nil {
		return "", err
	}
	if proxy.UUID == "" || proxy.Password == "" {
		return "", errors.New("tuic uuid and password are required")
	}
	if proxy.Token != "" || proxy.ReduceRTT || proxy.HeartbeatInterval != 0 || proxy.UDPOverStream ||
		proxy.Fingerprint != "" || proxy.Certificate != "" || proxy.PrivateKey != "" || !isEmptyClashOption(proxy.ECHOpts) {
		return "", errors.New("unsupported TUIC authentication, transport, or TLS options")
	}
	udpRelayMode := strings.ToLower(proxy.UDPRelayMode)
	if udpRelayMode != "" && udpRelayMode != "native" && udpRelayMode != "quic" {
		return "", fmt.Errorf("unsupported TUIC udp-relay-mode %q", proxy.UDPRelayMode)
	}
	congestionController := strings.ToLower(proxy.CongestionController)
	if congestionController != "" && congestionController != "bbr" {
		return "", fmt.Errorf("unsupported TUIC congestion-controller %q", proxy.CongestionController)
	}
	configuration := &outboundTUIC.Tuic{
		Name: proxy.Name, Server: proxy.Server, Port: proxy.Port,
		User: proxy.UUID, Password: proxy.Password, Sni: proxy.SNI,
		AllowInsecure: proxy.SkipCertVerify, DisableSni: proxy.DisableSNI,
		CongestionControl: congestionController, Alpn: append([]string(nil), proxy.ALPN...),
		UdpRelayMode: udpRelayMode, Protocol: "tuic",
	}
	return configuration.ExportToURL(), nil
}

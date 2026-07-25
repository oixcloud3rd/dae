/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	outboundTrojan "github.com/daeuniverse/outbound/dialer/trojan"
	outboundV2Ray "github.com/daeuniverse/outbound/dialer/v2ray"
	"gopkg.in/yaml.v3"
)

type clashWebSocketOptions struct {
	Path                string            `yaml:"path"`
	Headers             map[string]string `yaml:"headers"`
	MaxEarlyData        int               `yaml:"max-early-data"`
	EarlyDataHeaderName string            `yaml:"early-data-header-name"`
	V2RayHTTPUpgrade    bool              `yaml:"v2ray-http-upgrade"`
	UnsupportedOptions  map[string]any    `yaml:",inline"`
}

type clashGRPCOptions struct {
	ServiceName        string         `yaml:"grpc-service-name"`
	UnsupportedOptions map[string]any `yaml:",inline"`
}

type clashHTTPOptions struct {
	Method             string              `yaml:"method"`
	Path               clashStringList     `yaml:"path"`
	Headers            map[string][]string `yaml:"headers"`
	UnsupportedOptions map[string]any      `yaml:",inline"`
}

type clashHTTP2Options struct {
	Path               string          `yaml:"path"`
	Host               clashStringList `yaml:"host"`
	UnsupportedOptions map[string]any  `yaml:",inline"`
}

type clashRealityOptions struct {
	PublicKey          string         `yaml:"public-key"`
	ShortID            string         `yaml:"short-id"`
	UnsupportedOptions map[string]any `yaml:",inline"`
}

type clashV2RayProxy struct {
	clashProxyBase      `yaml:",inline"`
	UUID                string                `yaml:"uuid"`
	AlterID             int                   `yaml:"alterId"`
	Cipher              string                `yaml:"cipher"`
	Flow                string                `yaml:"flow"`
	Encryption          string                `yaml:"encryption"`
	Network             string                `yaml:"network"`
	TLS                 bool                  `yaml:"tls"`
	ServerName          string                `yaml:"servername"`
	SNI                 string                `yaml:"sni"`
	SkipCertVerify      bool                  `yaml:"skip-cert-verify"`
	ALPN                clashStringList       `yaml:"alpn"`
	ClientFingerprint   string                `yaml:"client-fingerprint"`
	Fingerprint         string                `yaml:"fingerprint"`
	Certificate         string                `yaml:"certificate"`
	PrivateKey          string                `yaml:"private-key"`
	ECHOpts             map[string]any        `yaml:"ech-opts"`
	RealityOpts         clashRealityOptions   `yaml:"reality-opts"`
	WSOpts              clashWebSocketOptions `yaml:"ws-opts"`
	GRPCOpts            clashGRPCOptions      `yaml:"grpc-opts"`
	HTTPOpts            clashHTTPOptions      `yaml:"http-opts"`
	HTTP2Opts           clashHTTP2Options     `yaml:"h2-opts"`
	PacketEncoding      string                `yaml:"packet-encoding"`
	PacketAddr          bool                  `yaml:"packet-addr"`
	XUDP                bool                  `yaml:"xudp"`
	GlobalPadding       bool                  `yaml:"global-padding"`
	AuthenticatedLength bool                  `yaml:"authenticated-length"`
	UnsupportedOptions  map[string]any        `yaml:",inline"`
}

func decodeClashVMess(node yaml.Node) (string, error) {
	var proxy clashV2RayProxy
	if err := node.Decode(&proxy); err != nil {
		return "", err
	}
	if err := validateClashV2RayBase(proxy); err != nil {
		return "", err
	}
	if proxy.AlterID != 0 {
		return "", errors.New("vmess alterId must be zero")
	}
	if cipher := strings.ToLower(proxy.Cipher); cipher != "" && cipher != "auto" {
		return "", fmt.Errorf("unsupported VMess cipher %q", proxy.Cipher)
	}
	if proxy.Flow != "" || proxy.Encryption != "" || !isEmptyClashOption(proxy.RealityOpts) {
		return "", errors.New("unsupported VMess flow, encryption, or Reality options")
	}
	if proxy.ClientFingerprint != "" {
		return "", errors.New("per-node VMess TLS client fingerprints are not supported")
	}
	transport, err := clashV2RayTransport(proxy.Network, proxy.WSOpts, proxy.GRPCOpts, proxy.HTTPOpts, proxy.HTTP2Opts)
	if err != nil {
		return "", err
	}
	if err = validateClashV2RayTLS(proxy, transport.network, false); err != nil {
		return "", err
	}
	security := "none"
	if proxy.TLS {
		security = "tls"
	}
	configuration := &outboundV2Ray.V2Ray{
		Ps: proxy.Name, Add: proxy.Server, Port: fmt.Sprint(proxy.Port), ID: proxy.UUID,
		Aid: "0", Net: transport.network, Type: "none", Host: transport.host,
		SNI: clashServerName(proxy), Path: transport.path, TLS: security,
		Alpn: strings.Join(proxy.ALPN, ","), AllowInsecure: proxy.SkipCertVerify,
		V: "2", Protocol: "vmess",
	}
	return configuration.ExportToURL(), nil
}

func decodeClashVLESS(node yaml.Node) (string, error) {
	var proxy clashV2RayProxy
	if err := node.Decode(&proxy); err != nil {
		return "", err
	}
	if err := validateClashV2RayBase(proxy); err != nil {
		return "", err
	}
	if proxy.AlterID != 0 || proxy.Cipher != "" {
		return "", errors.New("vless alterId and cipher are not supported")
	}
	if proxy.Encryption != "" && strings.ToLower(proxy.Encryption) != "none" {
		return "", errors.New("vless encryption is not supported")
	}
	transport, err := clashV2RayTransport(proxy.Network, proxy.WSOpts, proxy.GRPCOpts, proxy.HTTPOpts, proxy.HTTP2Opts)
	if err != nil {
		return "", err
	}
	reality := proxy.RealityOpts.PublicKey != ""
	if err = validateClashV2RayTLS(proxy, transport.network, reality); err != nil {
		return "", err
	}
	security := "none"
	fingerprint := ""
	switch {
	case reality:
		security = "reality"
		fingerprint = normalizeClashClientFingerprint(proxy.ClientFingerprint)
		if fingerprint == "" {
			fingerprint = "chrome_auto"
		}
	case proxy.TLS:
		security = "tls"
		if proxy.ClientFingerprint != "" {
			return "", errors.New("per-node VLESS TLS client fingerprints are not supported")
		}
	case proxy.ClientFingerprint != "":
		return "", errors.New("vless client fingerprint requires Reality")
	}
	configuration := &outboundV2Ray.V2Ray{
		Ps: proxy.Name, Add: proxy.Server, Port: fmt.Sprint(proxy.Port), ID: proxy.UUID,
		Net: transport.network, Type: "none", Host: transport.host,
		SNI: clashServerName(proxy), Path: transport.path, TLS: security,
		Flow: proxy.Flow, Alpn: strings.Join(proxy.ALPN, ","), Fingerprint: fingerprint,
		PublicKey: proxy.RealityOpts.PublicKey, ShortId: proxy.RealityOpts.ShortID,
		V: "2", Protocol: "vless",
	}
	link := configuration.ExportToURL()
	if reality {
		u, err := url.Parse(link)
		if err != nil {
			return "", err
		}
		query := u.Query()
		query.Set("pbk", proxy.RealityOpts.PublicKey)
		if proxy.RealityOpts.ShortID != "" {
			query.Set("sid", proxy.RealityOpts.ShortID)
		}
		u.RawQuery = query.Encode()
		link = u.String()
	}
	return link, nil
}

func validateClashV2RayBase(proxy clashV2RayProxy) error {
	if err := proxy.validateBase(); err != nil {
		return err
	}
	if proxy.UUID == "" {
		return errors.New("uuid is required")
	}
	if err := validateUnsupportedClashOptions(proxy.UnsupportedOptions); err != nil {
		return err
	}
	if proxy.Fingerprint != "" || proxy.Certificate != "" || proxy.PrivateKey != "" || !isEmptyClashOption(proxy.ECHOpts) {
		return errors.New("certificate pinning, client certificates, and ECH are not supported")
	}
	if proxy.PacketEncoding != "" || proxy.PacketAddr || proxy.XUDP || proxy.GlobalPadding || proxy.AuthenticatedLength {
		return errors.New("vmess/vless packet encoding and padding options are not supported")
	}
	if err := validateUnsupportedClashOptions(proxy.RealityOpts.UnsupportedOptions); err != nil {
		return fmt.Errorf("unsupported Reality options: %w", err)
	}
	return nil
}

func validateClashV2RayTLS(proxy clashV2RayProxy, network string, reality bool) error {
	if reality {
		if network != "tcp" {
			return errors.New("vless Reality requires TCP")
		}
		if proxy.SkipCertVerify || len(proxy.ALPN) != 0 {
			return errors.New("vless Reality skip-cert-verify and ALPN are not supported")
		}
		return nil
	}
	if network == "grpc" && !proxy.TLS {
		return errors.New("outbound gRPC transport requires TLS")
	}
	if !proxy.TLS && (clashServerName(proxy) != "" || proxy.SkipCertVerify || len(proxy.ALPN) != 0) {
		return errors.New("tls options require tls")
	}
	if network != "http" && network != "h2" && len(proxy.ALPN) != 0 {
		return fmt.Errorf("alpn is not supported for %s transport", network)
	}
	if proxy.Type == "vless" && proxy.SkipCertVerify {
		return errors.New("per-node VLESS skip-cert-verify is not supported")
	}
	return nil
}

func clashServerName(proxy clashV2RayProxy) string {
	if proxy.ServerName != "" {
		return proxy.ServerName
	}
	return proxy.SNI
}

type clashTransportResult struct {
	network string
	host    string
	path    string
}

func clashV2RayTransport(network string, ws clashWebSocketOptions, grpc clashGRPCOptions, httpOptions clashHTTPOptions, h2 clashHTTP2Options) (clashTransportResult, error) {
	network = strings.ToLower(strings.TrimSpace(network))
	if network == "" {
		network = "tcp"
	}
	if err := validateUnsupportedClashOptions(ws.UnsupportedOptions); err != nil {
		return clashTransportResult{}, fmt.Errorf("unsupported WebSocket options: %w", err)
	}
	if err := validateUnsupportedClashOptions(grpc.UnsupportedOptions); err != nil {
		return clashTransportResult{}, fmt.Errorf("unsupported gRPC options: %w", err)
	}
	if err := validateUnsupportedClashOptions(httpOptions.UnsupportedOptions); err != nil {
		return clashTransportResult{}, fmt.Errorf("unsupported HTTP options: %w", err)
	}
	if err := validateUnsupportedClashOptions(h2.UnsupportedOptions); err != nil {
		return clashTransportResult{}, fmt.Errorf("unsupported HTTP/2 options: %w", err)
	}
	switch network {
	case "tcp":
		if !isEmptyClashOption(ws) || !isEmptyClashOption(grpc) || !isEmptyClashOption(httpOptions) || !isEmptyClashOption(h2) {
			return clashTransportResult{}, errors.New("tcp node contains options for another transport")
		}
		return clashTransportResult{network: "tcp"}, nil
	case "ws", "httpupgrade":
		if !isEmptyClashOption(grpc) || !isEmptyClashOption(httpOptions) || !isEmptyClashOption(h2) {
			return clashTransportResult{}, errors.New("websocket node contains options for another transport")
		}
		if ws.MaxEarlyData != 0 || ws.EarlyDataHeaderName != "" {
			return clashTransportResult{}, errors.New("websocket early data is not supported")
		}
		host, err := clashHostHeader(ws.Headers)
		if err != nil {
			return clashTransportResult{}, err
		}
		resultNetwork := network
		if ws.V2RayHTTPUpgrade {
			resultNetwork = "httpupgrade"
		}
		return clashTransportResult{network: resultNetwork, host: host, path: ws.Path}, nil
	case "grpc":
		if !isEmptyClashOption(ws) || !isEmptyClashOption(httpOptions) || !isEmptyClashOption(h2) {
			return clashTransportResult{}, errors.New("gRPC node contains options for another transport")
		}
		return clashTransportResult{network: "grpc", path: grpc.ServiceName}, nil
	case "http":
		if !isEmptyClashOption(ws) || !isEmptyClashOption(grpc) || !isEmptyClashOption(h2) {
			return clashTransportResult{}, errors.New("http node contains options for another transport")
		}
		if httpOptions.Method != "" && !strings.EqualFold(httpOptions.Method, "GET") {
			return clashTransportResult{}, errors.New("custom HTTP transport methods are not supported")
		}
		host, err := clashHTTPHost(httpOptions.Headers)
		if err != nil {
			return clashTransportResult{}, err
		}
		return clashTransportResult{network: "http", host: host, path: firstString(httpOptions.Path)}, nil
	case "h2":
		if !isEmptyClashOption(ws) || !isEmptyClashOption(grpc) || !isEmptyClashOption(httpOptions) {
			return clashTransportResult{}, errors.New("http/2 node contains options for another transport")
		}
		return clashTransportResult{network: "h2", host: firstString(h2.Host), path: h2.Path}, nil
	default:
		return clashTransportResult{}, fmt.Errorf("unsupported V2Ray transport %q", network)
	}
}

func clashHostHeader(headers map[string]string) (string, error) {
	var host string
	for key, value := range headers {
		if strings.EqualFold(key, "Host") {
			host = value
			continue
		}
		if value != "" {
			return "", fmt.Errorf("unsupported WebSocket header %q", key)
		}
	}
	return host, nil
}

func clashHTTPHost(headers map[string][]string) (string, error) {
	var host string
	for key, values := range headers {
		if strings.EqualFold(key, "Host") {
			host = firstString(values)
			continue
		}
		if len(values) != 0 {
			return "", fmt.Errorf("unsupported HTTP transport header %q", key)
		}
	}
	return host, nil
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

type clashTrojanProxy struct {
	clashProxyBase     `yaml:",inline"`
	Password           string                `yaml:"password"`
	SNI                string                `yaml:"sni"`
	Network            string                `yaml:"network"`
	SkipCertVerify     bool                  `yaml:"skip-cert-verify"`
	ALPN               clashStringList       `yaml:"alpn"`
	ClientFingerprint  string                `yaml:"client-fingerprint"`
	Fingerprint        string                `yaml:"fingerprint"`
	Certificate        string                `yaml:"certificate"`
	PrivateKey         string                `yaml:"private-key"`
	ECHOpts            map[string]any        `yaml:"ech-opts"`
	RealityOpts        clashRealityOptions   `yaml:"reality-opts"`
	WSOpts             clashWebSocketOptions `yaml:"ws-opts"`
	GRPCOpts           clashGRPCOptions      `yaml:"grpc-opts"`
	SSOpts             map[string]any        `yaml:"ss-opts"`
	UnsupportedOptions map[string]any        `yaml:",inline"`
}

func decodeClashTrojan(node yaml.Node) (string, error) {
	var proxy clashTrojanProxy
	if err := node.Decode(&proxy); err != nil {
		return "", err
	}
	if err := proxy.validateBase(); err != nil {
		return "", err
	}
	if proxy.Password == "" {
		return "", errors.New("password is required")
	}
	if err := validateUnsupportedClashOptions(proxy.UnsupportedOptions); err != nil {
		return "", err
	}
	if len(proxy.ALPN) != 0 || proxy.ClientFingerprint != "" || proxy.Fingerprint != "" || proxy.Certificate != "" ||
		proxy.PrivateKey != "" || !isEmptyClashOption(proxy.ECHOpts) || !isEmptyClashOption(proxy.RealityOpts) || !isEmptyClashOption(proxy.SSOpts) {
		return "", errors.New("unsupported Trojan TLS or Shadowsocks options")
	}
	transport, err := clashTrojanTransport(proxy.Network, proxy.WSOpts, proxy.GRPCOpts)
	if err != nil {
		return "", err
	}
	sni := proxy.SNI
	if sni == "" {
		sni = proxy.Server
	}
	protocol := "trojan"
	if transport.network != "" {
		protocol = "trojan-go"
	}
	path := transport.path
	if transport.network == "grpc" {
		path = transport.serviceName
	}
	configuration := &outboundTrojan.Trojan{
		Name: proxy.Name, Server: proxy.Server, Port: proxy.Port, Password: proxy.Password,
		Sni: sni, Type: transport.network, Host: transport.host, Path: path,
		ServiceName: transport.serviceName, AllowInsecure: proxy.SkipCertVerify, Protocol: protocol,
	}
	return configuration.ExportToURL(), nil
}

type clashTrojanTransportResult struct {
	network     string
	host        string
	path        string
	serviceName string
}

func clashTrojanTransport(network string, ws clashWebSocketOptions, grpc clashGRPCOptions) (clashTrojanTransportResult, error) {
	network = strings.ToLower(strings.TrimSpace(network))
	if network == "tcp" {
		network = ""
	}
	if err := validateUnsupportedClashOptions(ws.UnsupportedOptions); err != nil {
		return clashTrojanTransportResult{}, fmt.Errorf("unsupported WebSocket options: %w", err)
	}
	if err := validateUnsupportedClashOptions(grpc.UnsupportedOptions); err != nil {
		return clashTrojanTransportResult{}, fmt.Errorf("unsupported gRPC options: %w", err)
	}
	switch network {
	case "":
		if !isEmptyClashOption(ws) || !isEmptyClashOption(grpc) {
			return clashTrojanTransportResult{}, errors.New("tcp Trojan node contains options for another transport")
		}
		return clashTrojanTransportResult{}, nil
	case "ws", "httpupgrade":
		if !isEmptyClashOption(grpc) {
			return clashTrojanTransportResult{}, errors.New("websocket Trojan node contains gRPC options")
		}
		if ws.MaxEarlyData != 0 || ws.EarlyDataHeaderName != "" {
			return clashTrojanTransportResult{}, errors.New("websocket early data is not supported")
		}
		host, err := clashHostHeader(ws.Headers)
		if err != nil {
			return clashTrojanTransportResult{}, err
		}
		if ws.V2RayHTTPUpgrade {
			network = "httpupgrade"
		}
		return clashTrojanTransportResult{network: network, host: host, path: ws.Path}, nil
	case "grpc":
		if !isEmptyClashOption(ws) {
			return clashTrojanTransportResult{}, errors.New("gRPC Trojan node contains WebSocket options")
		}
		return clashTrojanTransportResult{network: "grpc", serviceName: grpc.ServiceName}, nil
	default:
		return clashTrojanTransportResult{}, fmt.Errorf("unsupported Trojan transport %q", network)
	}
}

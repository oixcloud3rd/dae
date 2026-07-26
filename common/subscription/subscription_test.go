package subscription

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestResolveSubscriptionAcceptsPlainClashFile(t *testing.T) {
	configDir := t.TempDir()
	subscriptionDir := filepath.Join(configDir, "subscriptions")
	if err := os.MkdirAll(subscriptionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clashConfig := []byte(`
proxies:
  - name: plain-clash-snell
    type: snell
    server: snell.example
    port: 443
    psk: password
    version: 4
    obfs-opts:
      mode: ech-tls
      path: /ws
      ech-config: "AAQ+DAAA"
      client-fingerprint: android
`)
	if err := os.WriteFile(filepath.Join(subscriptionDir, "clash.yaml"), clashConfig, 0o600); err != nil {
		t.Fatal(err)
	}

	tag, nodes, err := ResolveSubscription(
		logrus.New(),
		&http.Client{},
		configDir,
		"file://subscriptions/clash.yaml",
	)
	if err != nil {
		t.Fatalf("ResolveSubscription: %v", err)
	}
	if tag != "" {
		t.Fatalf("unexpected tag %q", tag)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected one Clash node, got %d", len(nodes))
	}
	u, err := url.Parse(nodes[0])
	if err != nil {
		t.Fatalf("parse generated node: %v", err)
	}
	if got := u.Query().Get("tls-implementation"); got != "utls" {
		t.Fatalf("unexpected TLS implementation %q", got)
	}
	if got := u.Query().Get("client-fingerprint"); got != "android_11_okhttp" {
		t.Fatalf("unexpected client fingerprint %q", got)
	}
	if got := u.Query().Get("path"); got != "" {
		t.Fatalf("legacy ECH-TLS path was not removed: %q", got)
	}
}

func TestResolveSubscriptionAsSIP008_SS2022KeepsRawPSK(t *testing.T) {
	const password = "RCF/0OOYmo6crue3LwlEyD8izLAbuUuyPic/vasJH/o="
	payload := []byte(`{
		"version": 1,
		"servers": [
			{
				"id": "n1",
				"remarks": "test",
				"server": "127.0.0.1",
				"server_port": 443,
				"password": "` + password + `",
				"method": "2022-blake3-aes-256-gcm",
				"plugin": "",
				"plugin_opts": ""
			}
		]
	}`)

	nodes, err := ResolveSubscriptionAsSIP008(logrus.New(), payload)
	if err != nil {
		t.Fatalf("ResolveSubscriptionAsSIP008: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected one node, got %d", len(nodes))
	}

	u, err := url.Parse(nodes[0])
	if err != nil {
		t.Fatalf("parse generated node: %v", err)
	}

	if _, hasPassword := u.User.Password(); hasPassword {
		t.Fatalf("expected canonical base64 userinfo, got %q", u.User.String())
	}

	decoded, err := base64.RawURLEncoding.DecodeString(u.User.Username())
	if err != nil {
		t.Fatalf("decode generated userinfo: %v", err)
	}

	if got, want := string(decoded), "2022-blake3-aes-256-gcm:"+password; got != want {
		t.Fatalf("unexpected decoded userinfo: got %q want %q", got, want)
	}
}

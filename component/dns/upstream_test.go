/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package dns

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/stretchr/testify/require"
)

func TestParseOIXCloudUpstreamSchemes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw       string
		scheme    UpstreamScheme
		port      uint16
		path      string
		canonical string
	}{
		{"oixcloud+udp://1.1.1.1", UpstreamScheme_UDP, 53, "", "oixcloud+udp://1.1.1.1:53"},
		{"oixcloud+tcp://1.1.1.1", UpstreamScheme_TCP, 53, "", "oixcloud+tcp://1.1.1.1:53"},
		{"oixcloud+tcp+udp://1.1.1.1", UpstreamScheme_TCP_UDP, 53, "", "oixcloud+tcp+udp://1.1.1.1:53"},
		{"oixcloud+udp+tcp://1.1.1.1", UpstreamScheme_TCP_UDP, 53, "", "oixcloud+tcp+udp://1.1.1.1:53"},
		{"oixcloud+tls://1.1.1.1", UpstreamScheme_TLS, 853, "", "oixcloud+tls://1.1.1.1:853"},
		{"oixcloud+quic://1.1.1.1", UpstreamScheme_QUIC, 853, "", "oixcloud+quic://1.1.1.1:853"},
		{"oixcloud+https://1.1.1.1/custom", UpstreamScheme_HTTPS, 443, "/custom", "oixcloud+https://1.1.1.1:443/custom"},
		{"oixcloud+h3://1.1.1.1", UpstreamScheme_H3, 443, "/dns-query", "oixcloud+h3://1.1.1.1:443/dns-query"},
		{"oixcloud+http3://1.1.1.1", UpstreamScheme_H3, 443, "/dns-query", "oixcloud+h3://1.1.1.1:443/dns-query"},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			raw := mustParseURL(test.raw)
			scheme, hostname, port, path, oixCloud, err := parseRawUpstream(raw)
			require.NoError(t, err)
			require.True(t, oixCloud)
			require.Equal(t, test.scheme, scheme)
			require.Equal(t, "1.1.1.1", hostname)
			require.Equal(t, test.port, port)
			require.Equal(t, test.path, path)
			upstream := &Upstream{Scheme: scheme, Hostname: hostname, Port: port, Path: path, OIXCloud: oixCloud}
			require.Equal(t, test.canonical, upstream.String())
		})
	}
}

func TestParseOIXCloudUpstreamRejectsInvalidSchemes(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"oixcloud+://1.1.1.1",
		"oixcloud+oixcloud+udp://1.1.1.1",
		"oixcloud+fakeip://1.1.1.1",
		"udp://1.1.1.1?oixcloud=true",
	} {
		_, _, _, _, _, err := parseRawUpstream(mustParseURL(raw))
		require.Error(t, err, raw)
	}
}

func TestOIXCloudUpstreamRequiresEmbeddedKey(t *testing.T) {
	originalKey := consts.OIXCloudDNSAuthPrivateKey
	t.Cleanup(func() { consts.OIXCloudDNSAuthPrivateKey = originalKey })

	resolver := &Dns{upstream: []*UpstreamResolver{{Raw: mustParseURL("oixcloud+udp://1.1.1.1:53")}}}
	consts.OIXCloudDNSAuthPrivateKey = ""
	require.ErrorContains(t, resolver.CheckUpstreamsFormat(), "missing oixCloud DNS auth private key")
	consts.OIXCloudDNSAuthPrivateKey = "invalid!"
	require.ErrorContains(t, resolver.CheckUpstreamsFormat(), "decode oixCloud DNS auth private key")
	consts.OIXCloudDNSAuthPrivateKey = base64.StdEncoding.EncodeToString([]byte("short"))
	require.ErrorContains(t, resolver.CheckUpstreamsFormat(), "invalid oixCloud DNS auth private key seed length")

	seed := make([]byte, ed25519.SeedSize)
	consts.OIXCloudDNSAuthPrivateKey = base64.StdEncoding.EncodeToString(seed)
	require.NoError(t, resolver.CheckUpstreamsFormat())
}

func TestUpstreamResolverConcurrentCallsCacheSuccessfulInitialization(t *testing.T) {
	original := newUpstreamFunc
	t.Cleanup(func() {
		newUpstreamFunc = original
	})

	var initCalls atomic.Int32
	newUpstreamFunc = func(_ context.Context, raw *url.URL, _ string, _ resolveUpstreamIp46Func) (*Upstream, error) {
		initCalls.Add(1)
		return &Upstream{
			Scheme:   UpstreamScheme_UDP,
			Hostname: raw.Hostname(),
			Port:     53,
		}, nil
	}

	resolver := &UpstreamResolver{
		Raw:     mustParseURL("udp://8.8.8.8:53"),
		Network: "udp",
	}

	var wg sync.WaitGroup
	results := make(chan *Upstream, 8)
	for range 8 {
		wg.Go(func() {
			upstream, err := resolver.GetUpstream(context.Background())
			if err != nil {
				t.Errorf("GetUpstream(context.Background()) error = %v", err)
				return
			}
			results <- upstream
		})
	}
	wg.Wait()
	close(results)

	if got := initCalls.Load(); got < 1 {
		t.Fatalf("expected initializer to be called at least once, got %d", got)
	}

	firstState := resolver.state.Load()
	if firstState == nil || firstState == &errorSentinel {
		t.Fatalf("expected successful cached state, got %#v", firstState)
	}
	firstUpstream := firstState.upstream
	if firstUpstream == nil {
		t.Fatalf("expected successful cached state, got %#v", firstState)
		return
	}

	for upstream := range results {
		if upstream == nil {
			t.Fatal("expected concurrent initialization to return an upstream")
			continue
		}
		if upstream.Hostname != firstUpstream.Hostname || upstream.Port != firstUpstream.Port || upstream.Scheme != firstUpstream.Scheme {
			t.Fatalf("expected all goroutines to observe equivalent upstream values, got %#v want %#v", upstream, firstUpstream)
		}
	}

	upstream, err := resolver.GetUpstream(context.Background())
	if err != nil {
		t.Fatalf("expected cached call to succeed: %v", err)
	}
	if upstream != firstUpstream {
		t.Fatal("expected cached call to reuse the stored upstream pointer")
	}
}

func TestUpstreamResolverRetriesAfterInitializerFailure(t *testing.T) {
	original := newUpstreamFunc
	t.Cleanup(func() {
		newUpstreamFunc = original
	})

	var initCalls atomic.Int32
	failErr := errors.New("transient failure")
	newUpstreamFunc = func(_ context.Context, raw *url.URL, _ string, _ resolveUpstreamIp46Func) (*Upstream, error) {
		call := initCalls.Add(1)
		if call == 1 {
			return nil, failErr
		}
		return &Upstream{
			Scheme:   UpstreamScheme_UDP,
			Hostname: raw.Hostname(),
			Port:     53,
		}, nil
	}

	resolver := &UpstreamResolver{
		Raw:     mustParseURL("udp://1.1.1.1:53"),
		Network: "udp",
	}

	if _, err := resolver.GetUpstream(context.Background()); !errors.Is(err, failErr) {
		t.Fatalf("expected first call to fail with %v, got %v", failErr, err)
	}
	if state := resolver.state.Load(); state != &errorSentinel {
		t.Fatalf("expected error sentinel after failed init, got %#v", state)
	}

	upstream, err := resolver.GetUpstream(context.Background())
	if err != nil {
		t.Fatalf("expected retry to succeed: %v", err)
	}
	if upstream == nil {
		t.Fatal("expected retry to return an upstream")
	}
	if got := initCalls.Load(); got != 2 {
		t.Fatalf("expected exactly two initializer calls, got %d", got)
	}
}

func TestUpstreamResolverRetriesAfterFinishCallbackFailure(t *testing.T) {
	original := newUpstreamFunc
	t.Cleanup(func() {
		newUpstreamFunc = original
	})

	var initCalls atomic.Int32
	newUpstreamFunc = func(_ context.Context, raw *url.URL, _ string, _ resolveUpstreamIp46Func) (*Upstream, error) {
		initCalls.Add(1)
		return &Upstream{
			Scheme:   UpstreamScheme_UDP,
			Hostname: raw.Hostname(),
			Port:     53,
		}, nil
	}

	failErr := errors.New("callback rejected upstream")
	var callbackCalls atomic.Int32
	resolver := &UpstreamResolver{
		Raw:     mustParseURL("udp://9.9.9.9:53"),
		Network: "udp",
		FinishInitCallback: func(_ *url.URL, _ *Upstream) error {
			if callbackCalls.Add(1) == 1 {
				return failErr
			}
			return nil
		},
	}

	if _, err := resolver.GetUpstream(context.Background()); !errors.Is(err, failErr) {
		t.Fatalf("expected callback failure %v, got %v", failErr, err)
	}
	if state := resolver.state.Load(); state != &errorSentinel {
		t.Fatalf("expected error sentinel after callback failure, got %#v", state)
	}

	upstream, err := resolver.GetUpstream(context.Background())
	if err != nil {
		t.Fatalf("expected retry after callback failure to succeed: %v", err)
	}
	if upstream == nil {
		t.Fatal("expected upstream after callback retry")
	}
	if got := callbackCalls.Load(); got != 2 {
		t.Fatalf("expected callback to be retried, got %d calls", got)
	}
	if got := initCalls.Load(); got != 2 {
		t.Fatalf("expected initializer to be retried, got %d calls", got)
	}
}

func TestCheckUpstreamsFormat_RequiresBootstrapResolverForNamedHost(t *testing.T) {
	s := &Dns{
		upstream: []*UpstreamResolver{
			{
				Raw:     mustParseURL("udp://dns.google:53"),
				Network: "udp",
			},
		},
	}

	err := s.CheckUpstreamsFormat()
	if err == nil {
		t.Fatal("expected named upstream without bootstrap resolver to be rejected")
	}
	if !strings.Contains(err.Error(), "bootstrap_resolver") {
		t.Fatalf("expected bootstrap_resolver guidance, got %v", err)
	}
}

func TestNewUpstream_UsesExplicitBootstrapResolver(t *testing.T) {
	var calls atomic.Int32
	upstream, err := NewUpstream(context.Background(), mustParseURL("udp://dns.google:53"), "udp", func(_ context.Context, host string, network string) (*netutils.Ip46, error, error) {
		calls.Add(1)
		if host != "dns.google" {
			t.Fatalf("unexpected host %q", host)
		}
		if network != "udp" {
			t.Fatalf("unexpected network %q", network)
		}
		return &netutils.Ip46{
			Ip4: netip.MustParseAddr("8.8.8.8"),
			Ip6: netip.MustParseAddr("2001:4860:4860::8888"),
		}, nil, nil
	})
	if err != nil {
		t.Fatalf("NewUpstream() error = %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected explicit bootstrap resolver to be called once, got %d", got)
	}
	if upstream.Hostname != "dns.google" {
		t.Fatalf("unexpected upstream hostname %q", upstream.Hostname)
	}
	if !upstream.Ip4.IsValid() || !upstream.Ip6.IsValid() {
		t.Fatalf("expected bootstrap resolver to populate both families, got %+v", upstream.Ip46)
	}
}

func TestNewUpstream_IPHostDoesNotRequireBootstrapResolver(t *testing.T) {
	upstream, err := NewUpstream(context.Background(), mustParseURL("udp://1.1.1.1:53"), "udp", func(_ context.Context, _ string, _ string) (*netutils.Ip46, error, error) {
		t.Fatal("bootstrap resolver should not be used for IP upstreams")
		return nil, nil, nil
	})
	if err != nil {
		t.Fatalf("NewUpstream() error = %v", err)
	}
	if upstream.Hostname != "1.1.1.1" {
		t.Fatalf("unexpected upstream hostname %q", upstream.Hostname)
	}
	if upstream.Ip4 != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("unexpected upstream IPv4 %v", upstream.Ip4)
	}
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

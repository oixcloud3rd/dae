/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	dnscomponent "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type fakeOIXCloudDnsForwarder struct {
	request  *dnsmessage.Msg
	response func(*dnsmessage.Msg) *dnsmessage.Msg
	err      error
	closed   bool
}

func (f *fakeOIXCloudDnsForwarder) ForwardDNS(_ context.Context, data []byte) (*dnsmessage.Msg, error) {
	request := new(dnsmessage.Msg)
	if err := request.Unpack(data); err != nil {
		return nil, err
	}
	f.request = request
	if f.response != nil {
		return f.response(request), f.err
	}
	return nil, f.err
}

func (f *fakeOIXCloudDnsForwarder) Close() error {
	f.closed = true
	return nil
}

func setTestOIXCloudKey(t *testing.T) {
	t.Helper()
	originalKey := consts.OIXCloudDNSAuthPrivateKey
	t.Cleanup(func() { consts.OIXCloudDNSAuthPrivateKey = originalKey })
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	consts.OIXCloudDNSAuthPrivateKey = base64.StdEncoding.EncodeToString(seed)
}

func TestOIXCloudDnsForwarderSignsAndRestores(t *testing.T) {
	setTestOIXCloudKey(t)

	base := &fakeOIXCloudDnsForwarder{}
	base.response = func(request *dnsmessage.Msg) *dnsmessage.Msg {
		signed := request.Question[0].Name
		return &dnsmessage.Msg{
			MsgHdr:   dnsmessage.MsgHdr{Id: request.Id, Response: true},
			Question: append([]dnsmessage.Question(nil), request.Question...),
			Answer: []dnsmessage.RR{
				&dnsmessage.CNAME{
					Hdr:    dnsmessage.RR_Header{Name: signed, Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET},
					Target: signed,
				},
			},
		}
	}
	forwarder, err := newOIXCloudDnsForwarder(base, nil)
	require.NoError(t, err)
	request := new(dnsmessage.Msg)
	request.SetQuestion("Example.COM.", dnsmessage.TypeA)
	packed, err := request.Pack()
	require.NoError(t, err)
	originalPacked := append([]byte(nil), packed...)

	response, err := forwarder.ForwardDNS(context.Background(), packed)
	require.NoError(t, err)
	require.Equal(t, originalPacked, packed)
	require.Equal(t, "Example.COM.", request.Question[0].Name)
	require.NotEqual(t, request.Question[0].Name, base.request.Question[0].Name)
	require.Equal(t, strings.ToLower(base.request.Question[0].Name), base.request.Question[0].Name)
	require.Equal(t, "Example.COM.", response.Question[0].Name)
	require.Equal(t, "Example.COM.", response.Answer[0].Header().Name)
	require.Equal(t, "Example.COM.", response.Answer[0].(*dnsmessage.CNAME).Target)

	require.NoError(t, forwarder.Close())
	require.True(t, base.closed)
}

func TestNewDnsForwarderWrapsOIXCloudUpstream(t *testing.T) {
	setTestOIXCloudKey(t)

	forwarder, err := newDnsForwarder(
		&dnscomponent.Upstream{
			Scheme:   dnscomponent.UpstreamScheme_UDP,
			Hostname: "1.1.1.1",
			Port:     53,
			OIXCloud: true,
		},
		dialArgument{
			l4proto:    "udp",
			bestDialer: newTestEndpointDialer(),
			bestTarget: netip.MustParseAddrPort("1.1.1.1:53"),
		},
		nil,
	)
	require.NoError(t, err)
	wrapped, ok := forwarder.(*oixCloudDnsForwarder)
	require.True(t, ok)
	require.IsType(t, &DoUDP{}, wrapped.DnsForwarder)
	require.NoError(t, forwarder.Close())
}

func TestOIXCloudDnsForwarderStrictFailures(t *testing.T) {
	setTestOIXCloudKey(t)

	base := &fakeOIXCloudDnsForwarder{}
	forwarder, err := newOIXCloudDnsForwarder(base, nil)
	require.NoError(t, err)
	_, err = forwarder.ForwardDNS(context.Background(), []byte{0x00})
	require.ErrorContains(t, err, "unpack oixCloud DNS request")
	require.Nil(t, base.request)

	request := new(dnsmessage.Msg)
	request.SetQuestion(strings.Repeat("a", 63)+"."+strings.Repeat("b", 63)+"."+strings.Repeat("c", 30)+".", dnsmessage.TypeA)
	packed, err := request.Pack()
	require.NoError(t, err)
	_, err = forwarder.ForwardDNS(context.Background(), packed)
	require.ErrorContains(t, err, "signed domain exceeds DNS limits")
	require.Nil(t, base.request)

	request.SetQuestion("example.com.", dnsmessage.TypeA)
	packed, err = request.Pack()
	require.NoError(t, err)
	_, err = forwarder.ForwardDNS(context.Background(), packed)
	require.EqualError(t, err, "empty oixCloud upstream response")
}

func TestOIXCloudDnsForwarderPreservesUnderlyingErrorAndRestoresResponse(t *testing.T) {
	setTestOIXCloudKey(t)

	base := &fakeOIXCloudDnsForwarder{err: ErrDNSTruncated}
	base.response = func(request *dnsmessage.Msg) *dnsmessage.Msg {
		return &dnsmessage.Msg{Question: append([]dnsmessage.Question(nil), request.Question...)}
	}
	forwarder, err := newOIXCloudDnsForwarder(base, nil)
	require.NoError(t, err)
	request := new(dnsmessage.Msg)
	request.SetQuestion("truncated.example.", dnsmessage.TypeA)
	packed, err := request.Pack()
	require.NoError(t, err)
	response, err := forwarder.ForwardDNS(context.Background(), packed)
	require.ErrorIs(t, err, ErrDNSTruncated)
	require.Equal(t, "truncated.example.", response.Question[0].Name)

	base.err = errors.New("upstream failure")
	base.response = nil
	_, err = forwarder.ForwardDNS(context.Background(), packed)
	require.EqualError(t, err, "upstream failure")
}

func TestOIXCloudDnsForwarderRepeatedAttemptsDoNotDoubleSign(t *testing.T) {
	setTestOIXCloudKey(t)

	base := &fakeOIXCloudDnsForwarder{}
	base.response = func(request *dnsmessage.Msg) *dnsmessage.Msg {
		return &dnsmessage.Msg{Question: append([]dnsmessage.Question(nil), request.Question...)}
	}
	forwarder, err := newOIXCloudDnsForwarder(base, nil)
	require.NoError(t, err)
	request := new(dnsmessage.Msg)
	request.SetQuestion("fallback.example.", dnsmessage.TypeAAAA)
	packed, err := request.Pack()
	require.NoError(t, err)

	_, err = forwarder.ForwardDNS(context.Background(), packed)
	require.NoError(t, err)
	first := base.request.Question[0].Name
	_, err = forwarder.ForwardDNS(context.Background(), packed)
	require.NoError(t, err)
	second := base.request.Question[0].Name
	require.Equal(t, first, second)
	require.Len(t, dnsmessage.SplitDomainName(second), 4)
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package daedns

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
)

type stubDirectDialer struct {
	conn netproxy.Conn
}

func (d stubDirectDialer) DialContext(_ context.Context, _, _ string) (netproxy.Conn, error) {
	return d.conn, nil
}

type oixCloudDNSResponseConn struct {
	serverAddr   netip.AddrPort
	response     []byte
	questionName string
}

func (c *oixCloudDNSResponseConn) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("Write should not be used for UDP PacketConn")
}

func (c *oixCloudDNSResponseConn) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("Read should not be used for UDP PacketConn")
}

func (c *oixCloudDNSResponseConn) WriteTo(p []byte, addr string) (int, error) {
	if addr != c.serverAddr.String() {
		return 0, fmt.Errorf("unexpected upstream address %q", addr)
	}

	var request dnsmessage.Msg
	if err := request.Unpack(p); err != nil {
		return 0, err
	}
	if len(request.Question) != 1 {
		return 0, fmt.Errorf("got %d DNS questions, want 1", len(request.Question))
	}
	c.questionName = request.Question[0].Name
	response := dnsmessage.Msg{
		MsgHdr:   dnsmessage.MsgHdr{Id: request.Id, Response: true},
		Question: request.Question,
		Answer: []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name: request.Question[0].Name, Rrtype: dnsmessage.TypeA,
				Class: dnsmessage.ClassINET, Ttl: 60,
			},
			A: []byte{203, 0, 113, 1},
		}},
	}
	packed, err := response.Pack()
	if err != nil {
		return 0, err
	}
	c.response = packed
	return len(p), nil
}

func (c *oixCloudDNSResponseConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	if len(c.response) == 0 {
		return 0, netip.AddrPort{}, io.EOF
	}
	n := copy(p, c.response)
	c.response = nil
	return n, c.serverAddr, nil
}

func (c *oixCloudDNSResponseConn) Close() error                       { return nil }
func (c *oixCloudDNSResponseConn) SetDeadline(_ time.Time) error      { return nil }
func (c *oixCloudDNSResponseConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *oixCloudDNSResponseConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestInternalExchangeSignsOIXCloudQuestionAndRestoresResponse(t *testing.T) {
	originalPrivateKey := consts.OIXCloudDNSAuthPrivateKey
	t.Cleanup(func() {
		consts.OIXCloudDNSAuthPrivateKey = originalPrivateKey
	})

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	consts.OIXCloudDNSAuthPrivateKey = base64.StdEncoding.EncodeToString(seed)

	request := new(dnsmessage.Msg)
	request.SetQuestion("node.example.com.", dnsmessage.TypeA)
	data, err := request.Pack()
	if err != nil {
		t.Fatalf("pack request: %v", err)
	}
	serverAddr := netip.MustParseAddrPort("203.0.113.53:53")

	for _, test := range []struct {
		name     string
		oixCloud bool
	}{
		{name: "oixCloud", oixCloud: true},
		{name: "ordinary", oixCloud: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := &oixCloudDNSResponseConn{serverAddr: serverAddr}
			upstream := &componentdns.Upstream{
				Scheme: componentdns.UpstreamScheme_UDP,
				Port:   serverAddr.Port(), OIXCloud: test.oixCloud,
				Ip46: &netutils.Ip46{Ip4: serverAddr.Addr()},
			}

			router := &Router{directDialer: stubDirectDialer{conn: conn}}
			response, exchangeErr := router.exchange(context.Background(), upstream, data)
			if exchangeErr != nil {
				t.Fatalf("exchange() error = %v", exchangeErr)
			}
			if response.Question[0].Name != request.Question[0].Name {
				t.Fatalf("response question = %q, want restored %q", response.Question[0].Name, request.Question[0].Name)
			}
			if response.Answer[0].Header().Name != request.Question[0].Name {
				t.Fatalf("answer name = %q, want restored %q", response.Answer[0].Header().Name, request.Question[0].Name)
			}

			labels := dnsmessage.SplitDomainName(conn.questionName)
			wantLabels := 3
			if test.oixCloud {
				wantLabels += 2
			}
			if len(labels) != wantLabels {
				t.Fatalf("forwarded question %q has %d labels, want %d", conn.questionName, len(labels), wantLabels)
			}
			if !test.oixCloud && conn.questionName != request.Question[0].Name {
				t.Fatalf("ordinary forwarded question = %q, want %q", conn.questionName, request.Question[0].Name)
			}
		})
	}
}

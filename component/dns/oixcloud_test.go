/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func testOIXCloudDNSAuthPrivateKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func testOIXCloudSigner(unixTime int64) *OIXCloudSigner {
	return &OIXCloudSigner{
		privateKey: testOIXCloudDNSAuthPrivateKey(),
		timeFunc: func() time.Time {
			return time.Unix(unixTime, 0)
		},
	}
}

func TestParseOIXCloudDNSAuthPrivateKey(t *testing.T) {
	t.Parallel()

	seed := testOIXCloudDNSAuthPrivateKey().Seed()
	for _, encoded := range []string{
		base64.StdEncoding.EncodeToString(seed),
		base64.RawStdEncoding.EncodeToString(seed),
	} {
		privateKey, err := ParseOIXCloudDNSAuthPrivateKey(encoded)
		require.NoError(t, err)
		require.Equal(t, testOIXCloudDNSAuthPrivateKey(), privateKey)
	}
	_, err := ParseOIXCloudDNSAuthPrivateKey("")
	require.EqualError(t, err, "missing oixCloud DNS auth private key: inject OIXCLOUD_DNS_AUTH_PRIVATE_KEY at build time")
	_, err = ParseOIXCloudDNSAuthPrivateKey("not-base64!")
	require.ErrorContains(t, err, "decode oixCloud DNS auth private key")
	_, err = ParseOIXCloudDNSAuthPrivateKey(base64.StdEncoding.EncodeToString([]byte("short")))
	require.EqualError(t, err, "invalid oixCloud DNS auth private key seed length: got 5, want 32")
}

func TestOIXCloudTokenizeHostMatchesSingBox(t *testing.T) {
	t.Parallel()

	signer := testOIXCloudSigner(1700000000)
	signed, err := signer.TokenizeHost("Example.COM.")
	require.NoError(t, err)
	require.Equal(t, "hfbbr4ykfgo2u76ahw3ecur5mnygaa4764kn6aqcgx7how7mhopq.rbjitbn7b6svs4ryz4cu76p5pjfekczt3mygj6q23wjfsfvs3uaq.example.com.", signed)

	labels := dnsmessage.SplitDomainName(signed)
	require.Len(t, labels, 4)
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	first, err := encoding.DecodeString(strings.ToUpper(labels[0]))
	require.NoError(t, err)
	second, err := encoding.DecodeString(strings.ToUpper(labels[1]))
	require.NoError(t, err)
	signature := make([]byte, 0, len(first)+len(second))
	signature = append(signature, first...)
	signature = append(signature, second...)
	publicKey := testOIXCloudDNSAuthPrivateKey().Public().(ed25519.PublicKey)
	require.True(t, ed25519.Verify(publicKey, oixCloudAuthMessage("example.com", 1700000000/OIXCloudWindowSeconds), signature))

	signer.timeFunc = func() time.Time { return time.Unix(1700000099, 0) }
	sameWindow, err := signer.TokenizeHost("example.com")
	require.NoError(t, err)
	require.Equal(t, signed, sameWindow)
	signer.timeFunc = func() time.Time { return time.Unix(1700000300, 0) }
	nextWindow, err := signer.TokenizeHost("example.com")
	require.NoError(t, err)
	require.NotEqual(t, signed, nextWindow)

	root, err := signer.TokenizeHost(".")
	require.NoError(t, err)
	require.Equal(t, ".", root)
}

func TestOIXCloudPrepareAndRestoreResponse(t *testing.T) {
	t.Parallel()

	signer := testOIXCloudSigner(1700000000)
	request := new(dnsmessage.Msg)
	request.SetQuestion("Example.COM.", dnsmessage.TypeA)
	forward, names, err := signer.PrepareMessage(request)
	require.NoError(t, err)
	require.Equal(t, "Example.COM.", request.Question[0].Name)
	require.NotEqual(t, request.Question[0].Name, forward.Question[0].Name)
	require.Equal(t, strings.ToLower(forward.Question[0].Name), forward.Question[0].Name)

	signed := forward.Question[0].Name
	header := func(recordType uint16) dnsmessage.RR_Header {
		return dnsmessage.RR_Header{Name: signed, Rrtype: recordType, Class: dnsmessage.ClassINET, Ttl: 60}
	}
	response := &dnsmessage.Msg{
		MsgHdr:   dnsmessage.MsgHdr{Id: request.Id, Response: true},
		Question: append([]dnsmessage.Question(nil), forward.Question...),
		Answer: []dnsmessage.RR{
			&dnsmessage.A{Hdr: header(dnsmessage.TypeA)},
			&dnsmessage.CNAME{Hdr: header(dnsmessage.TypeCNAME), Target: signed},
			&dnsmessage.PTR{Hdr: header(dnsmessage.TypePTR), Ptr: signed},
			&dnsmessage.MX{Hdr: header(dnsmessage.TypeMX), Mx: signed},
			&dnsmessage.SRV{Hdr: header(dnsmessage.TypeSRV), Target: signed},
		},
		Ns: []dnsmessage.RR{
			&dnsmessage.NS{Hdr: header(dnsmessage.TypeNS), Ns: signed},
			&dnsmessage.SOA{Hdr: header(dnsmessage.TypeSOA), Ns: signed, Mbox: signed},
		},
		Extra: []dnsmessage.RR{
			&dnsmessage.SVCB{Hdr: header(dnsmessage.TypeSVCB), Target: signed},
			&dnsmessage.HTTPS{SVCB: dnsmessage.SVCB{Hdr: header(dnsmessage.TypeHTTPS), Target: signed}},
		},
	}
	signer.RestoreResponse(response, names)
	require.Equal(t, "Example.COM.", response.Question[0].Name)
	for _, records := range [][]dnsmessage.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range records {
			require.Equal(t, "Example.COM.", record.Header().Name)
		}
	}
	require.Equal(t, "Example.COM.", response.Answer[1].(*dnsmessage.CNAME).Target)
	require.Equal(t, "Example.COM.", response.Answer[2].(*dnsmessage.PTR).Ptr)
	require.Equal(t, "Example.COM.", response.Answer[3].(*dnsmessage.MX).Mx)
	require.Equal(t, "Example.COM.", response.Answer[4].(*dnsmessage.SRV).Target)
	require.Equal(t, "Example.COM.", response.Ns[0].(*dnsmessage.NS).Ns)
	require.Equal(t, "Example.COM.", response.Ns[1].(*dnsmessage.SOA).Ns)
	require.Equal(t, "Example.COM.", response.Ns[1].(*dnsmessage.SOA).Mbox)
	require.Equal(t, "Example.COM.", response.Extra[0].(*dnsmessage.SVCB).Target)
	require.Equal(t, "Example.COM.", response.Extra[1].(*dnsmessage.HTTPS).Target)
}

func TestOIXCloudStrictSigningFailures(t *testing.T) {
	t.Parallel()

	signer := testOIXCloudSigner(1700000000)
	_, _, err := signer.PrepareMessage(nil)
	require.EqualError(t, err, "nil oixCloud DNS request")

	request := new(dnsmessage.Msg)
	request.SetQuestion(strings.Repeat("a", 63)+"."+strings.Repeat("b", 63)+"."+strings.Repeat("c", 30)+".", dnsmessage.TypeA)
	_, _, err = signer.PrepareMessage(request)
	require.ErrorContains(t, err, "signed domain exceeds DNS limits")
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

const OIXCloudWindowSeconds = int64(300)

var oixCloudEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// OIXCloudSigner signs DNS questions using the oixCloud authentication format.
type OIXCloudSigner struct {
	privateKey ed25519.PrivateKey
	timeFunc   func() time.Time
}

// ParseOIXCloudDNSAuthPrivateKey parses a Base64-encoded Ed25519 seed.
func ParseOIXCloudDNSAuthPrivateKey(rawKey string) (ed25519.PrivateKey, error) {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return nil, errors.New("missing oixCloud DNS auth private key: inject OIXCLOUD_DNS_AUTH_PRIVATE_KEY at build time")
	}
	seed, err := base64.StdEncoding.DecodeString(rawKey)
	if err != nil {
		seed, err = base64.RawStdEncoding.DecodeString(rawKey)
		if err != nil {
			return nil, fmt.Errorf("decode oixCloud DNS auth private key: %w", err)
		}
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid oixCloud DNS auth private key seed length: got %d, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// NewOIXCloudSigner constructs a signer from the key embedded at link time.
func NewOIXCloudSigner() (*OIXCloudSigner, error) {
	privateKey, err := ParseOIXCloudDNSAuthPrivateKey(consts.OIXCloudDNSAuthPrivateKey)
	if err != nil {
		return nil, err
	}
	return &OIXCloudSigner{
		privateKey: privateKey,
		timeFunc:   time.Now,
	}, nil
}

// PrepareMessage returns a signed copy of message and a name map used to
// restore the upstream response. The input message is never modified.
func (s *OIXCloudSigner) PrepareMessage(message *dnsmessage.Msg) (*dnsmessage.Msg, map[string]string, error) {
	if message == nil {
		return nil, nil, errors.New("nil oixCloud DNS request")
	}
	forward := message.Copy()
	restore := make(map[string]string, len(forward.Question))
	for questionIndex := range forward.Question {
		original := dnsmessage.Fqdn(forward.Question[questionIndex].Name)
		signed, err := s.TokenizeHost(original)
		if err != nil {
			return nil, nil, fmt.Errorf("sign DNS question %s: %w", original, err)
		}
		if strings.EqualFold(original, signed) {
			continue
		}
		forward.Question[questionIndex].Name = signed
		restore[strings.ToLower(signed)] = original
	}
	return forward, restore, nil
}

// TokenizeHost creates the signed oixCloud DNS name for host.
func (s *OIXCloudSigner) TokenizeHost(host string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if name == "" {
		return host, nil
	}
	window := s.timeFunc().Unix() / OIXCloudWindowSeconds
	signature := ed25519.Sign(s.privateKey, oixCloudAuthMessage(name, window))
	half := ed25519.SignatureSize / 2
	first := strings.ToLower(oixCloudEncoding.EncodeToString(signature[:half]))
	second := strings.ToLower(oixCloudEncoding.EncodeToString(signature[half:]))
	signed := dnsmessage.Fqdn(first + "." + second + "." + name)
	if _, valid := dnsmessage.IsDomainName(signed); !valid {
		return "", fmt.Errorf("signed domain exceeds DNS limits: %s", name)
	}
	return signed, nil
}

func oixCloudAuthMessage(name string, window int64) []byte {
	message := make([]byte, 0, len(name)+1+20)
	message = append(message, name...)
	message = append(message, '|')
	return strconv.AppendInt(message, window, 10)
}

// RestoreResponse replaces signed question and record names with their
// original names before the response enters routing and caching.
func (s *OIXCloudSigner) RestoreResponse(response *dnsmessage.Msg, names map[string]string) {
	for questionIndex := range response.Question {
		if original, loaded := names[strings.ToLower(dnsmessage.Fqdn(response.Question[questionIndex].Name))]; loaded {
			response.Question[questionIndex].Name = original
		}
	}
	restoreOIXCloudRRs(response.Answer, names)
	restoreOIXCloudRRs(response.Ns, names)
	restoreOIXCloudRRs(response.Extra, names)
}

func restoreOIXCloudRRs(records []dnsmessage.RR, names map[string]string) {
	for _, record := range records {
		if record == nil {
			continue
		}
		header := record.Header()
		if original, loaded := names[strings.ToLower(dnsmessage.Fqdn(header.Name))]; loaded {
			header.Name = original
		}
		restoreOIXCloudRRTarget(record, names)
	}
}

func restoreOIXCloudRRTarget(record dnsmessage.RR, names map[string]string) {
	restore := func(name string) string {
		if original, loaded := names[strings.ToLower(dnsmessage.Fqdn(name))]; loaded {
			return original
		}
		return name
	}
	switch typedRecord := record.(type) {
	case *dnsmessage.CNAME:
		typedRecord.Target = restore(typedRecord.Target)
	case *dnsmessage.NS:
		typedRecord.Ns = restore(typedRecord.Ns)
	case *dnsmessage.PTR:
		typedRecord.Ptr = restore(typedRecord.Ptr)
	case *dnsmessage.MX:
		typedRecord.Mx = restore(typedRecord.Mx)
	case *dnsmessage.SRV:
		typedRecord.Target = restore(typedRecord.Target)
	case *dnsmessage.SOA:
		typedRecord.Ns = restore(typedRecord.Ns)
		typedRecord.Mbox = restore(typedRecord.Mbox)
	case *dnsmessage.SVCB:
		typedRecord.Target = restore(typedRecord.Target)
	case *dnsmessage.HTTPS:
		typedRecord.Target = restore(typedRecord.Target)
	}
}

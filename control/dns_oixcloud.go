/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"

	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type oixCloudDnsForwarder struct {
	DnsForwarder
	signer *dns.OIXCloudSigner
	log    *logrus.Logger
}

func newOIXCloudDnsForwarder(forwarder DnsForwarder, log *logrus.Logger) (DnsForwarder, error) {
	signer, err := dns.NewOIXCloudSigner()
	if err != nil {
		return nil, err
	}
	return &oixCloudDnsForwarder{
		DnsForwarder: forwarder,
		signer:       signer,
		log:          log,
	}, nil
}

func (f *oixCloudDnsForwarder) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	request := new(dnsmessage.Msg)
	if err := request.Unpack(data); err != nil {
		return nil, fmt.Errorf("unpack oixCloud DNS request: %w", err)
	}
	forward, restore, err := f.signer.PrepareMessage(request)
	if err != nil {
		return nil, err
	}
	if f.log != nil && f.log.IsLevelEnabled(logrus.DebugLevel) {
		for signed, original := range restore {
			f.log.WithContext(ctx).Debugf("oixCloud: sign %s -> %s", original, signed)
		}
	}
	forwardData, err := forward.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack oixCloud DNS request: %w", err)
	}

	response, forwardErr := f.DnsForwarder.ForwardDNS(ctx, forwardData)
	if response != nil {
		f.signer.RestoreResponse(response, restore)
		if f.log != nil && f.log.IsLevelEnabled(logrus.DebugLevel) {
			for signed, original := range restore {
				f.log.WithContext(ctx).Debugf("oixCloud: restore %s -> %s", signed, original)
			}
		}
	}
	if forwardErr != nil {
		return response, forwardErr
	}
	if response == nil {
		return nil, errors.New("empty oixCloud upstream response")
	}
	return response, nil
}

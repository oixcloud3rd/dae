/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateOIXCloudDNSAuthPrivateKey(t *testing.T) {
	t.Parallel()

	encoded := base64.StdEncoding.EncodeToString(make([]byte, oixCloudSeedSize))
	require.NoError(t, validateOIXCloudDNSAuthPrivateKey(encoded, true))
	require.NoError(t, validateOIXCloudDNSAuthPrivateKey(strings.TrimRight(encoded, "="), true))
	require.NoError(t, validateOIXCloudDNSAuthPrivateKey("", false))
	require.EqualError(t, validateOIXCloudDNSAuthPrivateKey("", true), "missing OIXCLOUD_DNS_AUTH_PRIVATE_KEY")
	require.ErrorContains(t, validateOIXCloudDNSAuthPrivateKey("invalid!", false), "decode OIXCLOUD_DNS_AUTH_PRIVATE_KEY")
	require.EqualError(
		t,
		validateOIXCloudDNSAuthPrivateKey(base64.StdEncoding.EncodeToString([]byte("short")), false),
		"invalid OIXCLOUD_DNS_AUTH_PRIVATE_KEY seed length: got 5, want 32",
	)
}

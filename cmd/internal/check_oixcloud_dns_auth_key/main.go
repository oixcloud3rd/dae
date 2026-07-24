/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const (
	oixCloudDNSAuthPrivateKeyEnvironment = "OIXCLOUD_DNS_AUTH_PRIVATE_KEY"
	oixCloudDNSAuthRequireKeyEnvironment = "OIXCLOUD_DNS_AUTH_REQUIRE_PRIVATE_KEY"
	oixCloudSeedSize                     = 32
)

func validateOIXCloudDNSAuthPrivateKey(rawKey string, required bool) error {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		if required {
			return fmt.Errorf("missing %s", oixCloudDNSAuthPrivateKeyEnvironment)
		}
		return nil
	}
	seed, err := base64.StdEncoding.DecodeString(rawKey)
	if err != nil {
		seed, err = base64.RawStdEncoding.DecodeString(rawKey)
		if err != nil {
			return fmt.Errorf("decode %s: %w", oixCloudDNSAuthPrivateKeyEnvironment, err)
		}
	}
	if len(seed) != oixCloudSeedSize {
		return fmt.Errorf("invalid %s seed length: got %d, want %d", oixCloudDNSAuthPrivateKeyEnvironment, len(seed), oixCloudSeedSize)
	}
	return nil
}

func main() {
	err := validateOIXCloudDNSAuthPrivateKey(
		os.Getenv(oixCloudDNSAuthPrivateKeyEnvironment),
		os.Getenv(oixCloudDNSAuthRequireKeyEnvironment) == "1",
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

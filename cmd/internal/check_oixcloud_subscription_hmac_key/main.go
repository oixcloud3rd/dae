/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	oixCloudSubscriptionHMACKeyEnvironment = "OIXCLOUD_SUBSCRIPTION_HMAC_KEY"
	oixCloudSubscriptionRequireKeyEnv      = "OIXCLOUD_SUBSCRIPTION_REQUIRE_HMAC_KEY"
)

func validateOIXCloudSubscriptionHMACKey(rawKey string, required bool) error {
	if strings.TrimSpace(rawKey) == "" && required {
		return errors.New("missing OIXCLOUD_SUBSCRIPTION_HMAC_KEY")
	}
	return nil
}

func main() {
	err := validateOIXCloudSubscriptionHMACKey(
		os.Getenv(oixCloudSubscriptionHMACKeyEnvironment),
		os.Getenv(oixCloudSubscriptionRequireKeyEnv) == "1",
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

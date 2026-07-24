/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package consts

// OIXCloudDNSAuthPrivateKey is a Base64-encoded 32-byte Ed25519 seed injected
// at link time. It intentionally has no runtime configuration source.
var OIXCloudDNSAuthPrivateKey string

// OIXCloudSubscriptionHMACKey authenticates requests to and responses from the
// oixCloud managed subscription endpoint. It is injected at link time and has
// no runtime configuration source.
var OIXCloudSubscriptionHMACKey string

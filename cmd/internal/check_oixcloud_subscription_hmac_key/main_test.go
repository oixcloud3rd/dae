/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package main

import "testing"

func TestValidateOIXCloudSubscriptionHMACKey(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		key      string
		required bool
		wantErr  bool
	}{
		{name: "provided", key: "test-key", required: true},
		{name: "optional empty", required: false},
		{name: "required empty", required: true, wantErr: true},
		{name: "required whitespace", key: " \t", required: true, wantErr: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateOIXCloudSubscriptionHMACKey(test.key, test.required)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateOIXCloudSubscriptionHMACKey() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

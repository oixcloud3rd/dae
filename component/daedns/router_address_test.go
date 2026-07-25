/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package daedns

import "testing"

func TestCompileNodeAddressConditions(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		value     string
		address   string
		wantMatch bool
	}{
		{name: "keyword ignores hostname case", key: "address_keyword", value: "A.NODES", address: "a.nodes.example", wantMatch: true},
		{name: "regex matches address host", key: "address_regex", value: `^[a-d]\.nodes\.example$`, address: "b.nodes.example", wantMatch: true},
		{name: "suffix matches at label boundary", key: "address_suffix", value: ".NODES.EXAMPLE.", address: "c.nodes.example.", wantMatch: true},
		{name: "suffix rejects partial label", key: "address_suffix", value: "nodes.example", address: "evilnodes.example", wantMatch: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predicate, err := compileNodeCondition(tt.key, []string{tt.value})
			if err != nil {
				t.Fatalf("compileNodeCondition() error = %v", err)
			}
			if got := predicate(NodeMeta{AddressHost: tt.address}); got != tt.wantMatch {
				t.Fatalf("predicate(AddressHost=%q) = %v, want %v", tt.address, got, tt.wantMatch)
			}
		})
	}
}

func TestCompileSubNodeAddressCondition(t *testing.T) {
	predicate, err := compileSubNodeCondition("address_suffix", []string{"nodes.example"})
	if err != nil {
		t.Fatalf("compileSubNodeCondition() error = %v", err)
	}
	if !predicate(NodeMeta{SubscriptionTag: "oixcloud", AddressHost: "a.nodes.example"}) {
		t.Fatal("expected subscription node address suffix to match")
	}
	if predicate(NodeMeta{SubscriptionTag: "oixcloud", AddressHost: "evilnodes.example"}) {
		t.Fatal("expected partial-label suffix not to match")
	}
}

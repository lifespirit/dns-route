package main

import (
	"net/netip"
	"testing"
)

func TestPrefixCovers(t *testing.T) {
	tests := []struct {
		name string
		have string
		want string
		ok   bool
	}{
		{name: "exact IPv4 prefix", have: "10.0.0.0/24", want: "10.0.0.0/24", ok: true},
		{name: "broader IPv4 prefix covers narrower", have: "10.0.0.0/16", want: "10.0.4.0/24", ok: true},
		{name: "narrower IPv4 prefix does not cover broader with same address", have: "10.0.0.0/25", want: "10.0.0.0/24", ok: false},
		{name: "disjoint IPv4 prefixes", have: "10.0.0.0/24", want: "10.0.1.0/24", ok: false},
		{name: "broader IPv6 prefix covers narrower", have: "2001:db8::/32", want: "2001:db8:1234::/48", ok: true},
		{name: "narrower IPv6 prefix does not cover broader", have: "2001:db8::/48", want: "2001:db8::/32", ok: false},
		{name: "different address families", have: "0.0.0.0/0", want: "::/0", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			have := netip.MustParsePrefix(tt.have)
			want := netip.MustParsePrefix(tt.want)
			if got := prefixCovers(have, want); got != tt.ok {
				t.Fatalf("prefixCovers(%s, %s) = %t, want %t", have, want, got, tt.ok)
			}
		})
	}
}

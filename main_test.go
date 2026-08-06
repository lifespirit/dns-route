package main

import (
	"net"
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

func TestCIDRCoveredBySnapshotDoesNotAcceptNarrowerRoute(t *testing.T) {
	rm := &RouteManager{snapshot: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/25")}}

	if rm.cidrCoveredBySnapshot("10.0.0.0/24") {
		t.Fatal("10.0.0.0/25 must not cover the requested 10.0.0.0/24")
	}
	if !rm.cidrCoveredBySnapshot("10.0.0.64/26") {
		t.Fatal("10.0.0.0/25 must cover 10.0.0.64/26")
	}
}

func TestIPCoveredBySnapshotHandlesIPv4AndIPv6(t *testing.T) {
	rm := &RouteManager{
		snapshot: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("2001:db8::/32"),
		},
	}

	if !rm.ipCoveredBySnapshot(net.ParseIP("192.0.2.10")) {
		t.Fatal("IPv4 address should be covered")
	}
	if !rm.ipCoveredBySnapshot(net.ParseIP("2001:db8::10")) {
		t.Fatal("IPv6 address should be covered")
	}
	if rm.ipCoveredBySnapshot(net.ParseIP("198.51.100.10")) {
		t.Fatal("unrelated IPv4 address must not be covered")
	}
}

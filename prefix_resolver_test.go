package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestHostPrefixResolution(t *testing.T) {
	tests := []struct {
		addr   string
		prefix string
	}{
		{addr: "192.0.2.10", prefix: "192.0.2.10/32"},
		{addr: "::ffff:192.0.2.10", prefix: "192.0.2.10/32"},
		{addr: "2001:db8::10", prefix: "2001:db8::10/128"},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := hostPrefixResolution(netip.MustParseAddr(tt.addr))
			if got.Prefix.String() != tt.prefix {
				t.Fatalf("prefix = %s, want %s", got.Prefix, tt.prefix)
			}
			if got.Source != PrefixSourceHost {
				t.Fatalf("source = %q, want %q", got.Source, PrefixSourceHost)
			}
		})
	}
}

func TestCymruQueryName(t *testing.T) {
	if got, want := cymruQueryName(netip.MustParseAddr("192.0.2.10")), "10.2.0.192.origin.asn.cymru.com."; got != want {
		t.Fatalf("IPv4 query = %q, want %q", got, want)
	}

	got := cymruQueryName(netip.MustParseAddr("2001:db8::1"))
	if !strings.HasPrefix(got, "1.0.0.0.") {
		t.Fatalf("IPv6 query has unexpected beginning: %q", got)
	}
	if !strings.HasSuffix(got, "8.b.d.0.1.0.0.2.origin6.asn.cymru.com.") {
		t.Fatalf("IPv6 query has unexpected ending: %q", got)
	}
}

func TestParseCymruPrefix(t *testing.T) {
	tests := []struct {
		name string
		txt  string
		addr string
		want string
		ok   bool
	}{
		{
			name: "IPv4 aggregate",
			txt:  "64496 | 192.0.2.0/24 | US | arin | 1992-12-01",
			addr: "192.0.2.10",
			want: "192.0.2.0/24",
			ok:   true,
		},
		{
			name: "IPv6 aggregate",
			txt:  "64496 | 2001:db8::/32 | ZZ | ripencc | 2001-01-01",
			addr: "2001:db8:1234::1",
			want: "2001:db8::/32",
			ok:   true,
		},
		{
			name: "host prefix is ignored",
			txt:  "64496 | 192.0.2.10/32 | US | arin | 1992-12-01",
			addr: "192.0.2.10",
			ok:   false,
		},
		{
			name: "prefix does not cover address",
			txt:  "64496 | 198.51.100.0/24 | US | arin | 1992-12-01",
			addr: "192.0.2.10",
			ok:   false,
		},
		{
			name: "address family mismatch",
			txt:  "64496 | 2001:db8::/32 | ZZ | ripencc | 2001-01-01",
			addr: "192.0.2.10",
			ok:   false,
		},
		{
			name: "malformed response",
			txt:  "not a Team Cymru response",
			addr: "192.0.2.10",
			ok:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseCymruPrefix(tt.txt, netip.MustParseAddr(tt.addr))
			if ok != tt.ok {
				t.Fatalf("ok = %t, want %t (prefix %s)", ok, tt.ok, got)
			}
			if tt.ok && got.String() != tt.want {
				t.Fatalf("prefix = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCymruPrefixResolverSuccess(t *testing.T) {
	var query string
	resolver := NewCymruPrefixResolver(func(_ context.Context, queryName string) ([]string, error) {
		query = queryName
		return []string{
			"malformed",
			"64496 | 192.0.2.0/24 | US | arin | 1992-12-01",
		}, nil
	})

	got, err := resolver.Resolve(context.Background(), netip.MustParseAddr("192.0.2.10"))
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if got.Prefix.String() != "192.0.2.0/24" || got.Source != PrefixSourceCymru {
		t.Fatalf("resolution = %+v, want Cymru 192.0.2.0/24", got)
	}
	if query != "10.2.0.192.origin.asn.cymru.com." {
		t.Fatalf("query = %q", query)
	}
}

func TestCymruPrefixResolverFallsBackToHostPrefix(t *testing.T) {
	lookupErr := errors.New("upstream unavailable")
	resolver := NewCymruPrefixResolver(func(_ context.Context, _ string) ([]string, error) {
		return nil, lookupErr
	})

	got, err := resolver.Resolve(context.Background(), netip.MustParseAddr("203.0.113.7"))
	if !errors.Is(err, lookupErr) {
		t.Fatalf("error = %v, want %v", err, lookupErr)
	}
	if got.Prefix.String() != "203.0.113.7/32" || got.Source != PrefixSourceHost {
		t.Fatalf("fallback = %+v, want host /32", got)
	}
}

func TestCymruPrefixResolverFallsBackWhenNoUsablePrefix(t *testing.T) {
	resolver := NewCymruPrefixResolver(func(_ context.Context, _ string) ([]string, error) {
		return []string{"64496 | 203.0.113.7/32 | US | arin | 1992-12-01"}, nil
	})

	got, err := resolver.Resolve(context.Background(), netip.MustParseAddr("203.0.113.7"))
	if !errors.Is(err, ErrNoUsableCymruPrefix) {
		t.Fatalf("error = %v, want ErrNoUsableCymruPrefix", err)
	}
	if got.Prefix.String() != "203.0.113.7/32" || got.Source != PrefixSourceHost {
		t.Fatalf("fallback = %+v, want host /32", got)
	}
}

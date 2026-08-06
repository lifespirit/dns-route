package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

type PrefixSource string

const (
	PrefixSourceHost  PrefixSource = "host"
	PrefixSourceCymru PrefixSource = "cymru"
)

var ErrNoUsableCymruPrefix = errors.New("Team Cymru response contains no usable covering prefix")

// PrefixResolution describes the prefix selected for one DNS answer address.
// Source is "cymru" when Team Cymru returned a usable aggregate and "host"
// when the resolver had to preserve the /32 or /128 fallback.
type PrefixResolution struct {
	Prefix netip.Prefix
	Source PrefixSource
}

// PrefixResolver converts one address from a DNS answer into the prefix that
// should be programmed by route backends. Implementations must always return a
// valid host-prefix fallback for a valid address, even when err is non-nil.
type PrefixResolver interface {
	Resolve(ctx context.Context, addr netip.Addr) (PrefixResolution, error)
}

// TXTLookupFunc isolates DNS transport from prefix parsing and makes the Cymru
// resolver testable without network access.
type TXTLookupFunc func(ctx context.Context, queryName string) ([]string, error)

type CymruPrefixResolver struct {
	lookupTXT TXTLookupFunc
}

func NewCymruPrefixResolver(lookupTXT TXTLookupFunc) *CymruPrefixResolver {
	return &CymruPrefixResolver{lookupTXT: lookupTXT}
}

func hostPrefixResolution(addr netip.Addr) PrefixResolution {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return PrefixResolution{}
	}
	return PrefixResolution{
		Prefix: netip.PrefixFrom(addr, addr.BitLen()),
		Source: PrefixSourceHost,
	}
}

func (r *CymruPrefixResolver) Resolve(ctx context.Context, addr netip.Addr) (PrefixResolution, error) {
	fallback := hostPrefixResolution(addr)
	if !fallback.Prefix.IsValid() {
		return PrefixResolution{}, fmt.Errorf("invalid address %q", addr)
	}
	if r == nil || r.lookupTXT == nil {
		return fallback, errors.New("Team Cymru TXT lookup is not configured")
	}

	queryName := cymruQueryName(addr)
	if queryName == "" {
		return fallback, fmt.Errorf("cannot build Team Cymru query for %q", addr)
	}

	txtRecords, err := r.lookupTXT(ctx, queryName)
	if err != nil {
		return fallback, err
	}
	for _, txt := range txtRecords {
		if prefix, ok := parseCymruPrefix(txt, addr); ok {
			return PrefixResolution{Prefix: prefix, Source: PrefixSourceCymru}, nil
		}
	}
	return fallback, ErrNoUsableCymruPrefix
}

func cymruQueryName(addr netip.Addr) string {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return ""
	}
	if addr.Is4() {
		v4 := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com.", v4[3], v4[2], v4[1], v4[0])
	}
	if !addr.Is6() {
		return ""
	}

	v6 := addr.As16()
	const hex = "0123456789abcdef"
	labels := make([]byte, 0, 64+len("origin6.asn.cymru.com."))
	for i := len(v6) - 1; i >= 0; i-- {
		b := v6[i]
		labels = append(labels, hex[b&0x0f], '.', hex[b>>4], '.')
	}
	labels = append(labels, "origin6.asn.cymru.com."...)
	return string(labels)
}

func parseCymruPrefix(txt string, addr netip.Addr) (netip.Prefix, bool) {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return netip.Prefix{}, false
	}

	fields := strings.Split(txt, "|")
	if len(fields) < 2 {
		return netip.Prefix{}, false
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(fields[1]))
	if err != nil {
		return netip.Prefix{}, false
	}
	prefix = prefix.Masked()

	if prefix.Addr().Is4() != addr.Is4() || !prefix.Contains(addr) {
		return netip.Prefix{}, false
	}
	// Cymru host routes do not provide any aggregation benefit. Keep the
	// explicit /32 or /128 fallback instead, matching the previous behavior.
	if prefix.Bits() >= addr.BitLen() {
		return netip.Prefix{}, false
	}
	return prefix, true
}

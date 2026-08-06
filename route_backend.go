package main

import (
	"context"
	"fmt"
	"net/netip"
)

const KernelRouteBackendName = "kernel"

// RouteIntent is the normalized route selected for one address from a DNS
// answer. Prefix may be either the host route or a broader Cymru prefix.
type RouteIntent struct {
	IP         netip.Addr
	Prefix     netip.Prefix
	ResolvedBy PrefixSource
}

// ApplyResult describes the state of one route backend after Ensure returns.
// Changed is true only when the backend can confirm that it installed a route
// which was absent immediately before the operation. Ready means the backend
// accepts the prefix as usable for traffic.
type ApplyResult struct {
	Changed bool
	Ready   bool
}

// RouteSnapshotProvider exposes the exact prefixes currently present in a
// backend snapshot. KernelRouteBackend implements it for ordered kernel+bgp
// reconciliation during startup and explicit route reloads.
type RouteSnapshotProvider interface {
	SnapshotRoutes() []RouteIntent
}

// DesiredRouteSetBackend replaces a backend's complete desired route set.
// BGPRouteBackend implements it so its table can mirror the configured kernel
// table without persistent route storage.
type DesiredRouteSetBackend interface {
	ReplaceDesired(ctx context.Context, routes []RouteIntent) error
}

// DesiredRouteSnapshotProvider exposes a process-local desired route set so a
// bgp-only backend can survive an in-process speaker reconfiguration without
// persisting dynamic prefixes to disk.
type DesiredRouteSnapshotProvider interface {
	DesiredRoutes() []RouteIntent
}

// ExactRouteBackend can require the precise prefix to exist instead of merely
// accepting coverage by a broader route. RouteManager uses this for the kernel
// side of kernel+bgp before allowing the matching BGP announcement.
type ExactRouteBackend interface {
	EnsureExact(ctx context.Context, route RouteIntent) (ApplyResult, error)
}

// RouteBackend applies one normalized route intent to a routing system. The
// address coverage check is an optional fast path: every active backend must
// report coverage before RouteManager may skip prefix resolution and Ensure.
type RouteBackend interface {
	Name() string
	CoversAddress(addr netip.Addr) bool
	Ensure(ctx context.Context, route RouteIntent) (ApplyResult, error)
	Reload(ctx context.Context) error
	SnapshotSize() int
	Close() error
}

func validateRouteIntent(route RouteIntent) (RouteIntent, error) {
	route.IP = route.IP.Unmap()
	if !route.IP.IsValid() {
		return RouteIntent{}, fmt.Errorf("invalid route address %q", route.IP)
	}
	if !route.Prefix.IsValid() {
		return RouteIntent{}, fmt.Errorf("invalid route prefix %q", route.Prefix)
	}
	route.Prefix = route.Prefix.Masked()
	if route.Prefix.Addr().Is4() != route.IP.Is4() {
		return RouteIntent{}, fmt.Errorf("route address %s and prefix %s use different address families", route.IP, route.Prefix)
	}
	if !route.Prefix.Contains(route.IP) {
		return RouteIntent{}, fmt.Errorf("route prefix %s does not contain address %s", route.Prefix, route.IP)
	}
	return route, nil
}

// prefixCovers reports whether every address in want is contained in have.
// Checking only have.Contains(want.Addr()) is insufficient: 10.0.0.0/25
// contains the network address of 10.0.0.0/24 but not the whole /24.
func prefixCovers(have, want netip.Prefix) bool {
	if !have.IsValid() || !want.IsValid() {
		return false
	}

	have = have.Masked()
	want = want.Masked()
	if have.Addr().BitLen() != want.Addr().BitLen() {
		return false
	}
	if have.Bits() > want.Bits() {
		return false
	}
	return have.Contains(want.Addr())
}

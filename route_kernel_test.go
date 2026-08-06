package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
)

func mustIPNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", cidr, err)
	}
	return network
}

func newTestKernelBackend() *KernelRouteBackend {
	cfg := &Config{RouteTable: 101}
	return &KernelRouteBackend{
		app: &App{cfg: cfg},
		cfg: cfg,
	}
}

func TestKernelBackendPrefixCoverage(t *testing.T) {
	backend := newTestKernelBackend()
	backend.snapshot = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/25")}

	if backend.coversPrefix(netip.MustParsePrefix("10.0.0.0/24")) {
		t.Fatal("10.0.0.0/25 must not cover requested 10.0.0.0/24")
	}
	if !backend.coversPrefix(netip.MustParsePrefix("10.0.0.64/26")) {
		t.Fatal("10.0.0.0/25 must cover 10.0.0.64/26")
	}
}

func TestKernelBackendCoversAddressIPv4AndIPv6(t *testing.T) {
	backend := newTestKernelBackend()
	backend.snapshot = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}

	if !backend.CoversAddress(netip.MustParseAddr("192.0.2.10")) {
		t.Fatal("IPv4 address should be covered")
	}
	if !backend.CoversAddress(netip.MustParseAddr("2001:db8::10")) {
		t.Fatal("IPv6 address should be covered")
	}
	if backend.CoversAddress(netip.MustParseAddr("198.51.100.10")) {
		t.Fatal("unrelated IPv4 address must not be covered")
	}
}

func TestKernelBackendEnsureSkipsCoveredPrefix(t *testing.T) {
	backend := newTestKernelBackend()
	backend.snapshot = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	replaces := 0
	backend.ops = kernelRouteOperations{
		listRoutes: func(int) ([]netlink.Route, error) {
			t.Fatal("covered prefix must not reload kernel routes")
			return nil, nil
		},
		replaceRoute: func(*Config, netip.Prefix) error {
			replaces++
			return nil
		},
	}

	result, err := backend.Ensure(context.Background(), RouteIntent{
		IP:     netip.MustParseAddr("192.0.2.10"),
		Prefix: netip.MustParsePrefix("192.0.2.0/24"),
	})
	if err != nil {
		t.Fatalf("Ensure returned error: %v", err)
	}
	if !result.Ready || result.Changed {
		t.Fatalf("result = %+v, want ready without change", result)
	}
	if replaces != 0 {
		t.Fatalf("replace calls = %d", replaces)
	}
}

func TestKernelBackendEnsureInstallsMissingPrefix(t *testing.T) {
	backend := newTestKernelBackend()
	var listedTable int
	var replacedPrefix netip.Prefix
	backend.ops = kernelRouteOperations{
		listRoutes: func(table int) ([]netlink.Route, error) {
			listedTable = table
			return nil, nil
		},
		replaceRoute: func(_ *Config, prefix netip.Prefix) error {
			replacedPrefix = prefix
			return nil
		},
	}

	result, err := backend.Ensure(context.Background(), RouteIntent{
		IP:         netip.MustParseAddr("192.0.2.10"),
		Prefix:     netip.MustParsePrefix("192.0.2.0/24"),
		ResolvedBy: PrefixSourceCymru,
	})
	if err != nil {
		t.Fatalf("Ensure returned error: %v", err)
	}
	if !result.Ready || !result.Changed {
		t.Fatalf("result = %+v, want confirmed change", result)
	}
	if listedTable != 101 {
		t.Fatalf("listed table = %d, want 101", listedTable)
	}
	if replacedPrefix.String() != "192.0.2.0/24" {
		t.Fatalf("replaced prefix = %s", replacedPrefix)
	}
	if !backend.coversPrefix(replacedPrefix) {
		t.Fatal("installed prefix was not added to snapshot")
	}
}

func TestKernelBackendEnsureSuppressesChangedAfterReloadFailure(t *testing.T) {
	backend := newTestKernelBackend()
	reloadErr := errors.New("netlink dump failed")
	backend.ops = kernelRouteOperations{
		listRoutes:   func(int) ([]netlink.Route, error) { return nil, reloadErr },
		replaceRoute: func(*Config, netip.Prefix) error { return nil },
	}

	result, err := backend.Ensure(context.Background(), RouteIntent{
		IP:     netip.MustParseAddr("2001:db8::10"),
		Prefix: netip.MustParsePrefix("2001:db8::/32"),
	})
	if err != nil {
		t.Fatalf("Ensure returned error: %v", err)
	}
	if !result.Ready || result.Changed {
		t.Fatalf("result = %+v, changed must be suppressed without a live precheck", result)
	}
}

func TestKernelBackendReloadUsesConfiguredTable(t *testing.T) {
	backend := newTestKernelBackend()
	backend.ops = kernelRouteOperations{
		listRoutes: func(table int) ([]netlink.Route, error) {
			if table != 101 {
				t.Fatalf("table = %d, want 101", table)
			}
			return []netlink.Route{{Dst: mustIPNet(t, "198.51.100.0/24")}}, nil
		},
	}

	if err := backend.Reload(context.Background()); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}
	if !backend.CoversAddress(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("reloaded prefix does not cover expected address")
	}
}

func TestKernelBackendEnsureExactInstallsPrefixDespiteBroaderCoverage(t *testing.T) {
	backend := newTestKernelBackend()
	backend.snapshot = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	var replaced netip.Prefix
	backend.ops = kernelRouteOperations{
		listRoutes: func(int) ([]netlink.Route, error) {
			return []netlink.Route{{Dst: mustIPNet(t, "192.0.2.0/24")}}, nil
		},
		replaceRoute: func(_ *Config, prefix netip.Prefix) error {
			replaced = prefix
			return nil
		},
	}

	requested := RouteIntent{
		IP:     netip.MustParseAddr("192.0.2.129"),
		Prefix: netip.MustParsePrefix("192.0.2.128/25"),
	}
	result, err := backend.EnsureExact(context.Background(), requested)
	if err != nil {
		t.Fatalf("EnsureExact returned error: %v", err)
	}
	if !result.Ready || !result.Changed {
		t.Fatalf("result=%+v, want exact route installation", result)
	}
	if replaced != requested.Prefix {
		t.Fatalf("replaced=%s, want %s", replaced, requested.Prefix)
	}
	if !backend.hasExactPrefix(requested.Prefix) {
		t.Fatal("exact prefix missing from snapshot")
	}
}

func TestKernelBackendSnapshotRoutesReturnsExactTablePrefixes(t *testing.T) {
	backend := newTestKernelBackend()
	backend.snapshot = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}

	routes := backend.SnapshotRoutes()
	if len(routes) != 2 {
		t.Fatalf("routes=%d, want 2", len(routes))
	}
	for i, route := range routes {
		if route.Prefix != backend.snapshot[i] {
			t.Fatalf("route[%d]=%s, want %s", i, route.Prefix, backend.snapshot[i])
		}
		if route.IP != route.Prefix.Addr() {
			t.Fatalf("route[%d] IP=%s, want network address %s", i, route.IP, route.Prefix.Addr())
		}
		if route.ResolvedBy != PrefixSourceKernel {
			t.Fatalf("route[%d] source=%q, want %q", i, route.ResolvedBy, PrefixSourceKernel)
		}
	}
}

func TestRouteGatewayForCIDRRequiresExplicitIPv4Gateway(t *testing.T) {
	gateway, ok, err := routeGatewayForCIDR(&Config{}, mustIPNet(t, "192.0.2.0/24"))
	if err == nil {
		t.Fatal("expected an error when wg_gateway_v4 is empty")
	}
	if gateway != nil || ok {
		t.Fatalf("gateway=%v ok=%t, want no gateway", gateway, ok)
	}
}

func TestRouteGatewayForCIDRUsesIPv4Gateway(t *testing.T) {
	gateway, ok, err := routeGatewayForCIDR(
		&Config{WGGatewayV4: "192.0.2.1"},
		mustIPNet(t, "198.51.100.0/24"),
	)
	if err != nil {
		t.Fatalf("routeGatewayForCIDR returned error: %v", err)
	}
	if !ok || gateway.String() != "192.0.2.1" {
		t.Fatalf("gateway=%v ok=%t, want 192.0.2.1", gateway, ok)
	}
}

func TestRouteGatewayForCIDRAllowsDirectIPv6Route(t *testing.T) {
	gateway, ok, err := routeGatewayForCIDR(&Config{}, mustIPNet(t, "2001:db8::/32"))
	if err != nil {
		t.Fatalf("routeGatewayForCIDR returned error: %v", err)
	}
	if gateway != nil || ok {
		t.Fatalf("gateway=%v ok=%t, want direct IPv6 route", gateway, ok)
	}
}

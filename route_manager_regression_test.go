package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func TestEnsureIPsAndWaitDoesNotTrustStaleAppliedCache(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := &App{ctx: ctx, cancel: cancel, cfg: &Config{RouteIPv4: true, LookupCIDR: false}}
	backend := &fakeRouteBackend{name: KernelRouteBackendName, result: ApplyResult{Ready: true}}
	rm := &RouteManager{
		app:             app,
		ctx:             ctx,
		backends:        []RouteBackend{backend},
		ipCache:         map[string]routeCacheEntry{"192.0.2.10": {State: StateApplied, CIDR: "192.0.2.10/32"}},
		cidrCache:       make(map[string]routeCacheEntry),
		resetAfterApply: make(map[string]bool),
	}
	app.routeMgr = rm

	if err := rm.EnsureIPsAndWait([]net.IP{net.ParseIP("192.0.2.10")}); err != nil {
		t.Fatalf("ensure route: %v", err)
	}
	if backend.ensures != 1 {
		t.Fatalf("backend ensure calls=%d, want 1", backend.ensures)
	}
}

func TestKernelBackendKeepsImmutableConfiguration(t *testing.T) {
	oldCfg := &Config{RouteTable: 101}
	app := &App{cfg: oldCfg}
	backend := NewKernelRouteBackendForConfig(app, oldCfg)
	var listedTable int
	backend.ops.listRoutes = func(table int) ([]netlink.Route, error) {
		listedTable = table
		return nil, nil
	}
	app.setConfig(&Config{RouteTable: 202})

	if err := backend.Reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if listedTable != 101 {
		t.Fatalf("listed table=%d, want immutable table 101", listedTable)
	}
}

func TestSameRouteBackendConfigIncludesKernelRoutingFields(t *testing.T) {
	base := &Config{
		RouteMode:   RouteModeKernel,
		RouteTable:  101,
		RouteIPv4:   true,
		RouteIPv6:   true,
		WGInterface: "wg0",
		WGGatewayV4: "192.0.2.1",
		WGGatewayV6: "2001:db8::1",
	}
	var variants []*Config
	for _, mutate := range []func(*Config){
		func(cfg *Config) { cfg.RouteTable++ },
		func(cfg *Config) { cfg.WGInterface = "wg1" },
		func(cfg *Config) { cfg.WGGatewayV4 = "192.0.2.2" },
		func(cfg *Config) { cfg.WGGatewayV6 = "2001:db8::2" },
	} {
		copyCfg := *base
		mutate(&copyCfg)
		variants = append(variants, &copyCfg)
	}
	for i, variant := range variants {
		if sameRouteBackendConfig(base, variant) {
			t.Fatalf("variant %d incorrectly considered the same", i)
		}
	}
}

func TestNewRouteManagerValidatesArguments(t *testing.T) {
	if _, err := NewRouteManager(nil, 1); err == nil {
		t.Fatal("nil app unexpectedly accepted")
	}
	app := &App{cfg: &Config{RouteMode: RouteModeKernel, RouteIPv4: true}}
	if _, err := NewRouteManager(app, 0); err == nil {
		t.Fatal("zero workers unexpectedly accepted")
	}
}

func TestRouteManagerCloseCancelsWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := &App{ctx: ctx, cancel: cancel, cfg: &Config{RouteMode: RouteModeKernel, RouteIPv4: true}}
	rm, err := NewRouteManager(app, 2)
	if err != nil {
		t.Fatalf("new route manager: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- rm.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("route manager close did not cancel workers")
	}
}

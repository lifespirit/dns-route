package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vishvananda/netlink"
)

type kernelRouteOperations struct {
	listRoutes   func(table int) ([]netlink.Route, error)
	replaceRoute func(cfg *Config, prefix netip.Prefix) error
}

type KernelRouteBackend struct {
	app *App
	ops kernelRouteOperations

	snapshotMu sync.RWMutex
	snapshot   []netip.Prefix
}

func NewKernelRouteBackend(app *App) *KernelRouteBackend {
	backend := &KernelRouteBackend{app: app}
	backend.ops = kernelRouteOperations{
		listRoutes:   listKernelRoutes,
		replaceRoute: replaceKernelRoute,
	}
	return backend
}

func (b *KernelRouteBackend) Name() string { return KernelRouteBackendName }

func (b *KernelRouteBackend) Close() error { return nil }

func (b *KernelRouteBackend) SnapshotSize() int {
	b.snapshotMu.RLock()
	defer b.snapshotMu.RUnlock()
	return len(b.snapshot)
}

func (b *KernelRouteBackend) Reload(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b == nil || b.app == nil {
		return fmt.Errorf("kernel route backend is not configured")
	}
	if b.ops.listRoutes == nil {
		return fmt.Errorf("kernel route listing is not configured")
	}

	cfg := b.app.getConfig()
	if cfg == nil {
		return fmt.Errorf("kernel route config is nil")
	}
	table := effectiveRouteTable(cfg.RouteTable)
	routes, err := b.ops.listRoutes(table)
	if err != nil {
		return fmt.Errorf("route list filtered: %w", err)
	}
	prefixes := make([]netip.Prefix, 0, len(routes))
	for _, route := range routes {
		if route.Dst == nil {
			continue
		}
		prefix, parseErr := netip.ParsePrefix(route.Dst.String())
		if parseErr != nil {
			log.Printf("ROUTE_SNAPSHOT_SKIP backend=%s dst=%q error=%v", b.Name(), route.Dst.String(), parseErr)
			continue
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	b.snapshotMu.Lock()
	b.snapshot = prefixes
	b.snapshotMu.Unlock()
	return nil
}

func (b *KernelRouteBackend) CoversAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return false
	}

	b.snapshotMu.RLock()
	defer b.snapshotMu.RUnlock()
	for _, prefix := range b.snapshot {
		if prefix.Addr().Is4() != addr.Is4() {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (b *KernelRouteBackend) coversPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return false
	}
	prefix = prefix.Masked()

	b.snapshotMu.RLock()
	defer b.snapshotMu.RUnlock()
	for _, existing := range b.snapshot {
		if prefixCovers(existing, prefix) {
			return true
		}
	}
	return false
}

func (b *KernelRouteBackend) addPrefixToSnapshot(prefix netip.Prefix) {
	if !prefix.IsValid() {
		return
	}
	prefix = prefix.Masked()

	b.snapshotMu.Lock()
	defer b.snapshotMu.Unlock()
	for _, existing := range b.snapshot {
		if existing == prefix {
			return
		}
	}
	b.snapshot = append(b.snapshot, prefix)
}

func (b *KernelRouteBackend) Ensure(ctx context.Context, route RouteIntent) (ApplyResult, error) {
	if err := ctx.Err(); err != nil {
		return ApplyResult{}, err
	}
	if b == nil || b.app == nil {
		return ApplyResult{}, fmt.Errorf("kernel route backend is not configured")
	}
	if b.ops.replaceRoute == nil {
		return ApplyResult{}, fmt.Errorf("kernel route replacement is not configured")
	}

	route, err := validateRouteIntent(route)
	if err != nil {
		return ApplyResult{}, err
	}
	if b.coversPrefix(route.Prefix) {
		return ApplyResult{Ready: true}, nil
	}

	// Refresh from the kernel immediately before RouteReplace. The in-memory
	// snapshot may not yet contain a route installed by another process. If the
	// prefix is already covered, no routing change is required and existing
	// conntrack state must be left untouched.
	routeAbsentConfirmed := false
	if reloadErr := b.Reload(ctx); reloadErr != nil {
		// Continue trying to install the route, but suppress conntrack reset:
		// without a successful live precheck we cannot prove that the route did
		// not already exist.
		log.Printf("ROUTE_PRECHECK_RELOAD_ERROR backend=%s ip=%s cidr=%s error=%v", b.Name(), route.IP, route.Prefix, reloadErr)
	} else if b.coversPrefix(route.Prefix) {
		return ApplyResult{Ready: true}, nil
	} else {
		routeAbsentConfirmed = true
	}

	cfg := b.app.getConfig()
	if err := b.ops.replaceRoute(cfg, route.Prefix); err != nil {
		atomic.AddUint64(&b.app.routeAddErrors, 1)
		reloadErr := b.Reload(ctx)
		recovered := reloadErr == nil && b.coversPrefix(route.Prefix)
		b.app.recordRouteAddError(route.IP.String(), route.Prefix.String(), err, reloadErr, recovered)
		if recovered {
			// The route appeared without a successful RouteReplace from this
			// operation. Do not disturb existing conntrack entries.
			return ApplyResult{Ready: true}, nil
		}
		return ApplyResult{}, err
	}

	atomic.AddUint64(&b.app.routeAdds, 1)
	b.addPrefixToSnapshot(route.Prefix)
	// Changed is intentionally conservative. A successful RouteReplace after a
	// failed live precheck is ready, but cannot safely trigger conntrack reset.
	return ApplyResult{Changed: routeAbsentConfirmed, Ready: true}, nil
}

func listKernelRoutes(table int) ([]netlink.Route, error) {
	filter := &netlink.Route{Table: table}
	return netlink.RouteListFiltered(netlink.FAMILY_ALL, filter, netlink.RT_FILTER_TABLE)
}

func replaceKernelRoute(cfg *Config, prefix netip.Prefix) error {
	if cfg == nil {
		return fmt.Errorf("route config is nil")
	}
	if cfg.WGInterface == "" {
		return fmt.Errorf("prepare route %s: wg_interface is empty", prefix)
	}
	if !prefix.IsValid() {
		return fmt.Errorf("invalid route prefix %q", prefix)
	}

	_, dst, err := net.ParseCIDR(prefix.Masked().String())
	if err != nil {
		return fmt.Errorf("parse route CIDR %q: %w", prefix, err)
	}
	link, err := netlink.LinkByName(cfg.WGInterface)
	if err != nil {
		return fmt.Errorf("lookup interface %q for route %s: %w", cfg.WGInterface, prefix, err)
	}
	table := effectiveRouteTable(cfg.RouteTable)
	route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Table: table}
	if gateway, ok, err := routeGatewayForCIDR(cfg, dst); err != nil {
		return fmt.Errorf("select gateway for route %s table %d dev %s: %w", prefix, table, cfg.WGInterface, err)
	} else if ok {
		route.Gw = gateway
	}
	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf(
			"netlink RouteReplace dst=%s table=%d dev=%s(index=%d) gw=%s: %w",
			prefix, table, cfg.WGInterface, link.Attrs().Index, routeGatewayString(route.Gw), err,
		)
	}
	return nil
}

func routeGatewayString(gateway net.IP) string {
	if gateway == nil {
		return "<direct>"
	}
	return gateway.String()
}

func routeGatewayForCIDR(cfg *Config, dst *net.IPNet) (net.IP, bool, error) {
	if dst.IP.To4() != nil {
		gatewayValue := strings.TrimSpace(cfg.WGGatewayV4)
		if gatewayValue == "" {
			gatewayValue = strings.TrimSpace(cfg.WGGateway)
		}
		if gatewayValue == "" {
			return nil, false, fmt.Errorf("wg_gateway_v4 or legacy wg_gateway is empty")
		}
		gateway := net.ParseIP(gatewayValue)
		if gateway == nil || gateway.To4() == nil {
			return nil, false, fmt.Errorf("gateway %q is not an IPv4 address for IPv4 route %s", gatewayValue, dst.String())
		}
		return gateway.To4(), true, nil
	}

	gatewayValue := strings.TrimSpace(cfg.WGGatewayV6)
	if gatewayValue == "" {
		gateway := net.ParseIP(strings.TrimSpace(cfg.WGGateway))
		if gateway != nil && gateway.To4() == nil {
			gatewayValue = strings.TrimSpace(cfg.WGGateway)
		}
	}
	if gatewayValue == "" {
		return nil, false, nil
	}
	gateway := net.ParseIP(gatewayValue)
	if gateway == nil || gateway.To4() != nil {
		return nil, false, fmt.Errorf("gateway %q is not an IPv6 address for IPv6 route %s", gatewayValue, dst.String())
	}
	return gateway.To16(), true, nil
}

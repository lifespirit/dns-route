package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
)

const BGPRouteBackendName = "bgp"

// BGPBackendStatus is a lock-safe runtime snapshot for the admin UI and
// Prometheus metrics. Desired prefixes are the in-memory target set; announced
// prefixes are paths currently accepted by the embedded speaker Loc-RIB.
type BGPBackendStatus struct {
	Configured         bool
	Established        bool
	Ready              bool
	RequireEstablished bool
	DesiredPrefixes    int
	AnnouncedPrefixes  int
}

// BGPSpeaker is the narrow boundary between route management and an embedded
// BGP implementation, such as an embedded GoBGP server.
type BGPSpeaker interface {
	Announce(ctx context.Context, route RouteIntent) (changed bool, err error)
	Withdraw(ctx context.Context, prefix netip.Prefix) (changed bool, err error)
	Established() bool
	Close() error
}

// BGPRouteBackend keeps only ephemeral process state. In bgp-only mode the
// desired set is rebuilt from DNS answers after every dns-route restart. In
// kernel+bgp mode RouteManager replaces this set from the configured kernel
// table during startup and every explicit route reload.
type BGPRouteBackend struct {
	speaker            BGPSpeaker
	requireEstablished bool
	ipv4               bool
	ipv6               bool

	mu        sync.RWMutex
	desired   map[netip.Prefix]RouteIntent
	announced map[netip.Prefix]struct{}
}

func NewBGPRouteBackend(speaker BGPSpeaker, requireEstablished, ipv4, ipv6 bool) (*BGPRouteBackend, error) {
	if speaker == nil {
		return nil, fmt.Errorf("BGP speaker is nil")
	}
	if !ipv4 && !ipv6 {
		return nil, fmt.Errorf("BGP backend has no enabled address family")
	}
	return &BGPRouteBackend{
		speaker:            speaker,
		requireEstablished: requireEstablished,
		ipv4:               ipv4,
		ipv6:               ipv6,
		desired:            make(map[netip.Prefix]RouteIntent),
		announced:          make(map[netip.Prefix]struct{}),
	}, nil
}

func (b *BGPRouteBackend) Name() string { return BGPRouteBackendName }

func (b *BGPRouteBackend) familyEnabled(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return false
	}
	if prefix.Addr().Is4() {
		return b.ipv4
	}
	return b.ipv6
}

func (b *BGPRouteBackend) ready() bool {
	if b == nil || b.speaker == nil {
		return false
	}
	return !b.requireEstablished || b.speaker.Established()
}

func (b *BGPRouteBackend) CoversAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !b.ready() {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	for prefix := range b.announced {
		if prefix.Addr().Is4() == addr.Is4() && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (b *BGPRouteBackend) SnapshotSize() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.announced)
}

func (b *BGPRouteBackend) Status() BGPBackendStatus {
	if b == nil || b.speaker == nil {
		return BGPBackendStatus{}
	}
	established := b.speaker.Established()
	b.mu.RLock()
	status := BGPBackendStatus{
		Configured:         true,
		Established:        established,
		Ready:              !b.requireEstablished || established,
		RequireEstablished: b.requireEstablished,
		DesiredPrefixes:    len(b.desired),
		AnnouncedPrefixes:  len(b.announced),
	}
	b.mu.RUnlock()
	return status
}

func (b *BGPRouteBackend) DesiredSize() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.desired)
}

func (b *BGPRouteBackend) DesiredRoutes() []RouteIntent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	routes := make([]RouteIntent, 0, len(b.desired))
	for _, route := range b.desired {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Prefix.String() < routes[j].Prefix.String()
	})
	return routes
}

func (b *BGPRouteBackend) rememberDesired(route RouteIntent) {
	b.mu.Lock()
	b.desired[route.Prefix] = route
	b.mu.Unlock()
}

func (b *BGPRouteBackend) markAnnounced(prefix netip.Prefix) {
	b.mu.Lock()
	b.announced[prefix.Masked()] = struct{}{}
	b.mu.Unlock()
}

func (b *BGPRouteBackend) markWithdrawn(prefix netip.Prefix) {
	b.mu.Lock()
	delete(b.announced, prefix.Masked())
	b.mu.Unlock()
}

func (b *BGPRouteBackend) Ensure(ctx context.Context, route RouteIntent) (ApplyResult, error) {
	if err := ctx.Err(); err != nil {
		return ApplyResult{}, err
	}
	if b == nil || b.speaker == nil {
		return ApplyResult{}, fmt.Errorf("BGP route backend is not configured")
	}
	route, err := validateRouteIntent(route)
	if err != nil {
		return ApplyResult{}, err
	}
	if !b.familyEnabled(route.Prefix) {
		return ApplyResult{}, fmt.Errorf("BGP address family is disabled for prefix %s", route.Prefix)
	}

	// Remember the prefix before touching the speaker. A temporary session or
	// speaker failure can then be retried from memory without SQLite.
	b.rememberDesired(route)
	changed, err := b.speaker.Announce(ctx, route)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("announce BGP prefix %s: %w", route.Prefix, err)
	}
	b.markAnnounced(route.Prefix)
	return ApplyResult{Changed: changed, Ready: b.ready()}, nil
}

// ReplaceDesired makes routes the complete desired BGP table and reconciles
// the speaker to it. RouteManager uses this only after successfully reloading
// the configured kernel table in kernel+bgp mode.
func (b *BGPRouteBackend) ReplaceDesired(ctx context.Context, routes []RouteIntent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b == nil || b.speaker == nil {
		return fmt.Errorf("BGP route backend is not configured")
	}

	desired := make(map[netip.Prefix]RouteIntent, len(routes))
	for _, route := range routes {
		route, err := validateRouteIntent(route)
		if err != nil {
			return err
		}
		if !b.familyEnabled(route.Prefix) {
			continue
		}
		desired[route.Prefix] = route
	}

	b.mu.Lock()
	b.desired = desired
	b.mu.Unlock()
	return b.Reload(ctx)
}

func (b *BGPRouteBackend) desiredAndAnnounced() ([]RouteIntent, []netip.Prefix) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	desired := make([]RouteIntent, 0, len(b.desired))
	for _, route := range b.desired {
		desired = append(desired, route)
	}
	sort.Slice(desired, func(i, j int) bool {
		return desired[i].Prefix.String() < desired[j].Prefix.String()
	})

	stale := make([]netip.Prefix, 0)
	for prefix := range b.announced {
		if _, wanted := b.desired[prefix]; !wanted {
			stale = append(stale, prefix)
		}
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].String() < stale[j].String() })
	return desired, stale
}

// Reload replays every desired prefix, so it also restores a newly-created
// speaker whose Loc-RIB is empty. Prefixes no longer present in desired are
// withdrawn after all wanted routes have been announced.
func (b *BGPRouteBackend) Reload(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b == nil || b.speaker == nil {
		return fmt.Errorf("BGP route backend is not configured")
	}

	desired, stale := b.desiredAndAnnounced()
	var errs []error
	for _, route := range desired {
		if _, err := b.speaker.Announce(ctx, route); err != nil {
			errs = append(errs, fmt.Errorf("reannounce BGP prefix %s: %w", route.Prefix, err))
			continue
		}
		b.markAnnounced(route.Prefix)
	}
	for _, prefix := range stale {
		if _, err := b.speaker.Withdraw(ctx, prefix); err != nil {
			errs = append(errs, fmt.Errorf("withdraw BGP prefix %s: %w", prefix, err))
			continue
		}
		b.markWithdrawn(prefix)
	}
	return errors.Join(errs...)
}

func (b *BGPRouteBackend) Close() error {
	if b == nil || b.speaker == nil {
		return nil
	}
	return b.speaker.Close()
}

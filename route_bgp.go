package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

const BGPRouteBackendName = "bgp"

// BGPSpeaker is the narrow boundary between route management and an embedded
// BGP implementation, such as an embedded GoBGP server.
type BGPSpeaker interface {
	Announce(ctx context.Context, route RouteIntent) (changed bool, err error)
	Established() bool
	Close() error
}

type BGPRouteBackend struct {
	store              ManagedPrefixStore
	speaker            BGPSpeaker
	requireEstablished bool
	ipv4               bool
	ipv6               bool

	snapshotMu sync.RWMutex
	snapshot   map[netip.Prefix]struct{}
}

func NewBGPRouteBackend(store ManagedPrefixStore, speaker BGPSpeaker, requireEstablished, ipv4, ipv6 bool) (*BGPRouteBackend, error) {
	if store == nil {
		return nil, fmt.Errorf("BGP managed prefix store is nil")
	}
	if speaker == nil {
		return nil, fmt.Errorf("BGP speaker is nil")
	}
	if !ipv4 && !ipv6 {
		return nil, fmt.Errorf("BGP backend has no enabled address family")
	}
	return &BGPRouteBackend{
		store:              store,
		speaker:            speaker,
		requireEstablished: requireEstablished,
		ipv4:               ipv4,
		ipv6:               ipv6,
		snapshot:           make(map[netip.Prefix]struct{}),
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

	b.snapshotMu.RLock()
	defer b.snapshotMu.RUnlock()
	for prefix := range b.snapshot {
		if prefix.Addr().Is4() == addr.Is4() && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (b *BGPRouteBackend) SnapshotSize() int {
	b.snapshotMu.RLock()
	defer b.snapshotMu.RUnlock()
	return len(b.snapshot)
}

func (b *BGPRouteBackend) addSnapshot(prefix netip.Prefix) {
	prefix = prefix.Masked()
	b.snapshotMu.Lock()
	b.snapshot[prefix] = struct{}{}
	b.snapshotMu.Unlock()
}

func (b *BGPRouteBackend) replaceSnapshot(prefixes map[netip.Prefix]struct{}) {
	b.snapshotMu.Lock()
	b.snapshot = prefixes
	b.snapshotMu.Unlock()
}

func (b *BGPRouteBackend) Ensure(ctx context.Context, route RouteIntent) (ApplyResult, error) {
	if err := ctx.Err(); err != nil {
		return ApplyResult{}, err
	}
	if b == nil || b.store == nil || b.speaker == nil {
		return ApplyResult{}, fmt.Errorf("BGP route backend is not configured")
	}
	route, err := validateRouteIntent(route)
	if err != nil {
		return ApplyResult{}, err
	}
	if !b.familyEnabled(route.Prefix) {
		return ApplyResult{}, fmt.Errorf("BGP address family is disabled for prefix %s", route.Prefix)
	}

	// Persist first. If the speaker is temporarily unavailable, the desired
	// prefix remains available for replay during Reload or after restart.
	if err := b.store.Save(ctx, route); err != nil {
		return ApplyResult{}, err
	}
	changed, err := b.speaker.Announce(ctx, route)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("announce BGP prefix %s: %w", route.Prefix, err)
	}
	b.addSnapshot(route.Prefix)
	return ApplyResult{Changed: changed, Ready: b.ready()}, nil
}

func (b *BGPRouteBackend) Reload(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b == nil || b.store == nil || b.speaker == nil {
		return fmt.Errorf("BGP route backend is not configured")
	}
	routes, err := b.store.ListEnabled(ctx)
	if err != nil {
		return err
	}

	loaded := make(map[netip.Prefix]struct{}, len(routes))
	var errs []error
	for _, route := range routes {
		route, validateErr := validateRouteIntent(route)
		if validateErr != nil {
			errs = append(errs, validateErr)
			continue
		}
		if !b.familyEnabled(route.Prefix) {
			continue
		}
		if _, announceErr := b.speaker.Announce(ctx, route); announceErr != nil {
			errs = append(errs, fmt.Errorf("reannounce BGP prefix %s: %w", route.Prefix, announceErr))
			continue
		}
		loaded[route.Prefix] = struct{}{}
	}
	b.replaceSnapshot(loaded)
	return errors.Join(errs...)
}

func (b *BGPRouteBackend) Close() error {
	if b == nil || b.speaker == nil {
		return nil
	}
	return b.speaker.Close()
}

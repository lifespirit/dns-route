package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type memoryManagedPrefixStore struct {
	routes   map[netip.Prefix]RouteIntent
	saveErr  error
	listErr  error
	saveCall int
}

func newMemoryManagedPrefixStore() *memoryManagedPrefixStore {
	return &memoryManagedPrefixStore{routes: make(map[netip.Prefix]RouteIntent)}
}

func (s *memoryManagedPrefixStore) Save(_ context.Context, route RouteIntent) error {
	s.saveCall++
	if s.saveErr != nil {
		return s.saveErr
	}
	s.routes[route.Prefix.Masked()] = route
	return nil
}

func (s *memoryManagedPrefixStore) ListEnabled(context.Context) ([]RouteIntent, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := make([]RouteIntent, 0, len(s.routes))
	for _, route := range s.routes {
		out = append(out, route)
	}
	return out, nil
}

func (s *memoryManagedPrefixStore) Disable(_ context.Context, prefix netip.Prefix) error {
	delete(s.routes, prefix.Masked())
	return nil
}

type fakeBGPSpeaker struct {
	established bool
	announceErr error
	changed     bool
	announced   []RouteIntent
	closed      bool
}

func (s *fakeBGPSpeaker) Announce(_ context.Context, route RouteIntent) (bool, error) {
	s.announced = append(s.announced, route)
	return s.changed, s.announceErr
}
func (s *fakeBGPSpeaker) Established() bool { return s.established }
func (s *fakeBGPSpeaker) Close() error {
	s.closed = true
	return nil
}

func bgpTestRoute(prefix, ip string) RouteIntent {
	return RouteIntent{
		IP:         netip.MustParseAddr(ip),
		Prefix:     netip.MustParsePrefix(prefix),
		ResolvedBy: PrefixSourceCymru,
	}
}

func TestBGPBackendEnsurePersistsAndAnnounces(t *testing.T) {
	store := newMemoryManagedPrefixStore()
	speaker := &fakeBGPSpeaker{established: true, changed: true}
	backend, err := NewBGPRouteBackend(store, speaker, true, true, true)
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	route := bgpTestRoute("192.0.2.0/24", "192.0.2.10")

	result, err := backend.Ensure(context.Background(), route)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if !result.Changed || !result.Ready {
		t.Fatalf("result = %+v", result)
	}
	if store.saveCall != 1 || len(speaker.announced) != 1 {
		t.Fatalf("save=%d announced=%d", store.saveCall, len(speaker.announced))
	}
	if !backend.CoversAddress(route.IP) {
		t.Fatal("announced prefix must cover route address")
	}
}

func TestBGPBackendPersistsBeforeAnnouncementFailure(t *testing.T) {
	announceErr := errors.New("session unavailable")
	store := newMemoryManagedPrefixStore()
	speaker := &fakeBGPSpeaker{announceErr: announceErr}
	backend, err := NewBGPRouteBackend(store, speaker, false, true, false)
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	route := bgpTestRoute("198.51.100.0/24", "198.51.100.7")

	if _, err := backend.Ensure(context.Background(), route); !errors.Is(err, announceErr) {
		t.Fatalf("ensure error = %v, want %v", err, announceErr)
	}
	if _, ok := store.routes[route.Prefix]; !ok {
		t.Fatal("desired prefix was not persisted")
	}
	if backend.SnapshotSize() != 0 {
		t.Fatalf("snapshot size = %d, want 0", backend.SnapshotSize())
	}
}

func TestBGPBackendRequireEstablishedControlsReadyAndCoverage(t *testing.T) {
	store := newMemoryManagedPrefixStore()
	speaker := &fakeBGPSpeaker{}
	backend, err := NewBGPRouteBackend(store, speaker, true, true, false)
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	route := bgpTestRoute("203.0.113.0/24", "203.0.113.20")

	result, err := backend.Ensure(context.Background(), route)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if result.Ready {
		t.Fatal("peer is not established")
	}
	if backend.CoversAddress(route.IP) {
		t.Fatal("coverage must be false while the required peer is down")
	}

	speaker.established = true
	if !backend.CoversAddress(route.IP) {
		t.Fatal("coverage must become true after the peer is established")
	}
}

func TestBGPBackendReloadReannouncesEnabledFamilies(t *testing.T) {
	store := newMemoryManagedPrefixStore()
	v4 := bgpTestRoute("192.0.2.0/24", "192.0.2.1")
	v6 := bgpTestRoute("2001:db8::/32", "2001:db8::1")
	store.routes[v4.Prefix] = v4
	store.routes[v6.Prefix] = v6
	speaker := &fakeBGPSpeaker{established: true}
	backend, err := NewBGPRouteBackend(store, speaker, false, true, false)
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}

	if err := backend.Reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(speaker.announced) != 1 || speaker.announced[0].Prefix != v4.Prefix {
		t.Fatalf("announced = %+v", speaker.announced)
	}
	if backend.SnapshotSize() != 1 {
		t.Fatalf("snapshot size = %d", backend.SnapshotSize())
	}
}

func TestNewBGPRouteBackendValidatesDependencies(t *testing.T) {
	store := newMemoryManagedPrefixStore()
	speaker := &fakeBGPSpeaker{}
	if _, err := NewBGPRouteBackend(nil, speaker, false, true, true); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := NewBGPRouteBackend(store, nil, false, true, true); err == nil {
		t.Fatal("nil speaker accepted")
	}
	if _, err := NewBGPRouteBackend(store, speaker, false, false, false); err == nil {
		t.Fatal("backend without address families accepted")
	}
}

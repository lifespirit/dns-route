package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type fakeBGPSpeaker struct {
	established bool
	announceErr error
	withdrawErr error
	changed     bool
	announced   []RouteIntent
	withdrawn   []netip.Prefix
	closed      bool
}

func (s *fakeBGPSpeaker) Announce(_ context.Context, route RouteIntent) (bool, error) {
	s.announced = append(s.announced, route)
	return s.changed, s.announceErr
}
func (s *fakeBGPSpeaker) Withdraw(_ context.Context, prefix netip.Prefix) (bool, error) {
	s.withdrawn = append(s.withdrawn, prefix.Masked())
	return s.changed, s.withdrawErr
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

func TestBGPBackendEnsureRemembersAndAnnounces(t *testing.T) {
	speaker := &fakeBGPSpeaker{established: true, changed: true}
	backend, err := NewBGPRouteBackend(speaker, true, true, true)
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
	if backend.DesiredSize() != 1 || backend.SnapshotSize() != 1 {
		t.Fatalf("desired=%d announced=%d", backend.DesiredSize(), backend.SnapshotSize())
	}
	if len(speaker.announced) != 1 {
		t.Fatalf("announced=%d", len(speaker.announced))
	}
	if !backend.CoversAddress(route.IP) {
		t.Fatal("announced prefix must cover route address")
	}
}

func TestBGPBackendKeepsFailedAnnouncementInMemory(t *testing.T) {
	announceErr := errors.New("session unavailable")
	speaker := &fakeBGPSpeaker{announceErr: announceErr}
	backend, err := NewBGPRouteBackend(speaker, false, true, false)
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	route := bgpTestRoute("198.51.100.0/24", "198.51.100.7")

	if _, err := backend.Ensure(context.Background(), route); !errors.Is(err, announceErr) {
		t.Fatalf("ensure error = %v, want %v", err, announceErr)
	}
	if backend.DesiredSize() != 1 {
		t.Fatalf("desired size = %d, want 1", backend.DesiredSize())
	}
	if backend.SnapshotSize() != 0 {
		t.Fatalf("announced size = %d, want 0", backend.SnapshotSize())
	}

	speaker.announceErr = nil
	if err := backend.Reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if backend.SnapshotSize() != 1 {
		t.Fatalf("announced size after retry = %d", backend.SnapshotSize())
	}
}

func TestBGPBackendRequireEstablishedControlsReadyAndCoverage(t *testing.T) {
	speaker := &fakeBGPSpeaker{}
	backend, err := NewBGPRouteBackend(speaker, true, true, false)
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

func TestBGPBackendReplaceDesiredMirrorsRouteSet(t *testing.T) {
	speaker := &fakeBGPSpeaker{established: true}
	backend, err := NewBGPRouteBackend(speaker, false, true, true)
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	stale := bgpTestRoute("192.0.2.0/24", "192.0.2.1")
	if _, err := backend.Ensure(context.Background(), stale); err != nil {
		t.Fatalf("seed stale: %v", err)
	}

	v4 := bgpTestRoute("198.51.100.0/24", "198.51.100.0")
	v6 := bgpTestRoute("2001:db8::/32", "2001:db8::")
	speaker.announced = nil
	if err := backend.ReplaceDesired(context.Background(), []RouteIntent{v4, v6}); err != nil {
		t.Fatalf("replace desired: %v", err)
	}

	if backend.DesiredSize() != 2 || backend.SnapshotSize() != 2 {
		t.Fatalf("desired=%d announced=%d", backend.DesiredSize(), backend.SnapshotSize())
	}
	if len(speaker.announced) != 2 {
		t.Fatalf("reannounced=%d, want 2", len(speaker.announced))
	}
	if len(speaker.withdrawn) != 1 || speaker.withdrawn[0] != stale.Prefix {
		t.Fatalf("withdrawn=%v, want %s", speaker.withdrawn, stale.Prefix)
	}
	if backend.CoversAddress(stale.IP) {
		t.Fatal("stale prefix still covered")
	}
	if !backend.CoversAddress(v4.IP) || !backend.CoversAddress(v6.IP) {
		t.Fatal("replacement prefixes not covered")
	}
}

func TestBGPBackendReplaceDesiredFiltersDisabledFamily(t *testing.T) {
	speaker := &fakeBGPSpeaker{established: true}
	backend, err := NewBGPRouteBackend(speaker, false, true, false)
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	v4 := bgpTestRoute("192.0.2.0/24", "192.0.2.0")
	v6 := bgpTestRoute("2001:db8::/32", "2001:db8::")

	if err := backend.ReplaceDesired(context.Background(), []RouteIntent{v4, v6}); err != nil {
		t.Fatalf("replace desired: %v", err)
	}
	if backend.DesiredSize() != 1 || len(speaker.announced) != 1 || speaker.announced[0].Prefix != v4.Prefix {
		t.Fatalf("desired=%d announced=%+v", backend.DesiredSize(), speaker.announced)
	}
}

func TestNewBGPRouteBackendValidatesDependencies(t *testing.T) {
	speaker := &fakeBGPSpeaker{}
	if _, err := NewBGPRouteBackend(nil, false, true, true); err == nil {
		t.Fatal("nil speaker accepted")
	}
	if _, err := NewBGPRouteBackend(speaker, false, false, false); err == nil {
		t.Fatal("backend without address families accepted")
	}
}

func TestBGPBackendStatusReportsRuntimeState(t *testing.T) {
	speaker := &fakeBGPSpeaker{established: true}
	backend, err := NewBGPRouteBackend(speaker, true, true, false)
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	route := bgpTestRoute("192.0.2.0/24", "192.0.2.10")
	if _, err := backend.Ensure(context.Background(), route); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	status := backend.Status()
	if !status.Configured || !status.Established || !status.Ready || !status.RequireEstablished {
		t.Fatalf("status = %+v", status)
	}
	if status.DesiredPrefixes != 1 || status.AnnouncedPrefixes != 1 {
		t.Fatalf("prefix counts = %+v", status)
	}
}

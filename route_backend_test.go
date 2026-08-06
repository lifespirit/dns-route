package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type fakeRouteBackend struct {
	name      string
	covered   bool
	result    ApplyResult
	ensureErr error
	reloadErr error
	ensures   int
	reloads   int
}

func (b *fakeRouteBackend) Name() string { return b.name }
func (b *fakeRouteBackend) CoversAddress(netip.Addr) bool {
	return b.covered
}
func (b *fakeRouteBackend) Ensure(context.Context, RouteIntent) (ApplyResult, error) {
	b.ensures++
	return b.result, b.ensureErr
}
func (b *fakeRouteBackend) Reload(context.Context) error {
	b.reloads++
	return b.reloadErr
}
func (b *fakeRouteBackend) SnapshotSize() int { return 1 }
func (b *fakeRouteBackend) Close() error      { return nil }

func TestValidateRouteIntent(t *testing.T) {
	valid := RouteIntent{
		IP:         netip.MustParseAddr("192.0.2.10"),
		Prefix:     netip.MustParsePrefix("192.0.2.0/24"),
		ResolvedBy: PrefixSourceCymru,
	}
	got, err := validateRouteIntent(valid)
	if err != nil {
		t.Fatalf("valid intent rejected: %v", err)
	}
	if got.Prefix.String() != "192.0.2.0/24" {
		t.Fatalf("normalized prefix = %s", got.Prefix)
	}

	tests := []RouteIntent{
		{IP: netip.MustParseAddr("192.0.2.10"), Prefix: netip.MustParsePrefix("198.51.100.0/24")},
		{IP: netip.MustParseAddr("192.0.2.10"), Prefix: netip.MustParsePrefix("2001:db8::/32")},
	}
	for _, route := range tests {
		if _, err := validateRouteIntent(route); err == nil {
			t.Fatalf("invalid intent accepted: %+v", route)
		}
	}
}

func TestBackendsCoverAddressRequiresEveryBackend(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.10")
	first := &fakeRouteBackend{name: "first", covered: true}
	second := &fakeRouteBackend{name: "second", covered: true}
	rm := &RouteManager{backends: []RouteBackend{first, second}}

	if !rm.backendsCoverAddress(addr) {
		t.Fatal("all backends cover the address")
	}
	second.covered = false
	if rm.backendsCoverAddress(addr) {
		t.Fatal("one missing backend must disable the fast path")
	}
}

func TestEnsureBackendsCollectsErrorsAndTracksKernelChange(t *testing.T) {
	backendErr := errors.New("BGP unavailable")
	kernel := &fakeRouteBackend{
		name:   KernelRouteBackendName,
		result: ApplyResult{Changed: true, Ready: true},
	}
	bgp := &fakeRouteBackend{name: "bgp", ensureErr: backendErr}
	rm := &RouteManager{backends: []RouteBackend{kernel, bgp}}

	changed, err := rm.ensureBackends(context.Background(), RouteIntent{
		IP:     netip.MustParseAddr("192.0.2.10"),
		Prefix: netip.MustParsePrefix("192.0.2.0/24"),
	})
	if !changed {
		t.Fatal("kernel change must be retained when another backend fails")
	}
	if !errors.Is(err, backendErr) {
		t.Fatalf("error = %v, want %v", err, backendErr)
	}
	if kernel.ensures != 1 || bgp.ensures != 1 {
		t.Fatalf("ensure counts: kernel=%d bgp=%d", kernel.ensures, bgp.ensures)
	}
}

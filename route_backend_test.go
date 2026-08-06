package main

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

type fakeRouteBackend struct {
	name              string
	covered           bool
	result            ApplyResult
	ensureErr         error
	exactResult       ApplyResult
	exactErr          error
	reloadErr         error
	replaceDesiredErr error
	ensures           int
	exactEnsures      int
	reloads           int
	snapshotRoutes    []RouteIntent
	replacedDesired   []RouteIntent
	events            *[]string
}

func (b *fakeRouteBackend) record(event string) {
	if b.events != nil {
		*b.events = append(*b.events, event)
	}
}

func (b *fakeRouteBackend) Name() string { return b.name }
func (b *fakeRouteBackend) CoversAddress(netip.Addr) bool {
	return b.covered
}
func (b *fakeRouteBackend) Ensure(context.Context, RouteIntent) (ApplyResult, error) {
	b.ensures++
	b.record("ensure:" + b.name)
	return b.result, b.ensureErr
}
func (b *fakeRouteBackend) EnsureExact(context.Context, RouteIntent) (ApplyResult, error) {
	b.exactEnsures++
	b.record("ensure-exact:" + b.name)
	return b.exactResult, b.exactErr
}
func (b *fakeRouteBackend) Reload(context.Context) error {
	b.reloads++
	b.record("reload:" + b.name)
	return b.reloadErr
}
func (b *fakeRouteBackend) SnapshotRoutes() []RouteIntent {
	return append([]RouteIntent(nil), b.snapshotRoutes...)
}
func (b *fakeRouteBackend) ReplaceDesired(_ context.Context, routes []RouteIntent) error {
	b.record("replace-desired:" + b.name)
	b.replacedDesired = append([]RouteIntent(nil), routes...)
	return b.replaceDesiredErr
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

func TestEnsureBackendsUsesExactKernelBeforeBGP(t *testing.T) {
	var events []string
	kernel := &fakeRouteBackend{
		name:        KernelRouteBackendName,
		exactResult: ApplyResult{Changed: true, Ready: true},
		events:      &events,
	}
	bgp := &fakeRouteBackend{
		name:   BGPRouteBackendName,
		result: ApplyResult{Ready: true},
		events: &events,
	}
	rm := &RouteManager{backends: []RouteBackend{bgp, kernel}}

	changed, err := rm.ensureBackends(context.Background(), RouteIntent{
		IP:     netip.MustParseAddr("192.0.2.10"),
		Prefix: netip.MustParsePrefix("192.0.2.0/24"),
	})
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if !changed {
		t.Fatal("kernel change not retained")
	}
	if kernel.exactEnsures != 1 || kernel.ensures != 0 || bgp.ensures != 1 {
		t.Fatalf("kernel exact=%d normal=%d bgp=%d", kernel.exactEnsures, kernel.ensures, bgp.ensures)
	}
	wantEvents := []string{"ensure-exact:kernel", "ensure:bgp"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events=%v, want %v", events, wantEvents)
	}
}

func TestEnsureBackendsNeverAnnouncesWhenKernelFails(t *testing.T) {
	kernelErr := errors.New("kernel route failed")
	kernel := &fakeRouteBackend{name: KernelRouteBackendName, exactErr: kernelErr}
	bgp := &fakeRouteBackend{name: BGPRouteBackendName, result: ApplyResult{Ready: true}}
	rm := &RouteManager{backends: []RouteBackend{kernel, bgp}}

	_, err := rm.ensureBackends(context.Background(), RouteIntent{
		IP:     netip.MustParseAddr("192.0.2.10"),
		Prefix: netip.MustParsePrefix("192.0.2.0/24"),
	})
	if !errors.Is(err, kernelErr) {
		t.Fatalf("error=%v, want %v", err, kernelErr)
	}
	if bgp.ensures != 0 {
		t.Fatalf("BGP ensure calls=%d, want 0", bgp.ensures)
	}
}

func TestEnsureBackendsRetainsKernelChangeWhenBGPFails(t *testing.T) {
	bgpErr := errors.New("BGP unavailable")
	kernel := &fakeRouteBackend{
		name:        KernelRouteBackendName,
		exactResult: ApplyResult{Changed: true, Ready: true},
	}
	bgp := &fakeRouteBackend{name: BGPRouteBackendName, ensureErr: bgpErr}
	rm := &RouteManager{backends: []RouteBackend{kernel, bgp}}

	changed, err := rm.ensureBackends(context.Background(), RouteIntent{
		IP:     netip.MustParseAddr("192.0.2.10"),
		Prefix: netip.MustParsePrefix("192.0.2.0/24"),
	})
	if !changed {
		t.Fatal("kernel change must be retained when BGP fails")
	}
	if !errors.Is(err, bgpErr) {
		t.Fatalf("error = %v, want %v", err, bgpErr)
	}
}

func TestReloadBackendsMirrorsKernelSnapshotIntoBGP(t *testing.T) {
	var events []string
	routes := []RouteIntent{{
		IP:         netip.MustParseAddr("198.51.100.0"),
		Prefix:     netip.MustParsePrefix("198.51.100.0/24"),
		ResolvedBy: PrefixSourceKernel,
	}}
	kernel := &fakeRouteBackend{
		name:           KernelRouteBackendName,
		snapshotRoutes: routes,
		events:         &events,
	}
	bgp := &fakeRouteBackend{name: BGPRouteBackendName, events: &events}
	rm := &RouteManager{backends: []RouteBackend{bgp, kernel}}

	if err := rm.ReloadBackends(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	wantEvents := []string{"reload:kernel", "replace-desired:bgp"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events=%v, want %v", events, wantEvents)
	}
	if !reflect.DeepEqual(bgp.replacedDesired, routes) {
		t.Fatalf("replaced=%+v, want %+v", bgp.replacedDesired, routes)
	}
	if bgp.reloads != 0 {
		t.Fatalf("BGP Reload called separately %d times", bgp.reloads)
	}
}

func TestReloadBackendsDoesNotUseStaleSnapshotAfterKernelFailure(t *testing.T) {
	kernelErr := errors.New("route dump failed")
	kernel := &fakeRouteBackend{name: KernelRouteBackendName, reloadErr: kernelErr}
	bgp := &fakeRouteBackend{name: BGPRouteBackendName}
	rm := &RouteManager{backends: []RouteBackend{kernel, bgp}}

	err := rm.ReloadBackends(context.Background())
	if !errors.Is(err, kernelErr) {
		t.Fatalf("error=%v, want %v", err, kernelErr)
	}
	if bgp.reloads != 0 || bgp.replacedDesired != nil {
		t.Fatalf("BGP touched after kernel failure: reloads=%d replaced=%v", bgp.reloads, bgp.replacedDesired)
	}
}

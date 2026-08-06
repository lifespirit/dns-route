package main

import (
	"context"
	"errors"
	"testing"
)

func validBGPSettings() BGPSettings {
	return BGPSettings{
		LocalASN:     65001,
		RouterID:     "192.0.2.1",
		PeerAddress:  "192.0.2.2",
		PeerASN:      65002,
		LocalAddress: "192.0.2.1",
		NextHopV4:    "192.0.2.1",
		NextHopV6:    "2001:db8::1",
		MultihopTTL:  1,
	}
}

func TestParseRouteMode(t *testing.T) {
	tests := []struct {
		input string
		want  RouteMode
	}{
		{"", RouteModeKernel},
		{" kernel ", RouteModeKernel},
		{"BGP", RouteModeBGP},
		{"kernel+BGP", RouteModeKernelBGP},
	}
	for _, tc := range tests {
		got, err := parseRouteMode(tc.input)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("parse %q = %q, want %q", tc.input, got, tc.want)
		}
	}
	if _, err := parseRouteMode("bird"); err == nil {
		t.Fatal("unsupported mode accepted")
	}
}

func TestRouteModeBackendSelection(t *testing.T) {
	if !RouteModeKernel.UsesKernel() || RouteModeKernel.UsesBGP() {
		t.Fatal("kernel mode selection is wrong")
	}
	if RouteModeBGP.UsesKernel() || !RouteModeBGP.UsesBGP() {
		t.Fatal("BGP mode selection is wrong")
	}
	if !RouteModeKernelBGP.UsesKernel() || !RouteModeKernelBGP.UsesBGP() {
		t.Fatal("kernel+BGP mode selection is wrong")
	}
}

func TestBGPSettingsValidation(t *testing.T) {
	valid := validBGPSettings()
	if err := valid.Validate(true, true); err != nil {
		t.Fatalf("valid settings rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*BGPSettings)
		ipv4   bool
		ipv6   bool
	}{
		{"no families", func(*BGPSettings) {}, false, false},
		{"local ASN", func(s *BGPSettings) { s.LocalASN = 0 }, true, false},
		{"peer ASN", func(s *BGPSettings) { s.PeerASN = 0 }, true, false},
		{"router ID", func(s *BGPSettings) { s.RouterID = "2001:db8::1" }, true, false},
		{"peer", func(s *BGPSettings) { s.PeerAddress = "not-an-ip" }, true, false},
		{"local family", func(s *BGPSettings) { s.LocalAddress = "2001:db8::2" }, true, false},
		{"multihop", func(s *BGPSettings) { s.MultihopTTL = 0 }, true, false},
		{"IPv4 next hop", func(s *BGPSettings) { s.NextHopV4 = "2001:db8::1" }, true, false},
		{"IPv6 next hop", func(s *BGPSettings) { s.NextHopV6 = "192.0.2.1" }, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			settings := valid
			tc.mutate(&settings)
			if err := settings.Validate(tc.ipv4, tc.ipv6); err == nil {
				t.Fatalf("invalid settings accepted: %+v", settings)
			}
		})
	}
}

func TestBuildRouteBackendsByMode(t *testing.T) {
	original := newConfiguredBGPSpeaker
	t.Cleanup(func() { newConfiguredBGPSpeaker = original })

	created := 0
	newConfiguredBGPSpeaker = func(_ context.Context, _ GoBGPSpeakerConfig) (BGPSpeaker, error) {
		created++
		return &fakeBGPSpeaker{established: true}, nil
	}

	for _, tc := range []struct {
		mode RouteMode
		want []string
	}{
		{RouteModeKernel, []string{KernelRouteBackendName}},
		{RouteModeBGP, []string{BGPRouteBackendName}},
		{RouteModeKernelBGP, []string{KernelRouteBackendName, BGPRouteBackendName}},
	} {
		cfg := &Config{
			RouteMode: tc.mode,
			RouteIPv4: true,
			BGP:       validBGPSettings(),
		}
		app := &App{cfg: cfg}
		backends, err := buildRouteBackends(context.Background(), app, cfg)
		if err != nil {
			t.Fatalf("mode %s: %v", tc.mode, err)
		}
		if len(backends) != len(tc.want) {
			t.Fatalf("mode %s backends=%d, want %d", tc.mode, len(backends), len(tc.want))
		}
		for i, want := range tc.want {
			if backends[i].Name() != want {
				t.Fatalf("mode %s backend[%d]=%s, want %s", tc.mode, i, backends[i].Name(), want)
			}
		}
		if err := closeRouteBackends(backends); err != nil {
			t.Fatalf("close mode %s: %v", tc.mode, err)
		}
	}
	if created != 2 {
		t.Fatalf("BGP speakers created=%d, want 2", created)
	}
}

func TestBuildRouteBackendsClosesKernelOnSpeakerFailure(t *testing.T) {
	original := newConfiguredBGPSpeaker
	t.Cleanup(func() { newConfiguredBGPSpeaker = original })
	wantErr := errors.New("speaker failed")
	newConfiguredBGPSpeaker = func(context.Context, GoBGPSpeakerConfig) (BGPSpeaker, error) {
		return nil, wantErr
	}
	cfg := &Config{RouteMode: RouteModeKernelBGP, RouteIPv4: true, BGP: validBGPSettings()}
	app := &App{cfg: cfg}
	if _, err := buildRouteBackends(context.Background(), app, cfg); !errors.Is(err, wantErr) {
		t.Fatalf("error=%v, want %v", err, wantErr)
	}
}

func TestReconfigureBGPOnlyTransfersDesiredRoutesInMemory(t *testing.T) {
	original := newConfiguredBGPSpeaker
	t.Cleanup(func() { newConfiguredBGPSpeaker = original })

	oldSpeaker := &fakeBGPSpeaker{established: true}
	oldBackend, err := NewBGPRouteBackend(oldSpeaker, false, true, false)
	if err != nil {
		t.Fatalf("old backend: %v", err)
	}
	route := bgpTestRoute("198.51.100.0/24", "198.51.100.10")
	if _, err := oldBackend.Ensure(context.Background(), route); err != nil {
		t.Fatalf("seed old backend: %v", err)
	}

	newSpeaker := &fakeBGPSpeaker{established: true}
	newConfiguredBGPSpeaker = func(context.Context, GoBGPSpeakerConfig) (BGPSpeaker, error) {
		return newSpeaker, nil
	}
	cfg := &Config{RouteMode: RouteModeBGP, RouteIPv4: true, BGP: validBGPSettings()}
	app := &App{cfg: cfg}
	rm := &RouteManager{app: app, backends: []RouteBackend{oldBackend}}

	if err := rm.ReconfigureBackends(context.Background(), cfg); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	if !oldSpeaker.closed {
		t.Fatal("old speaker was not closed")
	}
	if len(newSpeaker.announced) != 1 || newSpeaker.announced[0].Prefix != route.Prefix {
		t.Fatalf("new speaker announcements=%+v", newSpeaker.announced)
	}
	configured := backendByName(rm.backends, BGPRouteBackendName)
	bgp, ok := configured.(*BGPRouteBackend)
	if !ok {
		t.Fatalf("new BGP backend=%T", configured)
	}
	if bgp.DesiredSize() != 1 {
		t.Fatalf("new BGP desired=%d, want 1", bgp.DesiredSize())
	}
}

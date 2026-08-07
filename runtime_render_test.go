package main

import (
	"bytes"
	"context"
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSummarizeConfigCountsEffectiveRuntimeValues(t *testing.T) {
	cfg := &Config{
		ListenAddrs: []string{"127.0.0.1:53", "[::1]:53"},
		Upstreams:   []string{"1.1.1.1:53", "8.8.8.8:53"},
		ForwardZones: []ForwardZone{
			{Domain: "ru", Upstreams: []ForwardZoneUpstream{{Addr: "77.88.8.8:53"}}},
			{Domain: "lan"},
		},
		SpecialDomains: map[string]struct{}{
			"example.com":   {},
			"*.example.net": {},
			"example.org":   {},
		},
		SpecialDomainSources: []SpecialDomainSourceState{
			{ID: 1, Loaded: true},
			{ID: 2, Loaded: false},
		},
		LocalA: map[string][]LocalRecord{
			"both.example": {},
			"v4.example":   {},
		},
		LocalAAAA: map[string][]LocalRecord{
			"both.example": {},
			"v6.example":   {},
		},
		DNSRecordSources: []DNSRecordSourceState{
			{ID: 1, Loaded: true},
			{ID: 2, Loaded: true},
			{ID: 3, Loaded: false},
		},
		RouteTable: 0,
	}

	got := summarizeConfig(cfg)
	if got.ListenAddrs != 2 || got.DefaultUpstreams != 2 {
		t.Fatalf("listener/upstream summary = %+v", got)
	}
	if got.ForwardZones != 2 || got.ActiveForwardZones != 1 || got.ForwardUpstreams != 1 {
		t.Fatalf("forward summary = %+v", got)
	}
	if got.SpecialDomains != 3 || got.SpecialDomainSources != 2 || got.LoadedSpecialDomainSources != 1 {
		t.Fatalf("special-domain summary = %+v", got)
	}
	if got.LocalADomains != 2 || got.LocalAAAADomains != 2 || got.LocalDNSDomains != 3 {
		t.Fatalf("local DNS summary = %+v", got)
	}
	if got.DNSRecordSources != 3 || got.LoadedDNSRecordSources != 2 {
		t.Fatalf("DNS source summary = %+v", got)
	}
	if got.RouteTableConfigured != 0 || got.RouteTableEffective != mainRouteTable {
		t.Fatalf("route table summary = %+v", got)
	}
}

func TestAdminPageDataPopulatesRuntimeSpecialDomainCount(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "runtime.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := initDB(db); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		UpstreamProto:    make(map[string]string),
		UpstreamPriority: make(map[string]int),
		SpecialDomains: map[string]struct{}{
			"one.example":   {},
			"two.example":   {},
			"three.example": {},
		},
		LocalA:       make(map[string][]LocalRecord),
		LocalAAAA:    make(map[string][]LocalRecord),
		RouteMode:    RouteModeKernel,
		RouteIPv4:    true,
		RouteIPv6:    true,
		DefaultTTL:   60,
		RouteTable:   0,
		ForwardZones: nil,
	}
	app := &App{
		db:               db,
		cfg:              cfg,
		servers:          make(map[string]*managedListener),
		pendingListeners: make(map[string]*pendingListener),
	}

	data, err := app.adminPageData("Runtime", "/")
	if err != nil {
		t.Fatal(err)
	}
	if data.Runtime.SpecialDomains != 3 {
		t.Fatalf("runtime special domains = %d, want 3", data.Runtime.SpecialDomains)
	}
	if data.Runtime.RouteTableEffective != mainRouteTable {
		t.Fatalf("effective route table = %d, want %d", data.Runtime.RouteTableEffective, mainRouteTable)
	}

	var out bytes.Buffer
	if err := templates.ExecuteTemplate(&out, "admin.html.tmpl", data); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, want := range []string{
		"<tr><td>Special domains</td><td>3</td></tr>",
		"<tr><td>Route table</td><td>254 <small>(configured: 0)</small></td></tr>",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("runtime HTML missing %q", want)
		}
	}
}

func TestSettingsTemplateRendersEffectiveDefaultTTL(t *testing.T) {
	data := pageData{
		Title:    "Settings",
		Path:     "/settings",
		Config:   &Config{DefaultTTL: 60, RouteMode: RouteModeKernel},
		Settings: map[string]string{},
	}
	var out bytes.Buffer
	if err := templates.ExecuteTemplate(&out, "settings.html.tmpl", data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `name="local_record_ttl" value="60"`) {
		t.Fatalf("settings HTML does not render effective default TTL: %s", out.String())
	}
}

func TestStatsSnapshotUsesSharedConfigurationSummary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := &Config{
		RouteMode:  RouteModeKernelBGP,
		RouteTable: 0,
		RouteIPv4:  true,
		SpecialDomains: map[string]struct{}{
			"one.example": {},
			"two.example": {},
		},
		LocalA: map[string][]LocalRecord{"same.example": {}},
		LocalAAAA: map[string][]LocalRecord{
			"same.example":  {},
			"other.example": {},
		},
		ForwardZones: []ForwardZone{
			{Domain: "active.example", Upstreams: []ForwardZoneUpstream{{Addr: "192.0.2.53:53"}}},
			{Domain: "empty.example"},
		},
		UpstreamProto:    make(map[string]string),
		UpstreamPriority: make(map[string]int),
	}
	app := &App{
		ctx:                ctx,
		cancel:             cancel,
		cfg:                cfg,
		cache:              make(map[string]cacheEntry),
		servers:            make(map[string]*managedListener),
		pendingListeners:   make(map[string]*pendingListener),
		upstreamCircuits:   make(map[string]*upstreamCircuit),
		forwardPolicyStats: make(map[string]*forwardPolicyCounter),
		startedAt:          time.Now(),
	}
	app.routeMgr = &RouteManager{
		app:       app,
		backends:  []RouteBackend{&fakeRouteBackend{name: KernelRouteBackendName}, &fakeRouteBackend{name: BGPRouteBackendName}},
		ipCache:   make(map[string]routeCacheEntry),
		cidrCache: make(map[string]routeCacheEntry),
	}

	stats := app.statsSnapshot()
	if stats.SpecialDomains != 2 || stats.LocalDNSDomains != 2 {
		t.Fatalf("configuration counts = %+v", stats)
	}
	if stats.ForwardZones != 2 || stats.ActiveForwardZones != 1 || stats.ForwardUpstreams != 1 {
		t.Fatalf("forward counts = %+v", stats)
	}
	if stats.RouteTable != mainRouteTable || stats.RouteTableConfigured != 0 {
		t.Fatalf("route table values = effective %d configured %d", stats.RouteTable, stats.RouteTableConfigured)
	}
	if stats.RouteSnapshot != 2 || stats.KernelRouteSnapshot != 1 {
		t.Fatalf("snapshot values = total %d kernel %d", stats.RouteSnapshot, stats.KernelRouteSnapshot)
	}

	recorder := httptest.NewRecorder()
	app.handleMetrics(recorder, nil)
	metrics := recorder.Body.String()
	for _, want := range []string{
		"dns_route_special_domains 2\n",
		"dns_route_active_forward_zones 1\n",
		"dns_route_local_dns_domains 2\n",
		"dns_route_route_table 254\n",
		"dns_route_route_table_configured 0\n",
		"dns_route_route_snapshot_entries 2\n",
		"dns_route_kernel_route_snapshot_entries 1\n",
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("metrics missing %q:\n%s", want, metrics)
		}
	}
}

func TestStatsTemplateHidesDisabledBGPDetails(t *testing.T) {
	data := statsData{Title: "Statistics", Path: "/statistics", BGP: bgpStatusView{State: "disabled"}}
	var out bytes.Buffer
	if err := templates.ExecuteTemplate(&out, "stats.html.tmpl", data); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	if strings.Contains(html, "AS0") || strings.Contains(html, "Desired prefixes") {
		t.Fatalf("disabled BGP details leaked into statistics page: %s", html)
	}
}

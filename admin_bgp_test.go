package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSettingsTemplateRendersBGPSettingsWithoutSecret(t *testing.T) {
	cfg := &Config{
		RouteMode:  RouteModeKernelBGP,
		RouteTable: 101,
		RouteIPv4:  true,
		RouteIPv6:  true,
		BGP: BGPSettings{
			LocalASN:           65001,
			RouterID:           "192.0.2.1",
			PeerAddress:        "192.0.2.2",
			PeerASN:            65002,
			LocalAddress:       "192.0.2.1",
			NextHopV4:          "192.0.2.1",
			NextHopV6:          "2001:db8::1",
			Password:           "must-not-be-rendered",
			MultihopTTL:        2,
			RequireEstablished: true,
		},
	}
	data := pageData{
		Title:    "Settings",
		Path:     "/settings",
		Config:   cfg,
		Settings: map[string]string{},
		BGP: bgpStatusView{
			Enabled:            true,
			Configured:         true,
			State:              "established",
			Established:        true,
			Ready:              true,
			DesiredPrefixes:    2,
			AnnouncedPrefixes:  2,
			PasswordConfigured: true,
		},
	}
	var out bytes.Buffer
	if err := templates.ExecuteTemplate(&out, "settings.html.tmpl", data); err != nil {
		t.Fatalf("render settings: %v", err)
	}
	html := out.String()
	for _, want := range []string{
		`value="kernel+bgp" selected`,
		`name="bgp_local_asn" value="65001"`,
		`name="bgp_peer_address" value="192.0.2.2"`,
		`configured — blank keeps current`,
		`href="/settings" class="active"`,
		`name="return" value="/settings"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("settings HTML missing %q", want)
		}
	}
	if strings.Contains(html, cfg.BGP.Password) {
		t.Fatal("BGP password leaked into settings HTML")
	}
	if strings.Contains(html, `name="wg_gateway"`) {
		t.Fatal("legacy wg_gateway field is still rendered")
	}
}

func TestRuntimeTemplateContainsOnlyRuntimeContent(t *testing.T) {
	data := pageData{
		Title:  "Runtime",
		Path:   "/",
		Config: &Config{RouteMode: RouteModeKernelBGP},
		BGP: bgpStatusView{
			Enabled:           true,
			State:             "established",
			PeerAddress:       "192.0.2.2",
			PeerASN:           65002,
			DesiredPrefixes:   2,
			AnnouncedPrefixes: 2,
		},
	}
	var out bytes.Buffer
	if err := templates.ExecuteTemplate(&out, "admin.html.tmpl", data); err != nil {
		t.Fatalf("render runtime: %v", err)
	}
	html := out.String()
	for _, want := range []string{
		`<h2>Runtime</h2>`,
		`Loc-RIB: 2`,
		`href="/" class="active"`,
		`action="/reload"`,
		`action="/routes/reload"`,
		`href="/statistics"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("runtime HTML missing %q", want)
		}
	}
	for _, unwanted := range []string{
		`<h2>Global settings</h2>`,
		`<td>WG gateway</td>`,
		`action="/settings/save"`,
		`<h2>Conditional forwarding</h2>`,
		`action="/record/add"`,
	} {
		if strings.Contains(html, unwanted) {
			t.Fatalf("runtime HTML unexpectedly contains %q", unwanted)
		}
	}
}

func TestAdminSectionTemplatesRender(t *testing.T) {
	data := pageData{
		Config:   &Config{},
		Settings: map[string]string{},
	}
	cases := []struct {
		template string
		title    string
		path     string
		want     string
	}{
		{template: "settings.html.tmpl", title: "Settings", path: "/settings", want: "Global settings"},
		{template: "upstreams.html.tmpl", title: "Upstreams", path: "/upstreams", want: "Conditional forwarding"},
		{template: "special_domains.html.tmpl", title: "Special domains", path: "/special-domains", want: "Add special domain"},
		{template: "dns_records.html.tmpl", title: "DNS records", path: "/dns-records", want: "Add record"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			data.Title = tc.title
			data.Path = tc.path
			var out bytes.Buffer
			if err := templates.ExecuteTemplate(&out, tc.template, data); err != nil {
				t.Fatalf("render %s: %v", tc.template, err)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("%s missing %q", tc.template, tc.want)
			}
		})
	}
}

func TestStatsTemplateRendersBGPStatus(t *testing.T) {
	var out bytes.Buffer
	data := statsData{
		Title:     "Statistics",
		Path:      "/statistics",
		Message:   "127.0.0.1:8080",
		RouteMode: string(RouteModeBGP),
		BGP: bgpStatusView{
			Enabled:           true,
			State:             "down",
			PeerAddress:       "192.0.2.2",
			PeerASN:           65002,
			DesiredPrefixes:   3,
			AnnouncedPrefixes: 3,
		},
	}
	if err := templates.ExecuteTemplate(&out, "stats.html.tmpl", data); err != nil {
		t.Fatalf("render stats: %v", err)
	}
	html := out.String()
	for _, want := range []string{
		"Route mode",
		"bgp",
		"192.0.2.2 AS65002",
		"Desired prefixes",
		">3<",
		"HTTP panel: 127.0.0.1:8080",
		`action="/reload"`,
		`action="/routes/reload"`,
		`name="return" value="/statistics"`,
		`href="/statistics"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("stats HTML missing %q", want)
		}
	}
	headerEnd := strings.Index(html, `</header>`)
	if headerEnd < 0 {
		t.Fatal("statistics HTML is missing the shared header")
	}
	footerIndex := strings.Index(html, `<footer class="site-footer">`)
	if footerIndex < 0 {
		t.Fatal("statistics HTML is missing the shared footer")
	}
	for _, action := range []string{`action="/reload"`, `action="/routes/reload"`, `href="/statistics" class="active">Statistics</a>`} {
		index := strings.Index(html, action)
		if index < 0 || index > headerEnd {
			t.Fatalf("%q is not located in the header", action)
		}
		if index > footerIndex {
			t.Fatalf("%q unexpectedly appears in the footer", action)
		}
	}
	for _, footerItem := range []string{`href="/metrics"`, `href="/routes/errors"`, `action="/record/sources/refresh"`} {
		if index := strings.Index(html, footerItem); index < footerIndex {
			t.Fatalf("%q is not located in the footer", footerItem)
		}
	}
	for _, unwanted := range []string{
		"dns-route statistics</h1>",
		"Back to admin",
		`href="/stats"`,
	} {
		if strings.Contains(html, unwanted) {
			t.Fatalf("stats HTML unexpectedly contains %q", unwanted)
		}
	}
}

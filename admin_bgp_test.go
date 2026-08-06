package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestAdminTemplateRendersBGPSettingsWithoutSecret(t *testing.T) {
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
	if err := templates.ExecuteTemplate(&out, "admin.html.tmpl", data); err != nil {
		t.Fatalf("render admin: %v", err)
	}
	html := out.String()
	for _, want := range []string{
		`value="kernel+bgp" selected`,
		`name="bgp_local_asn" value="65001"`,
		`name="bgp_peer_address" value="192.0.2.2"`,
		`configured — blank keeps current`,
		`Loc-RIB: 2`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("admin HTML missing %q", want)
		}
	}
	if strings.Contains(html, cfg.BGP.Password) {
		t.Fatal("BGP password leaked into admin HTML")
	}
}

func TestStatsTemplateRendersBGPStatus(t *testing.T) {
	var out bytes.Buffer
	data := statsData{
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
	for _, want := range []string{"Route mode", "bgp", "192.0.2.2 AS65002", "Desired prefixes", ">3<"} {
		if !strings.Contains(html, want) {
			t.Fatalf("stats HTML missing %q", want)
		}
	}
}

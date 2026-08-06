package main

import (
	"crypto/tls"
	"database/sql"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOrderedUpstreamTargetsPreservesPriorityGroups(t *testing.T) {
	input := []upstreamTarget{
		{Addr: "late", Priority: 100},
		{Addr: "early-a", Priority: 10},
		{Addr: "early-b", Priority: 10},
		{Addr: "middle", Priority: 50},
	}
	got := orderedUpstreamTargets(input)
	priorities := make([]int, len(got))
	addresses := make([]string, len(got))
	for i, target := range got {
		priorities[i] = target.Priority
		addresses[i] = target.Addr
	}
	if !reflect.DeepEqual(priorities, []int{10, 10, 50, 100}) {
		t.Fatalf("priorities=%v", priorities)
	}
	seen := map[string]bool{}
	for _, address := range addresses {
		seen[address] = true
	}
	for _, target := range input {
		if !seen[target.Addr] {
			t.Fatalf("target %q lost during ordering", target.Addr)
		}
	}
}

func TestDoHClientVerifiesTLSCertificates(t *testing.T) {
	client := newDoHClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport=%T", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLS config is nil")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("DoH TLS certificate verification is disabled")
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("minimum TLS version=%d", transport.TLSClientConfig.MinVersion)
	}
}

func TestDoTTLSConfigVerifiesEndpointHost(t *testing.T) {
	for _, tt := range []struct {
		endpoint string
		wantHost string
	}{
		{endpoint: "dns.example:853", wantHost: "dns.example"},
		{endpoint: "[2001:db8::53]:853", wantHost: "2001:db8::53"},
	} {
		cfg, err := dotTLSConfig(tt.endpoint)
		if err != nil {
			t.Fatalf("dotTLSConfig(%q): %v", tt.endpoint, err)
		}
		if cfg.InsecureSkipVerify {
			t.Fatalf("DoT TLS verification disabled for %q", tt.endpoint)
		}
		if cfg.ServerName != tt.wantHost {
			t.Fatalf("ServerName=%q, want %q", cfg.ServerName, tt.wantHost)
		}
		if cfg.MinVersion < tls.VersionTLS12 {
			t.Fatalf("minimum TLS version=%d", cfg.MinVersion)
		}
	}
	if _, err := dotTLSConfig("missing-port"); err == nil {
		t.Fatal("invalid DoT endpoint unexpectedly accepted")
	}
}

func TestLoadConfigPreservesDefaultUpstreamPriority(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "priority.db")
	db, err := sql.Open("sqlite", sqliteDSN(dbPath))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := initDB(db); err != nil {
		t.Fatalf("init db: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO upstreams(addr, proto, enabled, priority) VALUES
		('192.0.2.100:53', 'udp', 1, 100),
		('192.0.2.10:53', 'udp', 1, 10)`); err != nil {
		t.Fatalf("seed upstreams: %v", err)
	}
	cfg, err := loadConfigFromDBWithCachedSources(db, nil, nil)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	targets := defaultUpstreamTargets(cfg)
	if len(targets) != 2 {
		t.Fatalf("targets=%d, want 2", len(targets))
	}
	if targets[0].Addr != "192.0.2.10:53" || targets[0].Priority != 10 {
		t.Fatalf("first target=%+v", targets[0])
	}
	if targets[1].Addr != "192.0.2.100:53" || targets[1].Priority != 100 {
		t.Fatalf("second target=%+v", targets[1])
	}
}

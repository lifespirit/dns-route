package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseSpecialDomainsCSV(t *testing.T) {
	parsed, err := parseSpecialDomainsCSV(strings.NewReader(strings.Join([]string{
		"\ufeffdomain",
		"",
		"# comment",
		"; another comment",
		"example.com",
		"*.yandex.ru",
		"trailing.example,",
		"EXAMPLE.COM.",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"*.yandex.ru", "example.com", "trailing.example"}
	if len(parsed.Patterns) != len(want) {
		t.Fatalf("patterns = %#v", parsed.Patterns)
	}
	for i := range want {
		if parsed.Patterns[i] != want[i] {
			t.Fatalf("patterns[%d] = %q, want %q", i, parsed.Patterns[i], want[i])
		}
	}
}

func TestParseSpecialDomainsCSVRejectsExtraColumn(t *testing.T) {
	if _, err := parseSpecialDomainsCSV(strings.NewReader("example.com,unexpected\n")); err == nil {
		t.Fatal("expected extra-column error")
	}
}

func TestSpecialDomainMatcher(t *testing.T) {
	matcher := newSpecialDomainMatcher()
	matcher.Add("example.com")
	matcher.Add("*.yandex.ru")

	for _, name := range []string{"example.com", "www.example.com", "deep.www.example.com", "maps.yandex.ru", "deep.maps.yandex.ru"} {
		if !matcher.Match(name) {
			t.Errorf("expected %q to match", name)
		}
	}
	for _, name := range []string{"yandex.ru", "notexample.com", "example.net"} {
		if matcher.Match(name) {
			t.Errorf("did not expect %q to match", name)
		}
	}
}

func TestSpecialDomainImportExport(t *testing.T) {
	db := openDNSRecordTestDB(t)
	parsed, err := parseSpecialDomainsCSV(strings.NewReader("example.com\n*.yandex.ru\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := importSpecialDomains(db, parsed); err != nil {
		t.Fatal(err)
	}
	// A duplicate import must be an idempotent enable/upsert.
	if err := importSpecialDomains(db, parsed); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM special_domains`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("rows = %d, want 2", count)
	}
	var out bytes.Buffer
	if err := exportSpecialDomainsCSV(db, &out); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "*.yandex.ru\nexample.com\n"; got != want {
		t.Fatalf("export = %q, want %q", got, want)
	}
}

func TestSpecialDomainSourceSnapshot(t *testing.T) {
	db := openDNSRecordTestDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("source.example\n*.source.test\n"))
	}))
	defer server.Close()
	if _, err := db.Exec(`INSERT INTO special_domain_sources(location, enabled) VALUES(?, 1)`, server.URL); err != nil {
		t.Fatal(err)
	}

	snapshots, err := fetchSpecialDomainSources(context.Background(), db, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 1 || len(snapshots[0].Patterns) != 2 {
		t.Fatalf("snapshots = %#v", snapshots)
	}
	cfg := &Config{SpecialDomains: make(map[string]struct{}), SpecialDomainMatcher: newSpecialDomainMatcher()}
	if err := applySpecialDomainSources(db, cfg, snapshots); err != nil {
		t.Fatal(err)
	}
	if len(cfg.SpecialDomainSources) != 1 || !cfg.SpecialDomainSources[0].Loaded {
		t.Fatalf("source states = %#v", cfg.SpecialDomainSources)
	}
	if !cfg.SpecialDomainMatcher.Match("source.example") || !cfg.SpecialDomainMatcher.Match("www.source.example") {
		t.Fatal("exact source pattern did not preserve suffix matching")
	}
	if !cfg.SpecialDomainMatcher.Match("www.source.test") || cfg.SpecialDomainMatcher.Match("source.test") {
		t.Fatal("wildcard source pattern has incorrect apex semantics")
	}
}

func TestSpecialDomainSourcePendingWhenLocationChanges(t *testing.T) {
	db := openDNSRecordTestDB(t)
	if _, err := db.Exec(`INSERT INTO special_domain_sources(location, enabled) VALUES('new.csv', 1)`); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{SpecialDomains: make(map[string]struct{}), SpecialDomainMatcher: newSpecialDomainMatcher()}
	snapshots := []SpecialDomainSourceSnapshot{{
		State:    SpecialDomainSourceState{ID: 1, Location: "old.csv", Loaded: true, Patterns: 1},
		Patterns: []string{"old.example"},
	}}
	if err := applySpecialDomainSources(db, cfg, snapshots); err != nil {
		t.Fatal(err)
	}
	if len(cfg.SpecialDomainSources) != 1 || cfg.SpecialDomainSources[0].Loaded {
		t.Fatalf("states = %#v", cfg.SpecialDomainSources)
	}
	if cfg.SpecialDomainMatcher.Match("old.example") {
		t.Fatal("stale snapshot was applied")
	}
}

func TestCachedSpecialDomainSourceSurvivesConfigReload(t *testing.T) {
	db := openDNSRecordTestDB(t)
	if _, err := db.Exec(`INSERT INTO special_domain_sources(location, enabled) VALUES('cached.csv', 1)`); err != nil {
		t.Fatal(err)
	}
	snapshots := []SpecialDomainSourceSnapshot{{
		State:    SpecialDomainSourceState{ID: 1, Location: "cached.csv", Kind: "file", Loaded: true, Patterns: 1},
		Patterns: []string{"*.cached.example"},
	}}
	cfg, err := loadConfigFromDBWithCachedSources(db, nil, snapshots)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SpecialDomainMatcher.Match("www.cached.example") {
		t.Fatal("cached source pattern was not applied")
	}
	if cfg.SpecialDomainMatcher.Match("cached.example") {
		t.Fatal("wildcard unexpectedly matched apex")
	}
	if len(cfg.SpecialDomainSources) != 1 || !cfg.SpecialDomainSources[0].Loaded {
		t.Fatalf("states = %#v", cfg.SpecialDomainSources)
	}
}

func TestExternalSourceLoadFailsBeforeConfigActivation(t *testing.T) {
	db := openDNSRecordTestDB(t)
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("good.example\n"))
	}))
	defer good.Close()
	if _, err := db.Exec(`INSERT INTO dns_record_sources(location, no_data_only, enabled) VALUES(?, 1, 1)`, good.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO special_domain_sources(location, enabled) VALUES('http://127.0.0.1:1/unavailable', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigFromDBWithExternalSources(db, nil, nil, true); err == nil {
		t.Fatal("expected source reload failure")
	}
}

func TestAppIsSpecialUsesCompiledMatcher(t *testing.T) {
	matcher := newSpecialDomainMatcher()
	matcher.Add("route.example")
	matcher.Add("*.wild.example")
	app := &App{cfg: &Config{SpecialDomainMatcher: matcher}}
	if !app.isSpecial("cdn.route.example") {
		t.Fatal("exact suffix was not routed")
	}
	if !app.isSpecial("cdn.wild.example") {
		t.Fatal("wildcard subdomain was not routed")
	}
	if app.isSpecial("wild.example") {
		t.Fatal("wildcard apex was routed")
	}
}

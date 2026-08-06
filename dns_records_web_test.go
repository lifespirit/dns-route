package main

import (
	"fmt"
	"net"
	"sort"
	"testing"
)

func TestDNSRecordWebIndexPaginatesByDomain(t *testing.T) {
	idx := newDNSRecordWebIndex()
	source := DNSRecordWebSource{
		State: DNSRecordSourceState{ID: 1, Location: "source.csv", Kind: "file"},
	}
	for i := 0; i < 45; i++ {
		name := fmt.Sprintf("host-%02d.example", i)
		idx.addDomain(name)
		source.Rules = append(source.Rules, DNSRecordWebRule{Name: name, Set: DNSRecordRuleSet{ASet: true, A: dnsRecordNoData}})
	}
	sort.Slice(source.Rules, func(i, j int) bool { return source.Rules[i].Name < source.Rules[j].Name })
	idx.Sources = append(idx.Sources, source)
	idx.finalize()

	page := idx.page("", 2, 60)
	if page.TotalDomains != 45 || page.TotalPages != 3 || page.Page != 2 {
		t.Fatalf("page metadata = %#v", page)
	}
	if len(page.Domains) != 20 {
		t.Fatalf("page domain count = %d", len(page.Domains))
	}
	if page.Domains[0].Name != "host-20.example" || page.Domains[19].Name != "host-39.example" {
		t.Fatalf("page bounds = %q..%q", page.Domains[0].Name, page.Domains[19].Name)
	}
	if !page.HasPrev || !page.HasNext {
		t.Fatalf("pagination flags = prev:%t next:%t", page.HasPrev, page.HasNext)
	}
}

func TestDNSRecordWebIndexSearchesSubstringAndRegexp(t *testing.T) {
	idx := newDNSRecordWebIndex()
	for _, name := range []string{"ads.example", "api.example", "tracker.example", "ads.internal"} {
		idx.addDomain(name)
	}
	idx.finalize()

	substring := idx.page("ADS", 1, 60)
	if substring.TotalDomains != 2 {
		t.Fatalf("substring matches = %d", substring.TotalDomains)
	}
	regexpPage := idx.page(`/^(ads|api)\.example$/`, 1, 60)
	if regexpPage.TotalDomains != 2 {
		t.Fatalf("regexp matches = %d", regexpPage.TotalDomains)
	}
	invalid := idx.page(`/[/`, 1, 60)
	if invalid.SearchError == "" {
		t.Fatal("invalid regexp was accepted")
	}
}

func TestDNSRecordWebIndexBuildsStatusesOnlyForSelectedDomain(t *testing.T) {
	idx := newDNSRecordWebIndex()
	idx.addDomain("same.lan")
	idx.Sources = []DNSRecordWebSource{
		{
			State: DNSRecordSourceState{ID: 1, Location: "first.csv", Kind: "file"},
			Rules: []DNSRecordWebRule{{
				Name: "same.lan",
				Set:  DNSRecordRuleSet{ASet: true, A: []LocalRecord{{IP: net.ParseIP("192.0.2.1").To4(), TTL: 60}}},
			}},
		},
		{
			State: DNSRecordSourceState{ID: 2, Location: "second.csv", Kind: "file"},
			Rules: []DNSRecordWebRule{{
				Name: "same.lan",
				Set: DNSRecordRuleSet{
					ASet:    true,
					A:       []LocalRecord{{IP: net.ParseIP("192.0.2.2").To4(), TTL: 60}},
					AAAASet: true,
					AAAA:    dnsRecordNoData,
				},
			}},
		},
	}
	idx.Persistent["same.lan"] = []DNSRecordState{{
		ID: 1, Name: "same.lan", Type: "A", Value: "192.0.2.10", TTL: 60,
		Source: "Database", SourceKind: "database", Status: "active", Persistent: true,
	}}
	idx.finalize()

	records := idx.recordsForDomain("same.lan", 60)
	statuses := make(map[string]string)
	for _, record := range records {
		statuses[record.Source+"|"+record.Type+"|"+record.Value] = record.Status
	}
	if got := statuses["Database|A|192.0.2.10"]; got != "active" {
		t.Fatalf("database A status = %q", got)
	}
	if got := statuses["first.csv|A|192.0.2.1"]; got != "overridden" {
		t.Fatalf("first source A status = %q", got)
	}
	if got := statuses["second.csv|A|192.0.2.2"]; got != "overridden" {
		t.Fatalf("second source A status = %q", got)
	}
	if got := statuses["second.csv|AAAA|"]; got != "active" {
		t.Fatalf("source AAAA status = %q", got)
	}
}

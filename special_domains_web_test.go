package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestLoadSpecialDomainPage(t *testing.T) {
	db := openDNSRecordTestDB(t)
	for i := 0; i < 45; i++ {
		pattern := fmt.Sprintf("domain-%02d.example", i)
		if _, err := db.Exec(`INSERT INTO special_domains(domain, enabled) VALUES(?, 1)`, pattern); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO special_domains(domain, enabled) VALUES('disabled.example', 0)`); err != nil {
		t.Fatal(err)
	}

	page, err := loadSpecialDomainPage(db, 2)
	if err != nil {
		t.Fatal(err)
	}
	if page.Page != 2 || page.TotalPages != 3 || page.TotalDomains != 45 {
		t.Fatalf("pagination = page %d/%d, domains=%d", page.Page, page.TotalPages, page.TotalDomains)
	}
	if len(page.Patterns) != specialDomainPageSize {
		t.Fatalf("patterns = %d, want %d", len(page.Patterns), specialDomainPageSize)
	}
	if page.Patterns[0] != "domain-20.example" || page.Patterns[19] != "domain-39.example" {
		t.Fatalf("unexpected page patterns: first=%q last=%q", page.Patterns[0], page.Patterns[19])
	}
	if !page.HasPrev || !page.HasNext || page.PrevURL != "/special-domains" || page.NextURL != "/special-domains?page=3" {
		t.Fatalf("navigation = %#v", page)
	}
	if page.ReturnURL != "/special-domains?page=2" {
		t.Fatalf("return URL = %q", page.ReturnURL)
	}

	last, err := loadSpecialDomainPage(db, 99)
	if err != nil {
		t.Fatal(err)
	}
	if last.Page != 3 || len(last.Patterns) != 5 || !last.HasPrev || last.HasNext {
		t.Fatalf("last page = %#v", last)
	}
}

func TestSpecialDomainsTemplatePaginatesPersistentRows(t *testing.T) {
	data := pageData{
		Title:               "Special domains",
		Path:                "/special-domains",
		Config:              &Config{},
		Message:             "127.0.0.1:8080",
		SpecialDomains:      []string{"domain-20.example", "domain-21.example"},
		SpecialPage:         2,
		SpecialTotalPages:   3,
		SpecialTotalDomains: 45,
		SpecialHasPrev:      true,
		SpecialHasNext:      true,
		SpecialPrevURL:      "/special-domains",
		SpecialNextURL:      "/special-domains?page=3",
		SpecialReturnURL:    "/special-domains?page=2",
	}
	var out strings.Builder
	if err := templates.ExecuteTemplate(&out, "special_domains.html.tmpl", data); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, expected := range []string{
		`45 domains · page 2 of 3`,
		`href="/special-domains?page=3"`,
		`domain-20.example`,
		`domain-21.example`,
		`value="/special-domains?page=2"`,
	} {
		if !strings.Contains(html, expected) {
			t.Fatalf("rendered page does not contain %q", expected)
		}
	}
}

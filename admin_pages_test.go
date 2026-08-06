package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminReturnPath(t *testing.T) {
	for _, tc := range []struct {
		name     string
		form     string
		fallback string
		want     string
	}{
		{name: "known page", form: "return=%2Fupstreams", fallback: "/", want: "/upstreams"},
		{name: "page query", form: "return=%2Fdns-records%3Fq%3Dads%26page%3D2", fallback: "/", want: "/dns-records?q=ads&page=2"},
		{name: "statistics page", form: "return=%2Fstatistics", fallback: "/", want: "/statistics"},
		{name: "missing", form: "", fallback: "/settings", want: "/settings"},
		{name: "external URL rejected", form: "return=https%3A%2F%2Fexample.com", fallback: "/", want: "/"},
		{name: "unknown local path rejected", form: "return=%2Fadmin", fallback: "/dns-records", want: "/dns-records"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/action", nil)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.form != "" {
				req = httptest.NewRequest("POST", "/action", strings.NewReader(tc.form))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			if got := adminReturnPath(req, tc.fallback); got != tc.want {
				t.Fatalf("adminReturnPath()=%q want %q", got, tc.want)
			}
		})
	}
}

func TestLegacyStatsRedirect(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec := httptest.NewRecorder()
	new(App).handleStatsRedirect(rec, req)
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusPermanentRedirect)
	}
	if got := rec.Header().Get("Location"); got != "/statistics" {
		t.Fatalf("Location=%q want /statistics", got)
	}
}

func TestDNSRecordsPageUsesFilePickerAndUnifiedSourceBlock(t *testing.T) {
	data := pageData{
		Title:              "DNS records",
		Path:               "/dns-records",
		Config:             &Config{},
		Message:            "127.0.0.1:8080",
		RecordQuery:        "db",
		RecordPage:         2,
		RecordTotalPages:   3,
		RecordTotalDomains: 41,
		RecordHasPrev:      true,
		RecordHasNext:      true,
		RecordPrevURL:      "/dns-records?q=db",
		RecordNextURL:      "/dns-records?q=db&page=3",
		RecordReturnURL:    "/dns-records?q=db&page=2",
		RecordDomains: []DNSRecordDomainView{{
			Name: "db.lan",
			Records: []DNSRecordState{
				{Name: "db.lan", Type: "A", Value: "192.0.2.1", TTL: 60, DefaultTTL: true, Source: "Database", SourceKind: "database", Status: "active", Persistent: true, ID: 1},
				{Name: "db.lan", Type: "A", Value: "192.0.2.2", TTL: 60, DefaultTTL: true, Source: "/tmp/source.csv", SourceKind: "file", SourceID: 2, Status: "overridden"},
			},
		}},
		DNSRecordSources: []DNSRecordSourceState{{ID: 2, Location: "/tmp/source.csv", Kind: "file", Loaded: true, Domains: 1, Records: 1}},
	}
	var out strings.Builder
	if err := templates.ExecuteTemplate(&out, "dns_records.html.tmpl", data); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, expected := range []string{
		`form="record-add-form">Add record`,
		`id="record-import-file"`,
		`document.getElementById('record-import-file').click()`,
		`onchange="if (this.files.length) this.form.submit()"`,
		`action="/record/export"`,
		`id="record-domain-search"`,
		`name="q" value="db"`,
		`substring or /regexp/`,
		`document.getElementById('record-domain-search').value=''`,
		`>Clear</button>`,
		`41 domains · page 2 of 3`,
		`/dns-records?q=db&amp;page=3`,
		`<h2>External CSV sources</h2>`,
		`<details class="reload-menu">`,
		`<summary>Reload</summary>`,
		`action="/record/sources/refresh"`,
		`Reload sources`,
		`Reload config reuses the current in-memory source snapshot`,
		`overridden`,
		`active`,
		`/tmp/source.csv`,
		`value="/dns-records?q=db&amp;page=2"`,
	} {
		if !strings.Contains(html, expected) {
			t.Fatalf("rendered page does not contain %q", expected)
		}
	}
	if strings.Contains(html, "<h2>Configured sources</h2>") {
		t.Fatal("configured sources remained a separate card")
	}
	if strings.Contains(html, `href="/dns-records">Clear</a>`) {
		t.Fatal("search clear control is still rendered as a link")
	}
	headerEnd := strings.Index(html, `</header>`)
	footerIndex := strings.Index(html, `<footer class="site-footer">`)
	refreshIndex := strings.Index(html, `action="/record/sources/refresh"`)
	if headerEnd < 0 || refreshIndex < 0 || refreshIndex > headerEnd {
		t.Fatal("Reload sources action is not located in the shared header")
	}
	if footerIndex < 0 || strings.Index(html[footerIndex:], `action="/record/sources/refresh"`) >= 0 {
		t.Fatal("Reload sources action unexpectedly remains in the footer")
	}
}

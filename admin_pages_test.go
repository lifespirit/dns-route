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
		Title:   "DNS records",
		Path:    "/dns-records",
		Config:  &Config{},
		Message: "127.0.0.1:8080",
		Records: []DNSRecordState{
			{Name: "db.lan", Type: "A", Value: "192.0.2.1", TTL: 60, DefaultTTL: true, Source: "Database", SourceKind: "database", Status: "active", Persistent: true, ID: 1},
			{Name: "db.lan", Type: "A", Value: "192.0.2.2", TTL: 60, DefaultTTL: true, Source: "/tmp/source.csv", SourceKind: "file", SourceID: 2, Status: "overridden"},
		},
		DNSRecordSources: []DNSRecordSourceState{{ID: 2, Location: "/tmp/source.csv", Kind: "file", Domains: 1, Records: 1}},
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
		`<h2>External CSV sources</h2>`,
		`overridden`,
		`active`,
		`/tmp/source.csv`,
	} {
		if !strings.Contains(html, expected) {
			t.Fatalf("rendered page does not contain %q", expected)
		}
	}
	if strings.Contains(html, "<h2>Configured sources</h2>") {
		t.Fatal("configured sources remained a separate card")
	}
}

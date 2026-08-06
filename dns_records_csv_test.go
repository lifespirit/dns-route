package main

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

func openDNSRecordTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "dns-route.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := initDB(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestParseDNSRecordsCSVForms(t *testing.T) {
	parsed, err := parseDNSRecordsCSV(strings.NewReader(strings.Join([]string{
		"test.lan",
		"trailing-comma.lan,",
		"a.lan,A",
		"aaaa.lan,AAAA",
		"empty-a.lan,A,",
		"empty-aaaa.lan,AAAA,",
		"address-a.lan,A,1.1.1.1",
		"address-aaaa.lan,AAAA,::1",
	}, "\n")), false)
	if err != nil {
		t.Fatal(err)
	}

	both := parsed.Domains["test.lan"]
	if !both.ASet || !both.AAAASet || len(both.A) != 1 || !both.A[0].NoData || len(both.AAAA) != 1 || !both.AAAA[0].NoData {
		t.Fatalf("single-column rule = %#v", both)
	}
	trailingComma := parsed.Domains["trailing-comma.lan"]
	if !trailingComma.ASet || !trailingComma.AAAASet || len(trailingComma.A) != 1 || !trailingComma.A[0].NoData || len(trailingComma.AAAA) != 1 || !trailingComma.AAAA[0].NoData {
		t.Fatalf("trailing-comma rule = %#v", trailingComma)
	}
	if set := parsed.Domains["a.lan"]; !set.ASet || set.AAAASet || len(set.A) != 1 || !set.A[0].NoData {
		t.Fatalf("A-only NODATA rule = %#v", set)
	}
	if set := parsed.Domains["aaaa.lan"]; set.ASet || !set.AAAASet || len(set.AAAA) != 1 || !set.AAAA[0].NoData {
		t.Fatalf("AAAA-only NODATA rule = %#v", set)
	}
	if set := parsed.Domains["empty-a.lan"]; len(set.A) != 1 || !set.A[0].NoData {
		t.Fatalf("empty A value rule = %#v", set)
	}
	if set := parsed.Domains["empty-aaaa.lan"]; len(set.AAAA) != 1 || !set.AAAA[0].NoData {
		t.Fatalf("empty AAAA value rule = %#v", set)
	}
	if got := parsed.Domains["address-a.lan"].A[0].IP.String(); got != "1.1.1.1" {
		t.Fatalf("A address = %q", got)
	}
	if got := parsed.Domains["address-aaaa.lan"].AAAA[0].IP.String(); got != "::1" {
		t.Fatalf("AAAA address = %q", got)
	}
}

func TestParseDNSRecordsCSVSkipsEmptyRows(t *testing.T) {
	parsed, err := parseDNSRecordsCSV(strings.NewReader("\n   \n,\n,,\n\t, \nkept.lan,A,192.0.2.10\n\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Domains) != 1 {
		t.Fatalf("domains = %#v", parsed.Domains)
	}
	set, ok := parsed.Domains["kept.lan"]
	if !ok || !set.ASet || set.AAAASet || len(set.A) != 1 || set.A[0].IP.String() != "192.0.2.10" {
		t.Fatalf("kept.lan = %#v", set)
	}
}

func TestParseDNSRecordsCSVNoDataOnlyIgnoresAddresses(t *testing.T) {
	parsed, err := parseDNSRecordsCSV(strings.NewReader("evil-a.lan,A,203.0.113.10,ignored\nevil-aaaa.lan,AAAA,2001:db8::10\nboth.lan\ntrailing.lan,\n"), true)
	if err != nil {
		t.Fatal(err)
	}
	if rec := parsed.Domains["evil-a.lan"].A[0]; !rec.NoData || rec.IP != nil {
		t.Fatalf("A source record = %#v", rec)
	}
	if rec := parsed.Domains["evil-aaaa.lan"].AAAA[0]; !rec.NoData || rec.IP != nil {
		t.Fatalf("AAAA source record = %#v", rec)
	}
	both := parsed.Domains["both.lan"]
	if !both.A[0].NoData || !both.AAAA[0].NoData {
		t.Fatalf("single-column source record = %#v", both)
	}
	trailing := parsed.Domains["trailing.lan"]
	if !trailing.ASet || !trailing.AAAASet || !trailing.A[0].NoData || !trailing.AAAA[0].NoData {
		t.Fatalf("trailing-comma source record = %#v", trailing)
	}
}

func TestParseDNSRecordsCSVLastModeWinsAndKeepsMultipleAddresses(t *testing.T) {
	parsed, err := parseDNSRecordsCSV(strings.NewReader(strings.Join([]string{
		"multi.lan,A,192.0.2.1",
		"multi.lan,A,192.0.2.2",
		"multi.lan,A",
		"multi.lan,A,192.0.2.3",
		"multi.lan,A,192.0.2.4",
	}, "\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	got := parsed.Domains["multi.lan"].A
	if len(got) != 2 || got[0].IP.String() != "192.0.2.3" || got[1].IP.String() != "192.0.2.4" {
		t.Fatalf("records = %#v", got)
	}
}

func TestReplaceImportedDNSRecordsReplacesWholeName(t *testing.T) {
	db := openDNSRecordTestDB(t)
	for _, args := range [][]any{
		{"TEST.LAN.", "A", "9.9.9.9"},
		{"test.lan", "AAAA", "2001:db8::9"},
		{"keep.lan", "A", "192.0.2.50"},
	} {
		if _, err := db.Exec(`INSERT INTO dns_records(name, type, value, ttl, enabled) VALUES(?, ?, ?, 0, 1)`, args...); err != nil {
			t.Fatal(err)
		}
	}
	parsed, err := parseDNSRecordsCSV(strings.NewReader("test.lan,A,1.1.1.1\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := replaceImportedDNSRecords(db, parsed); err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query(`SELECT type, value FROM dns_records WHERE name = 'test.lan' ORDER BY type, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got [][2]string
	for rows.Next() {
		var typ, value string
		if err := rows.Scan(&typ, &value); err != nil {
			t.Fatal(err)
		}
		got = append(got, [2]string{typ, value})
	}
	if len(got) != 1 || got[0] != [2]string{"A", "1.1.1.1"} {
		t.Fatalf("test.lan rows = %#v", got)
	}
	var keep int
	if err := db.QueryRow(`SELECT count(*) FROM dns_records WHERE name = 'keep.lan'`).Scan(&keep); err != nil {
		t.Fatal(err)
	}
	if keep != 1 {
		t.Fatalf("keep.lan count = %d", keep)
	}
}

func TestExportDNSRecordsCSVExportsEffectivePersistentRules(t *testing.T) {
	db := openDNSRecordTestDB(t)
	for _, args := range [][]any{
		{"both.lan", "A", ""},
		{"both.lan", "AAAA", ""},
		{"a.lan", "A", "192.0.2.1"},
		{"a.lan", "A", "192.0.2.2"},
		{"v6.lan", "AAAA", ""},
	} {
		if _, err := db.Exec(`INSERT INTO dns_records(name, type, value, ttl, enabled) VALUES(?, ?, ?, 0, 1)`, args...); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := exportDNSRecordsCSV(db, &out); err != nil {
		t.Fatal(err)
	}
	want := "a.lan,A,192.0.2.1\na.lan,A,192.0.2.2\nboth.lan\nv6.lan,AAAA\n"
	if out.String() != want {
		t.Fatalf("export:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestLoadDNSRecordSourcesRefreshBelowDatabasePriority(t *testing.T) {
	db := openDNSRecordTestDB(t)
	for _, args := range [][]any{
		{"base.lan", "A", "192.0.2.1"},
		{"base.lan", "AAAA", "2001:db8::1"},
	} {
		if _, err := db.Exec(`INSERT INTO dns_records(name, type, value, ttl, enabled) VALUES(?, ?, ?, 0, 1)`, args...); err != nil {
			t.Fatal(err)
		}
	}

	filePath := filepath.Join(t.TempDir(), "records.csv")
	if err := os.WriteFile(filePath, []byte("base.lan,A,192.0.2.2\nfile.lan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	httpBody := "base.lan,AAAA,2001:db8::20\nhttp.lan,A,203.0.113.20\n"
	httpRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		httpRequests++
		body := httpBody
		mu.Unlock()
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()

	if _, err := db.Exec(`INSERT INTO dns_record_sources(location, no_data_only, enabled) VALUES(?, 0, 1)`, filePath); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_record_sources(location, no_data_only, enabled) VALUES(?, 1, 1)`, server.URL); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfigFromDB(db)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.LocalA["base.lan"][0].IP.String(); got != "192.0.2.1" {
		t.Fatalf("base A = %q", got)
	}
	if got := cfg.LocalAAAA["base.lan"][0].IP.String(); got != "2001:db8::1" {
		t.Fatalf("base AAAA = %q", got)
	}
	if rec := cfg.LocalA["http.lan"][0]; !rec.NoData || rec.IP != nil {
		t.Fatalf("http A from NO_DATA-only source = %#v", rec)
	}
	if len(cfg.LocalA["file.lan"]) != 1 || !cfg.LocalA["file.lan"][0].NoData || len(cfg.LocalAAAA["file.lan"]) != 1 || !cfg.LocalAAAA["file.lan"][0].NoData {
		t.Fatalf("file.lan A=%#v AAAA=%#v", cfg.LocalA["file.lan"], cfg.LocalAAAA["file.lan"])
	}
	mu.Lock()
	firstRequestCount := httpRequests
	mu.Unlock()
	if firstRequestCount != 1 {
		t.Fatalf("HTTP requests after first load = %d", firstRequestCount)
	}
	if len(cfg.DNSRecordSources) != 2 || cfg.DNSRecordSources[0].NoDataOnly || !cfg.DNSRecordSources[1].NoDataOnly {
		t.Fatalf("source states = %#v", cfg.DNSRecordSources)
	}
	var persisted int
	if err := db.QueryRow(`SELECT count(*) FROM dns_records WHERE name IN ('file.lan', 'http.lan')`).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 0 {
		t.Fatalf("external records persisted = %d", persisted)
	}

	if err := os.WriteFile(filePath, []byte("base.lan,A,192.0.2.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	httpBody = "base.lan,AAAA,2001:db8::30\n"
	mu.Unlock()
	cfg, err = loadConfigFromDB(db)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.LocalA["base.lan"][0].IP.String(); got != "192.0.2.1" {
		t.Fatalf("refreshed base A = %q", got)
	}
	if got := cfg.LocalAAAA["base.lan"][0].IP.String(); got != "2001:db8::1" {
		t.Fatalf("refreshed base AAAA = %q", got)
	}
	mu.Lock()
	secondRequestCount := httpRequests
	mu.Unlock()
	if secondRequestCount != 2 {
		t.Fatalf("HTTP requests after reload = %d", secondRequestCount)
	}
}

func TestCSVRecordsProduceLocalDNSResponses(t *testing.T) {
	cfg := &Config{
		LocalA: map[string][]LocalRecord{
			"nodata.lan": {{NoData: true, TTL: 60}},
			"static.lan": {{IP: net.ParseIP("192.0.2.44").To4(), TTL: 60}},
		},
		LocalAAAA: map[string][]LocalRecord{},
	}
	app := &App{cfg: cfg}

	nodataReq := new(dns.Msg)
	nodataReq.SetQuestion("nodata.lan.", dns.TypeA)
	nodataResp := app.localResponse(nodataReq, nodataReq.Question[0])
	if nodataResp == nil || len(nodataResp.Answer) != 0 {
		t.Fatalf("NODATA response = %#v", nodataResp)
	}

	staticReq := new(dns.Msg)
	staticReq.SetQuestion("static.lan.", dns.TypeA)
	staticResp := app.localResponse(staticReq, staticReq.Question[0])
	if staticResp == nil || len(staticResp.Answer) != 1 {
		t.Fatalf("static response = %#v", staticResp)
	}
	a, ok := staticResp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "192.0.2.44" {
		t.Fatalf("static answer = %#v", staticResp.Answer[0])
	}
}

func TestEnsureDNSRecordSourceModeColumnMigratesExistingTable(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "migration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE dns_record_sources (id INTEGER PRIMARY KEY AUTOINCREMENT, location TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_record_sources(location, enabled) VALUES('/tmp/list.csv', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := initDB(db); err != nil {
		t.Fatal(err)
	}
	var mode int
	if err := db.QueryRow(`SELECT no_data_only FROM dns_record_sources WHERE location = '/tmp/list.csv'`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != 0 {
		t.Fatalf("migrated mode = %d", mode)
	}
}

func TestLoadDNSRecordSourcesLaterSourceWinsPerFamily(t *testing.T) {
	db := openDNSRecordTestDB(t)
	first := filepath.Join(t.TempDir(), "first.csv")
	second := filepath.Join(t.TempDir(), "second.csv")
	if err := os.WriteFile(first, []byte("same.lan,A,192.0.2.1\nsame.lan,AAAA,2001:db8::1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("same.lan,A,192.0.2.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_record_sources(location, no_data_only, enabled) VALUES(?, 0, 1), (?, 0, 1)`, first, second); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{LocalA: map[string][]LocalRecord{}, LocalAAAA: map[string][]LocalRecord{}, DefaultTTL: 60}
	if err := loadDNSRecordSources(context.Background(), db, cfg, newDNSRecordSourceClient()); err != nil {
		t.Fatal(err)
	}
	if got := cfg.LocalA["same.lan"][0].IP.String(); got != "192.0.2.2" {
		t.Fatalf("A = %q", got)
	}
	if got := cfg.LocalAAAA["same.lan"][0].IP.String(); got != "2001:db8::1" {
		t.Fatalf("AAAA = %q", got)
	}
}

func TestLoadDNSRecordSourcesTracksActiveAndOverriddenRecords(t *testing.T) {
	db := openDNSRecordTestDB(t)
	for _, args := range [][]any{
		{"same.lan", "A", "192.0.2.10"},
		{"same.lan", "AAAA", "2001:db8::10"},
	} {
		if _, err := db.Exec(`INSERT INTO dns_records(name, type, value, ttl, enabled) VALUES(?, ?, ?, 0, 1)`, args...); err != nil {
			t.Fatal(err)
		}
	}

	first := filepath.Join(t.TempDir(), "first.csv")
	second := filepath.Join(t.TempDir(), "second.csv")
	if err := os.WriteFile(first, []byte("same.lan,A,192.0.2.20\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("same.lan,A,192.0.2.30\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_record_sources(location, no_data_only, enabled) VALUES(?, 0, 1), (?, 0, 1)`, first, second); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfigFromDB(db)
	if err != nil {
		t.Fatal(err)
	}

	type key struct {
		value  string
		source string
	}
	statuses := make(map[key]string)
	for _, entry := range cfg.DNSRecordEntries {
		if entry.Name == "same.lan" {
			statuses[key{entry.Value, entry.Source}] = entry.Status
		}
	}
	if got := statuses[key{"192.0.2.10", "Database"}]; got != "active" {
		t.Fatalf("database A status = %q", got)
	}
	if got := statuses[key{"2001:db8::10", "Database"}]; got != "active" {
		t.Fatalf("database AAAA status = %q", got)
	}
	if got := statuses[key{"192.0.2.20", first}]; got != "overridden" {
		t.Fatalf("first source A status = %q", got)
	}
	if got := statuses[key{"192.0.2.30", second}]; got != "overridden" {
		t.Fatalf("second source A status = %q", got)
	}
	if got := cfg.LocalA["same.lan"][0].IP.String(); got != "192.0.2.10" {
		t.Fatalf("effective A = %q", got)
	}
}

func TestDisabledDatabaseRecordIsShownButNotOverridden(t *testing.T) {
	db := openDNSRecordTestDB(t)
	if _, err := db.Exec(`INSERT INTO dns_records(name, type, value, ttl, enabled) VALUES('same.lan', 'A', '192.0.2.10', 0, 0)`); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "source.csv")
	if err := os.WriteFile(file, []byte("same.lan,A,192.0.2.20\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_record_sources(location, no_data_only, enabled) VALUES(?, 0, 1)`, file); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigFromDB(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DNSRecordEntries) != 2 {
		t.Fatalf("record entries = %d", len(cfg.DNSRecordEntries))
	}
	for _, entry := range cfg.DNSRecordEntries {
		if entry.Persistent && entry.Status != "disabled" {
			t.Fatalf("disabled database status = %q", entry.Status)
		}
	}
}

func TestPersistentRecordsOverrideSourcesPerFamily(t *testing.T) {
	db := openDNSRecordTestDB(t)
	if _, err := db.Exec(`INSERT INTO dns_records(name, type, value, ttl, enabled) VALUES
		('mixed.lan', 'A', '192.0.2.10', 0, 1),
		('mixed.lan', 'A', '192.0.2.11', 0, 1)`); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "source.csv")
	if err := os.WriteFile(file, []byte("mixed.lan,A,192.0.2.20\nmixed.lan,AAAA,2001:db8::20\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_record_sources(location, no_data_only, enabled) VALUES(?, 0, 1)`, file); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfigFromDB(db)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(cfg.LocalA["mixed.lan"]); got != 2 {
		t.Fatalf("effective A count = %d", got)
	}
	if got := cfg.LocalA["mixed.lan"][0].IP.String(); got != "192.0.2.10" {
		t.Fatalf("first effective A = %q", got)
	}
	if got := cfg.LocalA["mixed.lan"][1].IP.String(); got != "192.0.2.11" {
		t.Fatalf("second effective A = %q", got)
	}
	if got := cfg.LocalAAAA["mixed.lan"][0].IP.String(); got != "2001:db8::20" {
		t.Fatalf("effective AAAA = %q", got)
	}

	statuses := make(map[string]string)
	for _, entry := range cfg.DNSRecordEntries {
		if entry.Name == "mixed.lan" {
			statuses[entry.Source+"|"+entry.Type+"|"+entry.Value] = entry.Status
		}
	}
	if got := statuses[file+"|A|192.0.2.20"]; got != "overridden" {
		t.Fatalf("source A status = %q", got)
	}
	if got := statuses[file+"|AAAA|2001:db8::20"]; got != "active" {
		t.Fatalf("source AAAA status = %q", got)
	}
	if got := statuses["Database|A|192.0.2.10"]; got != "active" {
		t.Fatalf("first database A status = %q", got)
	}
	if got := statuses["Database|A|192.0.2.11"]; got != "active" {
		t.Fatalf("second database A status = %q", got)
	}
}

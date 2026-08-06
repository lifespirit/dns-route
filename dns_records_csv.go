package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const dnsRecordImportMaxBytes int64 = 32 << 20

var dnsRecordNoData = []LocalRecord{{NoData: true}}

// DNSRecordRuleSet describes the A and AAAA records supplied for one name by
// one CSV input. ASet/AAAASet distinguish an omitted family from an explicit
// NODATA rule, which is represented by one LocalRecord with NoData=true.
type DNSRecordRuleSet struct {
	ASet    bool
	AAAASet bool
	A       []LocalRecord
	AAAA    []LocalRecord
}

// DNSRecordSourceState describes one configured external CSV source. Loaded
// reports whether the active in-memory snapshot contains matching parsed data.
// Source contents are never copied into SQLite.
type DNSRecordSourceState struct {
	ID         int64
	Location   string
	Kind       string
	NoDataOnly bool
	Loaded     bool
	Domains    int
	Records    int
}

// DNSRecordState is one persistent or externally supplied DNS record as shown
// in the admin panel. Status reflects the currently loaded configuration:
// later external sources override earlier external layers per name and type;
// persistent SQLite records are applied last and have final priority.
type DNSRecordState struct {
	ID         int64
	Name       string
	Type       string
	Value      string
	TTL        uint32
	DefaultTTL bool
	Source     string
	SourceKind string
	SourceID   int64
	Status     string
	Persistent bool
}

type dnsRecordCSV struct {
	Domains map[string]DNSRecordRuleSet
}

func newDNSRecordCSV() *dnsRecordCSV {
	return &dnsRecordCSV{Domains: make(map[string]DNSRecordRuleSet)}
}

func normalizeDNSRecordName(value string) (string, error) {
	value = normalizeName(value)
	if value == "" {
		return "", fmt.Errorf("DNS record name cannot be empty")
	}
	base := value
	if strings.HasPrefix(base, "*.") {
		base = strings.TrimPrefix(base, "*.")
	}
	if base == "" || strings.Contains(base, "*") || strings.ContainsAny(base, " \t\r\n,/") {
		return "", fmt.Errorf("invalid DNS record name %q", value)
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(base)); !ok {
		return "", fmt.Errorf("invalid DNS record name %q", value)
	}
	return value, nil
}

func parseDNSRecordsCSV(r io.Reader, noDataOnly bool) (*dnsRecordCSV, error) {
	raw, err := io.ReadAll(io.LimitReader(r, dnsRecordImportMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read CSV: %w", err)
	}
	if int64(len(raw)) > dnsRecordImportMaxBytes {
		return nil, fmt.Errorf("CSV exceeds %d bytes", dnsRecordImportMaxBytes)
	}

	reader := csv.NewReader(bytes.NewReader(raw))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	out := newDNSRecordCSV()
	line := 0
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line++
		if err != nil {
			return nil, fmt.Errorf("CSV line %d: %w", line, err)
		}
		if len(record) == 0 {
			continue
		}
		for i := range record {
			record[i] = strings.TrimSpace(record[i])
		}
		if line == 1 {
			record[0] = strings.TrimPrefix(record[0], "\uFEFF")
		}
		if record[0] == "" {
			allEmpty := true
			for _, field := range record[1:] {
				if field != "" {
					allEmpty = false
					break
				}
			}
			if allEmpty {
				continue
			}
		}
		if strings.HasPrefix(record[0], "#") || strings.HasPrefix(record[0], ";") {
			continue
		}
		if (strings.EqualFold(record[0], "domain") || strings.EqualFold(record[0], "name")) && len(record) > 1 && strings.EqualFold(record[1], "type") {
			continue
		}
		if noDataOnly && len(record) > 2 {
			record = record[:2]
		} else if len(record) > 3 {
			return nil, fmt.Errorf("CSV line %d: expected 1 to 3 columns, got %d", line, len(record))
		}
		// A trailing delimiter without a record type is equivalent to the
		// one-column Pi-hole form and therefore means NODATA for both A and
		// AAAA. encoding/csv represents "domain," as two fields.
		if len(record) == 2 && record[1] == "" {
			record = record[:1]
		}

		name, err := normalizeDNSRecordName(record[0])
		if err != nil {
			return nil, fmt.Errorf("CSV line %d: %w", line, err)
		}
		set := out.Domains[name]

		switch len(record) {
		case 1:
			set.ASet = true
			set.AAAASet = true
			set.A = dnsRecordNoData
			set.AAAA = dnsRecordNoData
		case 2, 3:
			typ := strings.ToUpper(strings.TrimSpace(record[1]))
			if typ != "A" && typ != "AAAA" {
				return nil, fmt.Errorf("CSV line %d: unsupported type %q", line, record[1])
			}
			value := ""
			if !noDataOnly && len(record) == 3 {
				value = record[2]
			}
			rec, err := dnsRecordForCSV(typ, value)
			if err != nil {
				return nil, fmt.Errorf("CSV line %d: %w", line, err)
			}
			if typ == "A" {
				set.ASet = true
				set.A = mergeCSVFamily(set.A, rec)
			} else {
				set.AAAASet = true
				set.AAAA = mergeCSVFamily(set.AAAA, rec)
			}
		}
		out.Domains[name] = set
	}
	if len(out.Domains) == 0 {
		return nil, fmt.Errorf("CSV contains no DNS records")
	}
	return out, nil
}

func dnsRecordForCSV(typ, value string) (LocalRecord, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return LocalRecord{NoData: true}, nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return LocalRecord{}, fmt.Errorf("invalid %s address %q", typ, value)
	}
	if typ == "A" {
		v4 := ip.To4()
		if v4 == nil {
			return LocalRecord{}, fmt.Errorf("A requires an IPv4 address, got %q", value)
		}
		return LocalRecord{IP: append(net.IP(nil), v4...)}, nil
	}
	if ip.To4() != nil {
		return LocalRecord{}, fmt.Errorf("AAAA requires an IPv6 address, got %q", value)
	}
	return LocalRecord{IP: append(net.IP(nil), ip.To16()...)}, nil
}

// mergeCSVFamily makes the last mode in a CSV file deterministic. NODATA
// replaces all addresses collected for the family. A later address replaces
// NODATA and additional addresses are appended as a multi-value DNS answer.
func mergeCSVFamily(existing []LocalRecord, rec LocalRecord) []LocalRecord {
	if rec.NoData || rec.IP == nil {
		return dnsRecordNoData
	}
	if len(existing) == 1 && existing[0].NoData {
		existing = nil
	}
	for _, current := range existing {
		if current.IP != nil && current.IP.Equal(rec.IP) {
			return existing
		}
	}
	return append(existing, rec)
}

func prepareCSVRecords(records []LocalRecord, ttl uint32) []LocalRecord {
	if len(records) == 1 && records[0].NoData {
		return records
	}
	for i := range records {
		records[i].TTL = ttl
	}
	return records
}

func dnsRecordRuleCount(set DNSRecordRuleSet) int {
	return len(set.A) + len(set.AAAA)
}

func replaceImportedDNSRecords(db *sql.DB, imported *dnsRecordCSV) error {
	if imported == nil || len(imported.Domains) == 0 {
		return fmt.Errorf("empty DNS-record import")
	}

	names := make([]string, 0, len(imported.Domains))
	for name := range imported.Domains {
		names = append(names, name)
	}
	sort.Strings(names)

	return withSQLiteWriteTx(context.Background(), db, func(conn *sql.Conn) error {
		for _, name := range names {
			set := imported.Domains[name]
			if _, err := conn.ExecContext(context.Background(), `DELETE FROM dns_records WHERE lower(rtrim(trim(name), '.')) = ?`, name); err != nil {
				return fmt.Errorf("replace DNS records for %q: %w", name, err)
			}
			if set.ASet {
				if err := insertImportedDNSRecords(conn, name, "A", set.A); err != nil {
					return err
				}
			}
			if set.AAAASet {
				if err := insertImportedDNSRecords(conn, name, "AAAA", set.AAAA); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func insertImportedDNSRecords(conn *sql.Conn, name, typ string, records []LocalRecord) error {
	for _, rec := range records {
		value := ""
		if !rec.NoData && rec.IP != nil {
			value = rec.IP.String()
		}
		if _, err := conn.ExecContext(context.Background(), `INSERT INTO dns_records(name, type, value, ttl, enabled) VALUES(?, ?, ?, 0, 1)`, name, typ, value); err != nil {
			return fmt.Errorf("store imported %s record for %q: %w", typ, name, err)
		}
	}
	return nil
}

type exportDNSFamily struct {
	NoData bool
	Values []string
}

type exportDNSName struct {
	A    exportDNSFamily
	AAAA exportDNSFamily
}

func exportDNSRecordsCSV(db *sql.DB, w io.Writer) error {
	rows, err := db.Query(`SELECT name, type, value FROM dns_records WHERE enabled = 1 ORDER BY name, type, id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	byName := make(map[string]exportDNSName)
	for rows.Next() {
		var name, typ, value string
		if err := rows.Scan(&name, &typ, &value); err != nil {
			return err
		}
		name = normalizeName(name)
		typ = strings.ToUpper(strings.TrimSpace(typ))
		value = strings.TrimSpace(value)
		if name == "" || (typ != "A" && typ != "AAAA") {
			continue
		}
		entry := byName[name]
		family := &entry.A
		if typ == "AAAA" {
			family = &entry.AAAA
		}
		if value == "" {
			family.NoData = true
			family.Values = nil
		} else if !family.NoData && !containsString(family.Values, value) {
			family.Values = append(family.Values, value)
		}
		byName[name] = entry
	}
	if err := rows.Err(); err != nil {
		return err
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	writer := csv.NewWriter(w)
	for _, name := range names {
		entry := byName[name]
		if entry.A.NoData && entry.AAAA.NoData {
			if err := writer.Write([]string{name}); err != nil {
				return err
			}
			continue
		}
		if err := writeExportDNSFamily(writer, name, "A", entry.A); err != nil {
			return err
		}
		if err := writeExportDNSFamily(writer, name, "AAAA", entry.AAAA); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func writeExportDNSFamily(writer *csv.Writer, name, typ string, family exportDNSFamily) error {
	if family.NoData {
		return writer.Write([]string{name, typ})
	}
	for _, value := range family.Values {
		if err := writer.Write([]string{name, typ, value}); err != nil {
			return err
		}
	}
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func newDNSRecordSourceClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

func loadDNSRecordSources(ctx context.Context, db *sql.DB, cfg *Config, client *http.Client) error {
	snapshots, err := fetchDNSRecordSources(ctx, db, client)
	if err != nil {
		return err
	}
	return applyDNSRecordSources(db, cfg, snapshots)
}

func fetchDNSRecordSources(ctx context.Context, db *sql.DB, client *http.Client) ([]DNSRecordWebSource, error) {
	// Do not keep a SQLite cursor open while downloading or parsing external
	// content. The configured rows are copied first, then all network and file
	// I/O happens without an active database cursor or transaction.
	sources, err := readEnabledDNSRecordSources(db)
	if err != nil {
		return nil, err
	}

	snapshots := make([]DNSRecordWebSource, 0, len(sources))
	for _, source := range sources {
		location := strings.TrimSpace(source.Location)
		body, kind, err := openDNSRecordSource(ctx, location, client)
		if err != nil {
			return nil, fmt.Errorf("load DNS-record source %q: %w", location, err)
		}
		parsed, parseErr := parseDNSRecordsCSV(body, source.NoDataOnly != 0)
		closeErr := body.Close()
		if parseErr != nil {
			return nil, fmt.Errorf("parse DNS-record source %q: %w", location, parseErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close DNS-record source %q: %w", location, closeErr)
		}

		recordCount := 0
		rules := make([]DNSRecordWebRule, 0, len(parsed.Domains))
		for name, set := range parsed.Domains {
			rules = append(rules, DNSRecordWebRule{Name: name, Set: set})
			recordCount += dnsRecordRuleCount(set)
		}
		sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
		state := DNSRecordSourceState{
			ID:         source.ID,
			Location:   location,
			Kind:       kind,
			NoDataOnly: source.NoDataOnly != 0,
			Loaded:     true,
			Domains:    len(parsed.Domains),
			Records:    recordCount,
		}
		snapshots = append(snapshots, DNSRecordWebSource{
			State: state,
			Rules: rules,
		})
	}
	return snapshots, nil
}

func applyDNSRecordSources(db *sql.DB, cfg *Config, snapshots []DNSRecordWebSource) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	if cfg.LocalA == nil {
		cfg.LocalA = make(map[string][]LocalRecord)
	}
	if cfg.LocalAAAA == nil {
		cfg.LocalAAAA = make(map[string][]LocalRecord)
	}
	if cfg.DNSRecordIndex == nil {
		cfg.DNSRecordIndex = newDNSRecordWebIndex()
	}
	cfg.DNSRecordSources = nil
	cfg.DNSRecordIndex.Sources = nil

	configured, err := readEnabledDNSRecordSources(db)
	if err != nil {
		return err
	}
	byID := make(map[int64]DNSRecordWebSource, len(snapshots))
	for _, snapshot := range snapshots {
		byID[snapshot.State.ID] = snapshot
	}

	for _, source := range configured {
		location := strings.TrimSpace(source.Location)
		state := DNSRecordSourceState{
			ID:         source.ID,
			Location:   location,
			Kind:       dnsRecordSourceKind(location),
			NoDataOnly: source.NoDataOnly != 0,
		}
		snapshot, loaded := byID[source.ID]
		if loaded && (snapshot.State.Location != location || snapshot.State.NoDataOnly != state.NoDataOnly) {
			loaded = false
		}
		if !loaded {
			cfg.DNSRecordSources = append(cfg.DNSRecordSources, state)
			continue
		}

		state = snapshot.State
		state.Loaded = true
		snapshot.State = state
		for _, rule := range snapshot.Rules {
			set := rule.Set
			if set.ASet {
				set.A = preparedCSVRecords(set.A, cfg.DefaultTTL)
				cfg.LocalA[rule.Name] = set.A
			}
			if set.AAAASet {
				set.AAAA = preparedCSVRecords(set.AAAA, cfg.DefaultTTL)
				cfg.LocalAAAA[rule.Name] = set.AAAA
			}
			cfg.DNSRecordIndex.addDomain(rule.Name)
		}
		cfg.DNSRecordSources = append(cfg.DNSRecordSources, state)
		cfg.DNSRecordIndex.Sources = append(cfg.DNSRecordIndex.Sources, snapshot)
	}
	return nil
}

func preparedCSVRecords(records []LocalRecord, ttl uint32) []LocalRecord {
	copied := append([]LocalRecord(nil), records...)
	return prepareCSVRecords(copied, ttl)
}

func dnsRecordSourceKind(location string) string {
	u, err := url.Parse(strings.TrimSpace(location))
	if err == nil {
		switch strings.ToLower(u.Scheme) {
		case "http", "https":
			return "http"
		}
	}
	return "file"
}

func readEnabledDNSRecordSources(db *sql.DB) ([]dnsRecordSourceDBRow, error) {
	rows, err := db.Query(`SELECT id, location, no_data_only, enabled FROM dns_record_sources WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sources []dnsRecordSourceDBRow
	for rows.Next() {
		var source dnsRecordSourceDBRow
		if err := rows.Scan(&source.ID, &source.Location, &source.NoDataOnly, &source.Enabled); err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sources, nil
}

func validateDNSRecordSourceLocation(location string) error {
	location = strings.TrimSpace(location)
	if location == "" {
		return fmt.Errorf("source location is required")
	}
	u, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("invalid source location: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "":
		return nil
	case "http", "https":
		if u.Host == "" {
			return fmt.Errorf("HTTP source requires a host")
		}
		return nil
	case "file":
		if u.Path == "" {
			return fmt.Errorf("file source requires a path")
		}
		return nil
	default:
		return fmt.Errorf("unsupported source scheme %q", u.Scheme)
	}
}

func openDNSRecordSource(ctx context.Context, location string, client *http.Client) (io.ReadCloser, string, error) {
	if err := validateDNSRecordSourceLocation(location); err != nil {
		return nil, "", err
	}
	u, _ := url.Parse(location)
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		if client == nil {
			client = newDNSRecordSourceClient()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
		if err != nil {
			return nil, "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, "", err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			return nil, "", fmt.Errorf("HTTP status %s", resp.Status)
		}
		return &dnsRecordLimitedReadCloser{Reader: io.LimitReader(resp.Body, dnsRecordImportMaxBytes+1), Closer: resp.Body}, "http", nil
	case "file":
		path, err := url.PathUnescape(u.Path)
		if err != nil {
			return nil, "", fmt.Errorf("decode file path: %w", err)
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, "", err
		}
		return &dnsRecordLimitedReadCloser{Reader: io.LimitReader(file, dnsRecordImportMaxBytes+1), Closer: file}, "file", nil
	default:
		file, err := os.Open(location)
		if err != nil {
			return nil, "", err
		}
		return &dnsRecordLimitedReadCloser{Reader: io.LimitReader(file, dnsRecordImportMaxBytes+1), Closer: file}, "file", nil
	}
}

type dnsRecordLimitedReadCloser struct {
	io.Reader
	io.Closer
}

func (a *App) handleRecordImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, dnsRecordImportMaxBytes+(1<<20))
	if err := r.ParseMultipartForm(dnsRecordImportMaxBytes); err != nil {
		renderError(w, http.StatusBadRequest, fmt.Errorf("parse import form: %w", err))
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		renderError(w, http.StatusBadRequest, fmt.Errorf("CSV file is required: %w", err))
		return
	}
	defer file.Close()
	parsed, err := parseDNSRecordsCSV(file, false)
	if err != nil {
		renderError(w, http.StatusBadRequest, err)
		return
	}
	if err := replaceImportedDNSRecords(a.db, parsed); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	redirectAdmin(w, r, "/dns-records")
}

func (a *App) handleRecordExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		renderError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="dns-records.csv"`)
	if r.Method == http.MethodHead {
		return
	}
	if err := exportDNSRecordsCSV(a.db, w); err != nil {
		logHTTPStreamError("export DNS records", err)
	}
}

func logHTTPStreamError(action string, err error) {
	if err != nil {
		log.Printf("%s: %v", action, err)
	}
}

type dnsRecordSourceDBRow struct {
	ID         int64
	Location   string
	NoDataOnly int
	Enabled    int
}

func getDNSRecordSourceByID(db *sql.DB, id int64) (dnsRecordSourceDBRow, error) {
	var row dnsRecordSourceDBRow
	err := db.QueryRow(`SELECT id, location, no_data_only, enabled FROM dns_record_sources WHERE id = ?`, id).Scan(&row.ID, &row.Location, &row.NoDataOnly, &row.Enabled)
	return row, err
}

func getDNSRecordSourceByLocation(db *sql.DB, location string) (dnsRecordSourceDBRow, error) {
	var row dnsRecordSourceDBRow
	err := db.QueryRow(`SELECT id, location, no_data_only, enabled FROM dns_record_sources WHERE location = ?`, location).Scan(&row.ID, &row.Location, &row.NoDataOnly, &row.Enabled)
	return row, err
}

func restoreDNSRecordSource(db *sql.DB, old dnsRecordSourceDBRow, existed bool, location string) {
	if existed {
		_, _ = db.Exec(`INSERT INTO dns_record_sources(id, location, no_data_only, enabled) VALUES(?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET location=excluded.location, no_data_only=excluded.no_data_only, enabled=excluded.enabled`, old.ID, old.Location, old.NoDataOnly, old.Enabled)
		return
	}
	_, _ = db.Exec(`DELETE FROM dns_record_sources WHERE location = ?`, location)
}

func (a *App) handleRecordSourceAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	location := strings.TrimSpace(r.FormValue("location"))
	noDataOnly := formBoolean(r, "no_data_only")
	if err := validateDNSRecordSourceLocation(location); err != nil {
		renderError(w, http.StatusBadRequest, fmt.Errorf("validate DNS-record source location: %w", err))
		return
	}
	old, err := getDNSRecordSourceByLocation(a.db, location)
	existed := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if _, err := a.db.Exec(`INSERT INTO dns_record_sources(location, no_data_only, enabled) VALUES(?, ?, 1) ON CONFLICT(location) DO UPDATE SET no_data_only=excluded.no_data_only, enabled=1`, location, boolInt(noDataOnly)); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		restoreDNSRecordSource(a.db, old, existed, location)
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	redirectAdmin(w, r, "/dns-records")
}

func (a *App) handleRecordSourceUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		renderError(w, http.StatusBadRequest, fmt.Errorf("invalid id"))
		return
	}
	old, err := getDNSRecordSourceByID(a.db, id)
	if err != nil {
		renderError(w, http.StatusNotFound, err)
		return
	}
	noDataOnly := formBoolean(r, "no_data_only")
	if err := validateDNSRecordSourceLocation(old.Location); err != nil {
		renderError(w, http.StatusBadRequest, fmt.Errorf("validate DNS-record source location: %w", err))
		return
	}
	if _, err := a.db.Exec(`UPDATE dns_record_sources SET no_data_only = ?, enabled = 1 WHERE id = ?`, boolInt(noDataOnly), id); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		restoreDNSRecordSource(a.db, old, true, old.Location)
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	redirectAdmin(w, r, "/dns-records")
}

func (a *App) handleRecordSourceDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		renderError(w, http.StatusBadRequest, fmt.Errorf("invalid id"))
		return
	}
	old, err := getDNSRecordSourceByID(a.db, id)
	if err != nil {
		renderError(w, http.StatusNotFound, err)
		return
	}
	if _, err := a.db.Exec(`DELETE FROM dns_record_sources WHERE id = ?`, id); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		restoreDNSRecordSource(a.db, old, true, old.Location)
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	redirectAdmin(w, r, "/dns-records")
}

func (a *App) handleRecordSourcesRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	if err := a.refreshDNSRecordSources(r.Context()); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	redirectAdmin(w, r, "/dns-records")
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func ensureDNSRecordSourceModeColumn(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(dns_record_sources)`)
	if err != nil {
		return err
	}
	hasColumn := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		if strings.EqualFold(name, "no_data_only") {
			hasColumn = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	if hasColumn {
		return nil
	}
	_, err = db.Exec(`ALTER TABLE dns_record_sources ADD COLUMN no_data_only INTEGER NOT NULL DEFAULT 0`)
	return err
}

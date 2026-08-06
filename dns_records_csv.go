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

// DNSRecordRuleSet describes the A and AAAA records supplied for one name by
// one CSV input. ASet/AAAASet distinguish an omitted family from an explicit
// NODATA rule, which is represented by one LocalRecord with NoData=true.
type DNSRecordRuleSet struct {
	ASet    bool
	AAAASet bool
	A       []LocalRecord
	AAAA    []LocalRecord
}

// DNSRecordSourceState describes one successfully loaded external CSV source.
// Source contents live only in the active Config and are never copied into
// SQLite.
type DNSRecordSourceState struct {
	ID         int64
	Location   string
	Kind       string
	NoDataOnly bool
	Domains    int
	Records    int
}

// DNSRecordState is one persistent or externally supplied DNS record as shown
// in the admin panel. Status reflects the currently loaded configuration:
// later external sources override earlier layers per name and record type.
type DNSRecordState struct {
	ID          int64
	Name        string
	Type        string
	Value       string
	TTL         uint32
	DefaultTTL  bool
	Source      string
	SourceKind  string
	SourceID    int64
	Status      string
	Persistent  bool
	sourceLayer int
	nameKey     string
	typeKey     string
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

		name, err := normalizeDNSRecordName(record[0])
		if err != nil {
			return nil, fmt.Errorf("CSV line %d: %w", line, err)
		}
		set := out.Domains[name]

		switch len(record) {
		case 1:
			set.ASet = true
			set.AAAASet = true
			set.A = []LocalRecord{{NoData: true}}
			set.AAAA = []LocalRecord{{NoData: true}}
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
		return []LocalRecord{{NoData: true}}
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

func cloneCSVRecords(records []LocalRecord, ttl uint32) []LocalRecord {
	out := make([]LocalRecord, 0, len(records))
	for _, rec := range records {
		copyRec := rec
		copyRec.TTL = ttl
		if rec.IP != nil {
			copyRec.IP = append(net.IP(nil), rec.IP...)
		}
		out = append(out, copyRec)
	}
	return out
}

func dnsRecordRuleCount(set DNSRecordRuleSet) int {
	return len(set.A) + len(set.AAAA)
}

func replaceImportedDNSRecords(db *sql.DB, imported *dnsRecordCSV) error {
	if imported == nil || len(imported.Domains) == 0 {
		return fmt.Errorf("empty DNS-record import")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	names := make([]string, 0, len(imported.Domains))
	for name := range imported.Domains {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		set := imported.Domains[name]
		if _, err := tx.Exec(`DELETE FROM dns_records WHERE lower(rtrim(trim(name), '.')) = ?`, name); err != nil {
			return fmt.Errorf("replace DNS records for %q: %w", name, err)
		}
		if set.ASet {
			if err := insertImportedDNSRecords(tx, name, "A", set.A); err != nil {
				return err
			}
		}
		if set.AAAASet {
			if err := insertImportedDNSRecords(tx, name, "AAAA", set.AAAA); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func insertImportedDNSRecords(tx *sql.Tx, name, typ string, records []LocalRecord) error {
	for _, rec := range records {
		value := ""
		if !rec.NoData && rec.IP != nil {
			value = rec.IP.String()
		}
		if _, err := tx.Exec(`INSERT INTO dns_records(name, type, value, ttl, enabled) VALUES(?, ?, ?, 0, 1)`, name, typ, value); err != nil {
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
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	if cfg.LocalA == nil {
		cfg.LocalA = make(map[string][]LocalRecord)
	}
	if cfg.LocalAAAA == nil {
		cfg.LocalAAAA = make(map[string][]LocalRecord)
	}
	cfg.DNSRecordSources = nil

	rows, err := db.Query(`SELECT id, location, no_data_only FROM dns_record_sources WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	sourceLayer := 0
	for rows.Next() {
		sourceLayer++
		var id int64
		var location string
		var noDataOnly int
		if err := rows.Scan(&id, &location, &noDataOnly); err != nil {
			return err
		}
		body, kind, err := openDNSRecordSource(ctx, strings.TrimSpace(location), client)
		if err != nil {
			return fmt.Errorf("load DNS-record source %q: %w", location, err)
		}
		parsed, parseErr := parseDNSRecordsCSV(body, noDataOnly != 0)
		closeErr := body.Close()
		if parseErr != nil {
			return fmt.Errorf("parse DNS-record source %q: %w", location, parseErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close DNS-record source %q: %w", location, closeErr)
		}

		recordCount := 0
		names := make([]string, 0, len(parsed.Domains))
		for name := range parsed.Domains {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			set := parsed.Domains[name]
			if set.ASet {
				markDNSRecordFamilyOverridden(cfg.DNSRecordEntries, name, "A")
				cfg.LocalA[name] = cloneCSVRecords(set.A, cfg.DefaultTTL)
				cfg.DNSRecordEntries = appendDNSRecordSourceEntries(cfg.DNSRecordEntries, id, sourceLayer, location, kind, name, "A", set.A, cfg.DefaultTTL)
			}
			if set.AAAASet {
				markDNSRecordFamilyOverridden(cfg.DNSRecordEntries, name, "AAAA")
				cfg.LocalAAAA[name] = cloneCSVRecords(set.AAAA, cfg.DefaultTTL)
				cfg.DNSRecordEntries = appendDNSRecordSourceEntries(cfg.DNSRecordEntries, id, sourceLayer, location, kind, name, "AAAA", set.AAAA, cfg.DefaultTTL)
			}
			recordCount += dnsRecordRuleCount(set)
		}
		cfg.DNSRecordSources = append(cfg.DNSRecordSources, DNSRecordSourceState{
			ID:         id,
			Location:   location,
			Kind:       kind,
			NoDataOnly: noDataOnly != 0,
			Domains:    len(parsed.Domains),
			Records:    recordCount,
		})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	sortDNSRecordStates(cfg.DNSRecordEntries)
	return nil
}

func markDNSRecordFamilyOverridden(entries []DNSRecordState, name, typ string) {
	for i := range entries {
		if entries[i].Status == "active" && entries[i].nameKey == name && entries[i].typeKey == typ {
			entries[i].Status = "overridden"
		}
	}
}

func appendDNSRecordSourceEntries(entries []DNSRecordState, sourceID int64, sourceLayer int, location, kind, name, typ string, records []LocalRecord, ttl uint32) []DNSRecordState {
	for _, record := range records {
		value := ""
		if !record.NoData && record.IP != nil {
			value = record.IP.String()
		}
		entries = append(entries, DNSRecordState{
			Name:        name,
			Type:        typ,
			Value:       value,
			TTL:         ttl,
			DefaultTTL:  true,
			Source:      location,
			SourceKind:  kind,
			SourceID:    sourceID,
			Status:      "active",
			Persistent:  false,
			sourceLayer: sourceLayer,
			nameKey:     name,
			typeKey:     typ,
		})
	}
	return entries
}

func sortDNSRecordStates(entries []DNSRecordState) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].nameKey != entries[j].nameKey {
			return entries[i].nameKey < entries[j].nameKey
		}
		if entries[i].typeKey != entries[j].typeKey {
			return entries[i].typeKey < entries[j].typeKey
		}
		if entries[i].sourceLayer != entries[j].sourceLayer {
			return entries[i].sourceLayer < entries[j].sourceLayer
		}
		if entries[i].ID != entries[j].ID {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].Value < entries[j].Value
	})
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

func validateDNSRecordSource(ctx context.Context, location string, noDataOnly bool) error {
	body, _, err := openDNSRecordSource(ctx, location, newDNSRecordSourceClient())
	if err != nil {
		return err
	}
	_, parseErr := parseDNSRecordsCSV(body, noDataOnly)
	closeErr := body.Close()
	if parseErr != nil {
		return parseErr
	}
	return closeErr
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
	if err := validateDNSRecordSource(r.Context(), location, noDataOnly); err != nil {
		renderError(w, http.StatusBadRequest, fmt.Errorf("validate DNS-record source: %w", err))
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
	if err := validateDNSRecordSource(r.Context(), old.Location, noDataOnly); err != nil {
		renderError(w, http.StatusBadRequest, fmt.Errorf("validate DNS-record source: %w", err))
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

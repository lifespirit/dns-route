package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// SpecialDomainMatcher is an immutable-at-runtime suffix matcher. A normal
// entry such as example.com preserves the historic behavior and matches both
// the apex and every subdomain. A wildcard entry such as *.example.com matches
// subdomains only and deliberately excludes the apex.
type SpecialDomainMatcher struct {
	domains   map[string]struct{}
	wildcards map[string]struct{}
}

func newSpecialDomainMatcher() *SpecialDomainMatcher {
	return &SpecialDomainMatcher{
		domains:   make(map[string]struct{}),
		wildcards: make(map[string]struct{}),
	}
}

func (m *SpecialDomainMatcher) Add(pattern string) {
	if m == nil {
		return
	}
	if strings.HasPrefix(pattern, "*.") {
		m.wildcards[strings.TrimPrefix(pattern, "*.")] = struct{}{}
		return
	}
	m.domains[pattern] = struct{}{}
}

func (m *SpecialDomainMatcher) Match(name string) bool {
	if m == nil {
		return false
	}
	name = normalizeName(name)
	if name == "" {
		return false
	}
	if _, ok := m.domains[name]; ok {
		return true
	}
	for offset := strings.IndexByte(name, '.'); offset >= 0; {
		suffix := name[offset+1:]
		if _, ok := m.domains[suffix]; ok {
			return true
		}
		if _, ok := m.wildcards[suffix]; ok {
			return true
		}
		next := strings.IndexByte(name[offset+1:], '.')
		if next < 0 {
			break
		}
		offset += next + 1
	}
	return false
}

type SpecialDomainSourceState struct {
	ID       int64
	Location string
	Kind     string
	Loaded   bool
	Patterns int
}

type SpecialDomainSourceSnapshot struct {
	State    SpecialDomainSourceState
	Patterns []string
}

type specialDomainCSV struct {
	Patterns []string
}

func normalizeSpecialDomainPattern(value string) (string, error) {
	value = normalizeName(value)
	if value == "" {
		return "", fmt.Errorf("special-domain pattern cannot be empty")
	}
	wildcard := strings.HasPrefix(value, "*.")
	base := value
	if wildcard {
		base = strings.TrimPrefix(value, "*.")
	}
	if base == "" || strings.Contains(base, "*") || strings.ContainsAny(base, " \t\r\n,/") {
		return "", fmt.Errorf("invalid special-domain pattern %q", value)
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(base)); !ok {
		return "", fmt.Errorf("invalid special-domain pattern %q", value)
	}
	if wildcard {
		return "*." + base, nil
	}
	return base, nil
}

func parseSpecialDomainsCSV(r io.Reader) (*specialDomainCSV, error) {
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

	seen := make(map[string]struct{})
	var patterns []string
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
		allEmpty := true
		for _, field := range record {
			if field != "" {
				allEmpty = false
				break
			}
		}
		if allEmpty {
			continue
		}
		if strings.HasPrefix(record[0], "#") || strings.HasPrefix(record[0], ";") {
			continue
		}
		if strings.EqualFold(record[0], "domain") || strings.EqualFold(record[0], "pattern") {
			if len(record) == 1 || allFieldsEmpty(record[1:]) {
				continue
			}
		}
		if len(record) > 1 && !allFieldsEmpty(record[1:]) {
			return nil, fmt.Errorf("CSV line %d: expected one domain-pattern column", line)
		}
		pattern, err := normalizeSpecialDomainPattern(record[0])
		if err != nil {
			return nil, fmt.Errorf("CSV line %d: %w", line, err)
		}
		if _, ok := seen[pattern]; ok {
			continue
		}
		seen[pattern] = struct{}{}
		patterns = append(patterns, pattern)
	}
	if len(patterns) == 0 {
		return nil, fmt.Errorf("CSV contains no special domains")
	}
	sort.Strings(patterns)
	return &specialDomainCSV{Patterns: patterns}, nil
}

func allFieldsEmpty(fields []string) bool {
	for _, field := range fields {
		if strings.TrimSpace(field) != "" {
			return false
		}
	}
	return true
}

func importSpecialDomains(db *sql.DB, parsed *specialDomainCSV) error {
	if parsed == nil || len(parsed.Patterns) == 0 {
		return fmt.Errorf("empty special-domain import")
	}
	return withSQLiteWriteTx(context.Background(), db, func(conn *sql.Conn) error {
		stmt, err := conn.PrepareContext(context.Background(), `INSERT INTO special_domains(domain, enabled) VALUES(?, 1) ON CONFLICT(domain) DO UPDATE SET enabled = 1`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, pattern := range parsed.Patterns {
			if _, err := stmt.ExecContext(context.Background(), pattern); err != nil {
				return err
			}
		}
		return nil
	})
}

func exportSpecialDomainsCSV(db *sql.DB, w io.Writer) error {
	rows, err := db.Query(`SELECT domain FROM special_domains WHERE enabled = 1 ORDER BY domain`)
	if err != nil {
		return err
	}
	defer rows.Close()
	writer := csv.NewWriter(w)
	for rows.Next() {
		var pattern string
		if err := rows.Scan(&pattern); err != nil {
			return err
		}
		pattern, err = normalizeSpecialDomainPattern(pattern)
		if err != nil {
			continue
		}
		if err := writer.Write([]string{pattern}); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	writer.Flush()
	return writer.Error()
}

type specialDomainSourceDBRow struct {
	ID       int64
	Location string
	Enabled  int
}

func readEnabledSpecialDomainSources(db *sql.DB) ([]specialDomainSourceDBRow, error) {
	rows, err := db.Query(`SELECT id, location, enabled FROM special_domain_sources WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []specialDomainSourceDBRow
	for rows.Next() {
		var source specialDomainSourceDBRow
		if err := rows.Scan(&source.ID, &source.Location, &source.Enabled); err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sources, nil
}

func fetchSpecialDomainSources(ctx context.Context, db *sql.DB, client *http.Client) ([]SpecialDomainSourceSnapshot, error) {
	sources, err := readEnabledSpecialDomainSources(db)
	if err != nil {
		return nil, err
	}
	snapshots := make([]SpecialDomainSourceSnapshot, 0, len(sources))
	for _, source := range sources {
		location := strings.TrimSpace(source.Location)
		body, kind, err := openDNSRecordSource(ctx, location, client)
		if err != nil {
			return nil, fmt.Errorf("load special-domain source %q: %w", location, err)
		}
		parsed, parseErr := parseSpecialDomainsCSV(body)
		closeErr := body.Close()
		if parseErr != nil {
			return nil, fmt.Errorf("parse special-domain source %q: %w", location, parseErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close special-domain source %q: %w", location, closeErr)
		}
		snapshots = append(snapshots, SpecialDomainSourceSnapshot{
			State: SpecialDomainSourceState{
				ID:       source.ID,
				Location: location,
				Kind:     kind,
				Loaded:   true,
				Patterns: len(parsed.Patterns),
			},
			Patterns: parsed.Patterns,
		})
	}
	return snapshots, nil
}

func applySpecialDomainSources(db *sql.DB, cfg *Config, snapshots []SpecialDomainSourceSnapshot) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	if cfg.SpecialDomains == nil {
		cfg.SpecialDomains = make(map[string]struct{})
	}
	if cfg.SpecialDomainMatcher == nil {
		cfg.SpecialDomainMatcher = newSpecialDomainMatcher()
	}
	cfg.SpecialDomainSources = nil
	cfg.SpecialDomainSourceSnapshots = nil

	configured, err := readEnabledSpecialDomainSources(db)
	if err != nil {
		return err
	}
	byID := make(map[int64]SpecialDomainSourceSnapshot, len(snapshots))
	for _, snapshot := range snapshots {
		byID[snapshot.State.ID] = snapshot
	}
	for _, source := range configured {
		location := strings.TrimSpace(source.Location)
		state := SpecialDomainSourceState{ID: source.ID, Location: location, Kind: dnsRecordSourceKind(location)}
		snapshot, loaded := byID[source.ID]
		if loaded && snapshot.State.Location != location {
			loaded = false
		}
		if !loaded {
			cfg.SpecialDomainSources = append(cfg.SpecialDomainSources, state)
			continue
		}
		state = snapshot.State
		state.Loaded = true
		snapshot.State = state
		for _, pattern := range snapshot.Patterns {
			cfg.SpecialDomains[pattern] = struct{}{}
			cfg.SpecialDomainMatcher.Add(pattern)
		}
		cfg.SpecialDomainSources = append(cfg.SpecialDomainSources, state)
		cfg.SpecialDomainSourceSnapshots = append(cfg.SpecialDomainSourceSnapshots, snapshot)
	}
	return nil
}

func getSpecialDomainSourceByID(db *sql.DB, id int64) (specialDomainSourceDBRow, error) {
	var row specialDomainSourceDBRow
	err := db.QueryRow(`SELECT id, location, enabled FROM special_domain_sources WHERE id = ?`, id).Scan(&row.ID, &row.Location, &row.Enabled)
	return row, err
}

func restoreSpecialDomainSource(db *sql.DB, old specialDomainSourceDBRow, existed bool, location string) {
	if existed {
		_, _ = db.Exec(`INSERT INTO special_domain_sources(id, location, enabled) VALUES(?, ?, ?) ON CONFLICT(id) DO UPDATE SET location=excluded.location, enabled=excluded.enabled`, old.ID, old.Location, old.Enabled)
		return
	}
	_, _ = db.Exec(`DELETE FROM special_domain_sources WHERE location = ?`, location)
}

func (a *App) handleSpecialImport(w http.ResponseWriter, r *http.Request) {
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
	parsed, err := parseSpecialDomainsCSV(file)
	if err != nil {
		renderError(w, http.StatusBadRequest, err)
		return
	}
	if err := importSpecialDomains(a.db, parsed); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	redirectAdmin(w, r, "/special-domains")
}

func (a *App) handleSpecialExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		renderError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="special-domains.csv"`)
	if r.Method == http.MethodHead {
		return
	}
	if err := exportSpecialDomainsCSV(a.db, w); err != nil {
		logHTTPStreamError("export special domains", err)
	}
}

func (a *App) handleSpecialSourceAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	location := strings.TrimSpace(r.FormValue("location"))
	if err := validateDNSRecordSourceLocation(location); err != nil {
		renderError(w, http.StatusBadRequest, fmt.Errorf("validate special-domain source location: %w", err))
		return
	}
	var old specialDomainSourceDBRow
	err := a.db.QueryRow(`SELECT id, location, enabled FROM special_domain_sources WHERE location = ?`, location).Scan(&old.ID, &old.Location, &old.Enabled)
	existed := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if _, err := a.db.Exec(`INSERT INTO special_domain_sources(location, enabled) VALUES(?, 1) ON CONFLICT(location) DO UPDATE SET enabled = 1`, location); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		restoreSpecialDomainSource(a.db, old, existed, location)
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	redirectAdmin(w, r, "/special-domains")
}

func (a *App) handleSpecialSourceDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		renderError(w, http.StatusBadRequest, fmt.Errorf("invalid id"))
		return
	}
	old, err := getSpecialDomainSourceByID(a.db, id)
	if err != nil {
		renderError(w, http.StatusNotFound, err)
		return
	}
	if _, err := a.db.Exec(`DELETE FROM special_domain_sources WHERE id = ?`, id); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		restoreSpecialDomainSource(a.db, old, true, old.Location)
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	redirectAdmin(w, r, "/special-domains")
}

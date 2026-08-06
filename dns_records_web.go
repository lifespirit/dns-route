package main

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	dnsRecordPageSize       = 20
	dnsRecordSearchMaxBytes = 512
)

// DNSRecordWebSource keeps the parsed, immutable rules of one external source
// for the admin UI. Runtime DNS lookups continue to use Config.LocalA and
// Config.LocalAAAA and never traverse this structure.
type DNSRecordWebRule struct {
	Name string
	Set  DNSRecordRuleSet
}

type DNSRecordWebSource struct {
	State DNSRecordSourceState
	Rules []DNSRecordWebRule
}

// DNSRecordWebIndex is built once during config reload and then treated as
// immutable. Domains is the compact sorted search index. Detailed rows are
// materialized only for the domains displayed on the current admin page.
type DNSRecordWebIndex struct {
	Domains    []string
	Sources    []DNSRecordWebSource
	Persistent map[string][]DNSRecordState
}

type DNSRecordDomainView struct {
	Name    string
	Records []DNSRecordState
}

type DNSRecordPageView struct {
	Domains      []DNSRecordDomainView
	Query        string
	SearchError  string
	Page         int
	TotalPages   int
	TotalDomains int
	HasPrev      bool
	HasNext      bool
	PrevURL      string
	NextURL      string
	ReturnURL    string
}

func newDNSRecordWebIndex() *DNSRecordWebIndex {
	return &DNSRecordWebIndex{
		Persistent: make(map[string][]DNSRecordState),
	}
}

func (idx *DNSRecordWebIndex) addDomain(name string) {
	if idx == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	idx.Domains = append(idx.Domains, name)
}

func (idx *DNSRecordWebIndex) finalize() {
	if idx == nil {
		return
	}
	sort.Strings(idx.Domains)
	if len(idx.Domains) < 2 {
		return
	}
	write := 1
	for read := 1; read < len(idx.Domains); read++ {
		if idx.Domains[read] == idx.Domains[write-1] {
			continue
		}
		idx.Domains[write] = idx.Domains[read]
		write++
	}
	idx.Domains = idx.Domains[:write]
}

func (source DNSRecordWebSource) ruleForDomain(name string) (DNSRecordRuleSet, bool) {
	position := sort.Search(len(source.Rules), func(i int) bool {
		return source.Rules[i].Name >= name
	})
	if position >= len(source.Rules) || source.Rules[position].Name != name {
		return DNSRecordRuleSet{}, false
	}
	return source.Rules[position].Set, true
}

func dnsRecordPageURL(query string, page int) string {
	values := url.Values{}
	if strings.TrimSpace(query) != "" {
		values.Set("q", query)
	}
	if page > 1 {
		values.Set("page", strconv.Itoa(page))
	}
	if encoded := values.Encode(); encoded != "" {
		return "/dns-records?" + encoded
	}
	return "/dns-records"
}

func compileDNSRecordSearch(raw string) (func(string) bool, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > dnsRecordSearchMaxBytes {
		return nil, fmt.Errorf("search expression exceeds %d bytes", dnsRecordSearchMaxBytes)
	}
	if raw == "" {
		return func(string) bool { return true }, nil
	}
	if len(raw) >= 2 && strings.HasPrefix(raw, "/") && strings.HasSuffix(raw, "/") {
		expression := raw[1 : len(raw)-1]
		re, err := regexp.Compile(expression)
		if err != nil {
			return nil, fmt.Errorf("invalid regexp: %w", err)
		}
		return re.MatchString, nil
	}
	needle := strings.ToLower(raw)
	return func(name string) bool {
		return strings.Contains(strings.ToLower(name), needle)
	}, nil
}

func (idx *DNSRecordWebIndex) page(rawQuery string, requestedPage int, defaultTTL uint32) DNSRecordPageView {
	view := DNSRecordPageView{
		Query:      rawQuery,
		Page:       requestedPage,
		TotalPages: 1,
	}
	if view.Page < 1 {
		view.Page = 1
	}
	view.ReturnURL = dnsRecordPageURL(rawQuery, view.Page)
	if idx == nil {
		return view
	}

	match, err := compileDNSRecordSearch(rawQuery)
	if err != nil {
		view.SearchError = err.Error()
		return view
	}

	if strings.TrimSpace(rawQuery) == "" {
		view.TotalDomains = len(idx.Domains)
		if view.TotalDomains > 0 {
			view.TotalPages = (view.TotalDomains + dnsRecordPageSize - 1) / dnsRecordPageSize
		}
		if view.Page > view.TotalPages {
			view.Page = view.TotalPages
		}
		start := (view.Page - 1) * dnsRecordPageSize
		end := start + dnsRecordPageSize
		if end > len(idx.Domains) {
			end = len(idx.Domains)
		}
		for _, name := range idx.Domains[start:end] {
			view.Domains = append(view.Domains, DNSRecordDomainView{Name: name, Records: idx.recordsForDomain(name, defaultTTL)})
		}
	} else {
		for _, name := range idx.Domains {
			if match(name) {
				view.TotalDomains++
			}
		}
		if view.TotalDomains > 0 {
			view.TotalPages = (view.TotalDomains + dnsRecordPageSize - 1) / dnsRecordPageSize
		}
		if view.Page > view.TotalPages {
			view.Page = view.TotalPages
		}
		start := (view.Page - 1) * dnsRecordPageSize
		end := start + dnsRecordPageSize
		matched := 0
		for _, name := range idx.Domains {
			if !match(name) {
				continue
			}
			if matched >= start && matched < end {
				view.Domains = append(view.Domains, DNSRecordDomainView{Name: name, Records: idx.recordsForDomain(name, defaultTTL)})
			}
			matched++
			if matched >= end {
				break
			}
		}
	}

	view.HasPrev = view.Page > 1
	view.HasNext = view.Page < view.TotalPages
	if view.HasPrev {
		view.PrevURL = dnsRecordPageURL(rawQuery, view.Page-1)
	}
	if view.HasNext {
		view.NextURL = dnsRecordPageURL(rawQuery, view.Page+1)
	}
	view.ReturnURL = dnsRecordPageURL(rawQuery, view.Page)
	return view
}

func (idx *DNSRecordWebIndex) recordsForDomain(name string, defaultTTL uint32) []DNSRecordState {
	if idx == nil {
		return nil
	}
	persistent := idx.Persistent[name]
	localActive := map[string]bool{}
	out := make([]DNSRecordState, 0, len(persistent)+4)
	for _, record := range persistent {
		out = append(out, record)
		if record.Status == "active" && (record.Type == "A" || record.Type == "AAAA") {
			localActive[record.Type] = true
		}
	}

	lastSource := map[string]int{"A": -1, "AAAA": -1}
	for sourceIndex, source := range idx.Sources {
		set, ok := source.ruleForDomain(name)
		if !ok {
			continue
		}
		if set.ASet {
			lastSource["A"] = sourceIndex
		}
		if set.AAAASet {
			lastSource["AAAA"] = sourceIndex
		}
	}

	for sourceIndex, source := range idx.Sources {
		set, ok := source.ruleForDomain(name)
		if !ok {
			continue
		}
		if set.ASet {
			status := "overridden"
			if !localActive["A"] && lastSource["A"] == sourceIndex {
				status = "active"
			}
			out = appendDNSRecordWebSourceRows(out, source.State, name, "A", set.A, defaultTTL, status)
		}
		if set.AAAASet {
			status := "overridden"
			if !localActive["AAAA"] && lastSource["AAAA"] == sourceIndex {
				status = "active"
			}
			out = appendDNSRecordWebSourceRows(out, source.State, name, "AAAA", set.AAAA, defaultTTL, status)
		}
	}
	return out
}

func appendDNSRecordWebSourceRows(out []DNSRecordState, source DNSRecordSourceState, name, typ string, records []LocalRecord, defaultTTL uint32, status string) []DNSRecordState {
	for _, record := range records {
		value := ""
		if !record.NoData && record.IP != nil {
			value = record.IP.String()
		}
		ttl := record.TTL
		defaulted := false
		if ttl == 0 {
			ttl = defaultTTL
			defaulted = true
		}
		out = append(out, DNSRecordState{
			Name:       name,
			Type:       typ,
			Value:      value,
			TTL:        ttl,
			DefaultTTL: defaulted,
			Source:     source.Location,
			SourceKind: source.Kind,
			SourceID:   source.ID,
			Status:     status,
			Persistent: false,
		})
	}
	return out
}

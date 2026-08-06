package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"strconv"
)

const specialDomainPageSize = 20

type SpecialDomainPageView struct {
	Patterns     []string
	Page         int
	TotalPages   int
	TotalDomains int
	HasPrev      bool
	HasNext      bool
	PrevURL      string
	NextURL      string
	ReturnURL    string
}

func specialDomainPageURL(page int) string {
	if page <= 1 {
		return "/special-domains"
	}
	values := url.Values{}
	values.Set("page", strconv.Itoa(page))
	return "/special-domains?" + values.Encode()
}

func loadSpecialDomainPage(db *sql.DB, requestedPage int) (SpecialDomainPageView, error) {
	view := SpecialDomainPageView{
		Page:       requestedPage,
		TotalPages: 1,
	}
	if view.Page < 1 {
		view.Page = 1
	}
	if db == nil {
		view.ReturnURL = specialDomainPageURL(view.Page)
		return view, nil
	}

	if err := db.QueryRow(`SELECT COUNT(*) FROM special_domains WHERE enabled = 1`).Scan(&view.TotalDomains); err != nil {
		return SpecialDomainPageView{}, fmt.Errorf("count special domains: %w", err)
	}
	if view.TotalDomains > 0 {
		view.TotalPages = (view.TotalDomains + specialDomainPageSize - 1) / specialDomainPageSize
	}
	if view.Page > view.TotalPages {
		view.Page = view.TotalPages
	}

	offset := (view.Page - 1) * specialDomainPageSize
	rows, err := db.Query(`SELECT domain FROM special_domains WHERE enabled = 1 ORDER BY domain LIMIT ? OFFSET ?`, specialDomainPageSize, offset)
	if err != nil {
		return SpecialDomainPageView{}, fmt.Errorf("list special domains: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var pattern string
		if err := rows.Scan(&pattern); err != nil {
			return SpecialDomainPageView{}, fmt.Errorf("scan special domain: %w", err)
		}
		view.Patterns = append(view.Patterns, pattern)
	}
	if err := rows.Err(); err != nil {
		return SpecialDomainPageView{}, fmt.Errorf("iterate special domains: %w", err)
	}

	view.HasPrev = view.Page > 1
	view.HasNext = view.Page < view.TotalPages
	if view.HasPrev {
		view.PrevURL = specialDomainPageURL(view.Page - 1)
	}
	if view.HasNext {
		view.NextURL = specialDomainPageURL(view.Page + 1)
	}
	view.ReturnURL = specialDomainPageURL(view.Page)
	return view, nil
}

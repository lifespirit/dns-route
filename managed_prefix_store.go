package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"time"
)

// ManagedPrefixStore persists the desired BGP Loc-RIB independently from the
// lifetime of the embedded speaker. A speaker can re-announce every learned
// prefix after dns-route restarts.
type ManagedPrefixStore interface {
	Save(ctx context.Context, route RouteIntent) error
	ListEnabled(ctx context.Context) ([]RouteIntent, error)
	Disable(ctx context.Context, prefix netip.Prefix) error
}

type SQLiteManagedPrefixStore struct {
	db *sql.DB
}

func NewSQLiteManagedPrefixStore(db *sql.DB) *SQLiteManagedPrefixStore {
	return &SQLiteManagedPrefixStore{db: db}
}

func (s *SQLiteManagedPrefixStore) Save(ctx context.Context, route RouteIntent) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("managed prefix store is not configured")
	}
	route, err := validateRouteIntent(route)
	if err != nil {
		return err
	}

	family := 6
	if route.Prefix.Addr().Is4() {
		family = 4
	}
	now := time.Now().Unix()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO managed_prefixes(prefix, family, resolved_by, first_seen, last_seen, enabled)
		VALUES(?, ?, ?, ?, ?, 1)
		ON CONFLICT(prefix) DO UPDATE SET
			family = excluded.family,
			resolved_by = excluded.resolved_by,
			last_seen = excluded.last_seen,
			enabled = 1
	`, route.Prefix.String(), family, string(route.ResolvedBy), now, now)
	if err != nil {
		return fmt.Errorf("save managed prefix %s: %w", route.Prefix, err)
	}
	return nil
}

func (s *SQLiteManagedPrefixStore) ListEnabled(ctx context.Context) ([]RouteIntent, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("managed prefix store is not configured")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT prefix, resolved_by
		FROM managed_prefixes
		WHERE enabled = 1
		ORDER BY family, prefix
	`)
	if err != nil {
		return nil, fmt.Errorf("list managed prefixes: %w", err)
	}
	defer rows.Close()

	var routes []RouteIntent
	for rows.Next() {
		var prefixText, sourceText string
		if err := rows.Scan(&prefixText, &sourceText); err != nil {
			return nil, fmt.Errorf("scan managed prefix: %w", err)
		}
		prefix, err := netip.ParsePrefix(prefixText)
		if err != nil {
			return nil, fmt.Errorf("parse stored managed prefix %q: %w", prefixText, err)
		}
		prefix = prefix.Masked()
		route, err := validateRouteIntent(RouteIntent{
			IP:         prefix.Addr(),
			Prefix:     prefix,
			ResolvedBy: PrefixSource(sourceText),
		})
		if err != nil {
			return nil, fmt.Errorf("validate stored managed prefix %q: %w", prefixText, err)
		}
		routes = append(routes, route)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate managed prefixes: %w", err)
	}
	return routes, nil
}

func (s *SQLiteManagedPrefixStore) Disable(ctx context.Context, prefix netip.Prefix) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("managed prefix store is not configured")
	}
	if !prefix.IsValid() {
		return fmt.Errorf("invalid managed prefix %q", prefix)
	}
	prefix = prefix.Masked()
	if _, err := s.db.ExecContext(ctx, `UPDATE managed_prefixes SET enabled = 0 WHERE prefix = ?`, prefix.String()); err != nil {
		return fmt.Errorf("disable managed prefix %s: %w", prefix, err)
	}
	return nil
}

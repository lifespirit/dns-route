package main

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestApplyConfigMutationRollsBackExactPreviousState(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "config.db")
	db, err := sql.Open("sqlite", sqliteDSN(dbPath))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := initDB(db); err != nil {
		t.Fatalf("init db: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO upstreams(addr, proto, enabled, priority) VALUES('192.0.2.53:53', 'udp', 1, 100)`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	cfg, err := loadConfigFromDBWithCachedSources(db, nil, nil)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	app := &App{db: db, ctx: ctx, cancel: cancel, cfg: cfg}

	err = app.applyConfigMutation(ctx, func(conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx, `UPDATE upstreams SET proto = 'tls' WHERE addr = '192.0.2.53:53'`); err != nil {
			return err
		}
		_, err := conn.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES('route_table', 'invalid')`)
		return err
	})
	if err == nil {
		t.Fatal("invalid candidate config unexpectedly committed")
	}

	var proto string
	if err := db.QueryRow(`SELECT proto FROM upstreams WHERE addr = '192.0.2.53:53'`).Scan(&proto); err != nil {
		t.Fatalf("read upstream after rollback: %v", err)
	}
	if proto != "udp" {
		t.Fatalf("upstream proto=%q, want previous value udp", proto)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM settings WHERE key = 'route_table'`).Scan(&count); err != nil {
		t.Fatalf("read setting after rollback: %v", err)
	}
	if count != 0 {
		t.Fatalf("invalid route_table setting persisted: count=%d", count)
	}
	if got := app.getConfig().UpstreamProto["192.0.2.53:53"]; got != "udp" {
		t.Fatalf("runtime upstream proto=%q, want udp", got)
	}
}

func TestApplyConfigMutationRollsBackWhenBackendActivationFails(t *testing.T) {
	original := newConfiguredBGPSpeaker
	wantErr := errors.New("speaker unavailable")
	newConfiguredBGPSpeaker = func(context.Context, GoBGPSpeakerConfig) (BGPSpeaker, error) {
		return nil, wantErr
	}
	t.Cleanup(func() { newConfiguredBGPSpeaker = original })

	dbPath := filepath.Join(t.TempDir(), "activation.db")
	db, err := sql.Open("sqlite", sqliteDSN(dbPath))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := initDB(db); err != nil {
		t.Fatalf("init db: %v", err)
	}
	cfg, err := loadConfigFromDBWithCachedSources(db, nil, nil)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	app := &App{db: db, ctx: ctx, cancel: cancel, cfg: cfg}
	routeMgr, err := NewRouteManager(app, 1)
	if err != nil {
		t.Fatalf("new route manager: %v", err)
	}
	app.routeMgr = routeMgr
	t.Cleanup(func() { _ = routeMgr.Close() })

	settings := map[string]string{
		"route_mode":        "bgp",
		"route_ipv4":        "1",
		"route_ipv6":        "0",
		"bgp_local_asn":     "65001",
		"bgp_router_id":     "192.0.2.1",
		"bgp_peer_address":  "192.0.2.2",
		"bgp_peer_asn":      "65002",
		"bgp_local_address": "192.0.2.1",
		"bgp_next_hop_v4":   "192.0.2.1",
		"bgp_multihop_ttl":  "1",
	}
	err = app.applyConfigMutation(ctx, func(conn *sql.Conn) error {
		for key, value := range settings {
			if _, err := conn.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?, ?)`, key, value); err != nil {
				return err
			}
		}
		return nil
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("activation error=%v, want %v", err, wantErr)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM settings WHERE key = 'route_mode'`).Scan(&count); err != nil {
		t.Fatalf("read route_mode after rollback: %v", err)
	}
	if count != 0 {
		t.Fatalf("route_mode persisted after activation failure: count=%d", count)
	}
	if app.getConfig().RouteMode != RouteModeKernel {
		t.Fatalf("runtime mode=%q, want kernel", app.getConfig().RouteMode)
	}
	if backendByName(routeMgr.backends, KernelRouteBackendName) == nil {
		t.Fatal("original kernel backend was not retained")
	}
}

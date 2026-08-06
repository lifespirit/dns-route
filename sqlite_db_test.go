package main

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestSQLiteDSNAppliesBusySafeguards(t *testing.T) {
	dsn := sqliteDSN(filepath.Join(t.TempDir(), "config db.sqlite"))
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "file" {
		t.Fatalf("scheme = %q in %q", parsed.Scheme, dsn)
	}
	query := parsed.Query()
	if got := query.Get("_txlock"); got != "immediate" {
		t.Fatalf("_txlock = %q", got)
	}
	pragmas := query["_pragma"]
	joined := strings.Join(pragmas, " ")
	if !strings.Contains(joined, "busy_timeout(10000)") {
		t.Fatalf("busy_timeout missing from %#v", pragmas)
	}
	if !strings.Contains(joined, "journal_mode(WAL)") {
		t.Fatalf("journal_mode missing from %#v", pragmas)
	}
}

func TestWithSQLiteWriteTxRollsBackCallbackError(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "rollback.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE items(value INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("stop import")
	err = withSQLiteWriteTx(context.Background(), db, func(conn *sql.Conn) error {
		if _, err := conn.ExecContext(context.Background(), `INSERT INTO items(value) VALUES(1)`); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("transaction error = %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT count(*) FROM items`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rows after rollback = %d", count)
	}
	if err := withSQLiteWriteTx(context.Background(), db, func(conn *sql.Conn) error {
		_, err := conn.ExecContext(context.Background(), `INSERT INTO items(value) VALUES(2)`)
		return err
	}); err != nil {
		t.Fatalf("next write after rollback: %v", err)
	}
}

func TestWithSQLiteWriteTxCleansConnectionAfterBusyCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "busy.db")
	writer, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	writer.SetMaxOpenConns(1)
	writer.SetMaxIdleConns(1)
	reader, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	reader.SetMaxOpenConns(1)
	reader.SetMaxIdleConns(1)

	if _, err := writer.Exec(`PRAGMA journal_mode=DELETE`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(`PRAGMA busy_timeout=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Exec(`PRAGMA busy_timeout=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(`CREATE TABLE items(value INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(`INSERT INTO items(value) VALUES(0)`); err != nil {
		t.Fatal(err)
	}

	rows, err := reader.Query(`SELECT value FROM items`)
	if err != nil {
		t.Fatal(err)
	}
	if !rows.Next() {
		rows.Close()
		t.Fatal("reader returned no row")
	}

	err = withSQLiteWriteTx(context.Background(), writer, func(conn *sql.Conn) error {
		_, err := conn.ExecContext(context.Background(), `UPDATE items SET value = 1`)
		return err
	})
	if err == nil {
		rows.Close()
		t.Skip("SQLite build allowed the commit while the reader was open")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "busy") && !strings.Contains(strings.ToLower(err.Error()), "locked") {
		rows.Close()
		t.Fatalf("expected busy commit, got %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}

	if err := withSQLiteWriteTx(context.Background(), writer, func(conn *sql.Conn) error {
		_, err := conn.ExecContext(context.Background(), `UPDATE items SET value = 2`)
		return err
	}); err != nil {
		t.Fatalf("write after busy commit cleanup: %v", err)
	}
	var value int
	if err := writer.QueryRow(`SELECT value FROM items`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != 2 {
		t.Fatalf("value = %d", value)
	}
}

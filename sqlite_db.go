package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	sqliteBusyTimeoutMS = 10_000
	sqliteRollbackLimit = 5 * time.Second
)

// sqliteDSN applies connection-local SQLite safeguards to every connection
// opened by database/sql. WAL allows readers and the single writer to make
// progress concurrently, busy_timeout waits for short lock conflicts, and
// immediate transactions acquire the write reservation at BEGIN instead of
// unexpectedly failing halfway through a write transaction.
func sqliteDSN(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if path == ":memory:" {
		path = "file::memory:?cache=shared"
	} else if !strings.HasPrefix(strings.ToLower(path), "file:") {
		escaped := url.PathEscape(path)
		escaped = strings.ReplaceAll(escaped, "%2F", "/")
		path = "file:" + escaped
	}

	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	params := []string{
		"_pragma=" + url.QueryEscape(fmt.Sprintf("busy_timeout(%d)", sqliteBusyTimeoutMS)),
		"_pragma=" + url.QueryEscape("journal_mode(WAL)"),
		"_txlock=immediate",
	}
	return path + separator + strings.Join(params, "&")
}

// withSQLiteWriteTx deliberately uses SQL BEGIN/COMMIT on a pinned *sql.Conn
// instead of database/sql's *sql.Tx. Older modernc.org/sqlite releases could
// return SQLITE_BUSY from Commit while leaving the underlying connection inside
// the transaction. An explicit rollback on the same connection guarantees that
// a failed admin operation cannot poison the connection when it returns to the
// pool.
func withSQLiteWriteTx(ctx context.Context, db *sql.DB, fn func(*sql.Conn) error) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire sqlite connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin sqlite write transaction: %w", err)
	}
	active := true
	defer func() {
		if !active {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(context.Background(), sqliteRollbackLimit)
		defer cancel()
		if _, rollbackErr := conn.ExecContext(rollbackCtx, "ROLLBACK"); rollbackErr != nil && !sqliteNoActiveTransaction(rollbackErr) {
			cleanupErr := fmt.Errorf("rollback sqlite write transaction: %w", rollbackErr)
			if err == nil {
				err = cleanupErr
			} else {
				err = errors.Join(err, cleanupErr)
			}
		}
	}()

	if err := fn(conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("commit sqlite write transaction: %w", err)
	}
	active = false
	return nil
}

func sqliteNoActiveTransaction(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no transaction is active") ||
		strings.Contains(message, "cannot rollback") && strings.Contains(message, "no transaction")
}

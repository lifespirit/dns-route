package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
)

type storedPrefixRow struct {
	prefix  string
	family  int64
	source  string
	enabled bool
}

type prefixStoreDriver struct {
	mu   sync.Mutex
	rows map[string]storedPrefixRow
}

func (d *prefixStoreDriver) Open(string) (driver.Conn, error) {
	return &prefixStoreConn{driver: d}, nil
}

type prefixStoreConn struct {
	driver *prefixStoreDriver
}

func (c *prefixStoreConn) Prepare(string) (driver.Stmt, error) {
	return nil, driver.ErrSkip
}
func (c *prefixStoreConn) Close() error              { return nil }
func (c *prefixStoreConn) Begin() (driver.Tx, error) { return nil, driver.ErrSkip }

func (c *prefixStoreConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.driver.mu.Lock()
	defer c.driver.mu.Unlock()

	switch {
	case strings.Contains(query, "INSERT INTO managed_prefixes"):
		if len(args) != 5 {
			return nil, fmt.Errorf("insert args = %d", len(args))
		}
		prefix, _ := args[0].Value.(string)
		family, _ := args[1].Value.(int64)
		source, _ := args[2].Value.(string)
		c.driver.rows[prefix] = storedPrefixRow{
			prefix:  prefix,
			family:  family,
			source:  source,
			enabled: true,
		}
		return driver.RowsAffected(1), nil
	case strings.Contains(query, "UPDATE managed_prefixes SET enabled = 0"):
		if len(args) != 1 {
			return nil, fmt.Errorf("disable args = %d", len(args))
		}
		prefix, _ := args[0].Value.(string)
		row, ok := c.driver.rows[prefix]
		if ok {
			row.enabled = false
			c.driver.rows[prefix] = row
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
	default:
		return nil, fmt.Errorf("unexpected exec query: %s", query)
	}
}

func (c *prefixStoreConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(query, "FROM managed_prefixes") {
		return nil, fmt.Errorf("unexpected query: %s", query)
	}
	c.driver.mu.Lock()
	defer c.driver.mu.Unlock()

	rows := make([]storedPrefixRow, 0, len(c.driver.rows))
	for _, row := range c.driver.rows {
		if row.enabled {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].family != rows[j].family {
			return rows[i].family < rows[j].family
		}
		return rows[i].prefix < rows[j].prefix
	})
	return &prefixStoreRows{rows: rows}, nil
}

type prefixStoreRows struct {
	rows []storedPrefixRow
	pos  int
}

func (r *prefixStoreRows) Columns() []string { return []string{"prefix", "resolved_by"} }
func (r *prefixStoreRows) Close() error      { return nil }
func (r *prefixStoreRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.rows) {
		return io.EOF
	}
	row := r.rows[r.pos]
	r.pos++
	dest[0] = row.prefix
	dest[1] = row.source
	return nil
}

func TestSQLiteManagedPrefixStoreSaveListDisable(t *testing.T) {
	drv := &prefixStoreDriver{rows: make(map[string]storedPrefixRow)}
	name := fmt.Sprintf("managed-prefix-test-%p", drv)
	sql.Register(name, drv)
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	defer db.Close()

	store := NewSQLiteManagedPrefixStore(db)
	v4 := bgpTestRoute("192.0.2.0/24", "192.0.2.10")
	v6 := bgpTestRoute("2001:db8::/32", "2001:db8::1")
	if err := store.Save(context.Background(), v6); err != nil {
		t.Fatalf("save IPv6: %v", err)
	}
	if err := store.Save(context.Background(), v4); err != nil {
		t.Fatalf("save IPv4: %v", err)
	}

	routes, err := store.ListEnabled(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("route count = %d", len(routes))
	}
	if routes[0].Prefix != v4.Prefix || routes[1].Prefix != v6.Prefix {
		t.Fatalf("routes = %+v", routes)
	}
	if routes[0].IP != v4.Prefix.Addr() {
		t.Fatalf("restored IP = %s, want network address %s", routes[0].IP, v4.Prefix.Addr())
	}

	if err := store.Disable(context.Background(), netip.MustParsePrefix("192.0.2.99/24")); err != nil {
		t.Fatalf("disable: %v", err)
	}
	routes, err = store.ListEnabled(context.Background())
	if err != nil {
		t.Fatalf("list after disable: %v", err)
	}
	if len(routes) != 1 || routes[0].Prefix != v6.Prefix {
		t.Fatalf("routes after disable = %+v", routes)
	}
}

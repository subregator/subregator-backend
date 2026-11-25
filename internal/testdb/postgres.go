package testdb

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func URL(t testing.TB) string {
	t.Helper()
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TEST_DATABASE_URL required for PostgreSQL integration tests")
	}
	admin, err := sql.Open("pgx", raw)
	if err != nil {
		t.Fatal("open PostgreSQL test connection")
	}
	var token [12]byte
	if _, err = rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	schema := "test_" + hex.EncodeToString(token[:])
	if _, err = admin.ExecContext(context.Background(), "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal("create isolated PostgreSQL test schema:", err)
	}
	t.Cleanup(func() { admin.Exec("DROP SCHEMA " + schema + " CASCADE"); admin.Close() })
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal("invalid test database URL")
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

func Analyze(t testing.TB, dsn string) {
	t.Helper()
	d, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("open test statistics connection")
	}
	defer d.Close()
	if _, err = d.Exec("ANALYZE state,resources,resource_providers,listings,events,polls,check_cache"); err != nil {
		t.Fatal("analyze test fixture:", err)
	}
}

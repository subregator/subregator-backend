package history

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/testdb"
)

func sqliteFixture(t *testing.T, d *DB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.db")
	old, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	ddl, e := os.ReadFile("testdata/sqlite-v1.sql")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = old.Exec(string(ddl)); e != nil {
		t.Fatal(e)
	}
	for _, table := range importTables {
		rows, e := d.sql.Query("SELECT " + columns(table, true) + " FROM " + table.name)
		if e != nil {
			t.Fatal(e)
		}
		quoted := strings.Split(table.columns, ",")
		for i, c := range quoted {
			quoted[i] = `"` + c + `"`
		}
		for rows.Next() {
			values, e := readValues(rows, table)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = old.Exec("INSERT INTO "+table.name+"("+strings.Join(quoted, ",")+") VALUES("+placeholders(len(quoted))+")", values...); e != nil {
				t.Fatal(e)
			}
		}
		if e = rows.Err(); e != nil {
			t.Fatal(e)
		}
		rows.Close()
	}
	if _, e = old.Exec("UPDATE events SET changed_fields='[]' WHERE type='removed'; UPDATE sqlite_sequence SET seq=500 WHERE name='events'; UPDATE sqlite_sequence SET seq=900 WHERE name='polls'"); e != nil {
		t.Fatal(e)
	}
	old.Close()
	os.Chmod(path, 0600)
	return path
}
func TestSQLiteImportPreservesRowsCursorsAndSource(t *testing.T) {
	d, s := setup(t)
	at := time.Now().UTC().Truncate(time.Millisecond)
	first := offer("a", "1.1.1.0/24", 1000, at)
	for i, offers := range [][]catalog.Offer{{first}, {}, {first}} {
		if e := s.Apply("a", offers, nil, at.Add(time.Duration(i)*time.Second)); e != nil {
			t.Fatal(e)
		}
	}
	payload := json.RawMessage(`{"status":"ok","country":"AU"}`)
	if e := d.CachePut(context.Background(), "fixture", payload, at.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	source := sqliteFixture(t, d)
	original, e := os.ReadFile(source)
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(original)
	target, e := Open(testdb.URL(t))
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	report, e := target.ImportSQLite(context.Background(), source)
	if e != nil {
		t.Fatal(e)
	}
	if report.Tables["events"].Count != 3 || report.Tables["listings"].Count != 1 || report.Tables["check_cache"].Count != 1 {
		t.Fatal("missing import rows", report)
	}
	got := events(t, target, Query{})
	if len(got.Items) != 3 || got.Items[2].ID != 3 || got.Items[2].Type != "relisted" {
		t.Fatal("history changed", got)
	}
	listing, e := target.Listing(context.Background(), s.View().Offers[0].ID)
	if e != nil || listing.Appearances != 2 || !listing.Active {
		t.Fatal("listing lifecycle changed", e, listing)
	}
	cached, expires, ok, e := target.CacheGet(context.Background(), "fixture")
	if e != nil || !ok || string(cached) != string(payload) || !expires.Equal(at.Add(time.Hour)) {
		t.Fatal("cache changed", e)
	}
	restored, e := catalog.NewPersistentStore(target, "", []catalog.Provider{provider("a"), provider("b")})
	if e != nil {
		t.Fatal(e)
	}
	if e = restored.Apply("a", nil, nil, at.Add(3*time.Second)); e != nil {
		t.Fatal(e)
	}
	tail := events(t, target, Query{AfterID: 3})
	if len(tail.Items) != 1 || tail.Items[0].ID != 501 {
		t.Fatal("event sequence reused old IDs", tail)
	}
	var pollID int64
	if e = target.sql.QueryRow("SELECT MAX(id) FROM polls").Scan(&pollID); e != nil || pollID != 901 {
		t.Fatal("poll sequence changed", e, pollID)
	}
	again, e := target.ImportSQLite(context.Background(), source)
	if e != nil || !again.AlreadyImported {
		t.Fatal("import not idempotent", e)
	}
	if len(events(t, target, Query{}).Items) != 4 {
		t.Fatal("retry overwrote new history")
	}
	current, e := os.ReadFile(source)
	if e != nil || sha256.Sum256(current) != digest {
		t.Fatal("SQLite source changed", e)
	}
}
func TestSQLiteImportRejectsOccupiedTargetAndRollsBack(t *testing.T) {
	sourceDB, s := setup(t)
	if e := s.Apply("a", []catalog.Offer{offer("a", "1.1.1.0/24", 1000, time.Now())}, nil, time.Now()); e != nil {
		t.Fatal(e)
	}
	source := sqliteFixture(t, sourceDB)
	if _, e := sourceDB.ImportSQLite(context.Background(), source); e == nil {
		t.Fatal("occupied database overwritten")
	}
	target, e := Open(testdb.URL(t))
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	if _, e = target.sql.Exec(`CREATE FUNCTION fail_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rejection'; END $$; CREATE TRIGGER fail_import BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION fail_import()`); e != nil {
		t.Fatal(e)
	}
	if _, e = target.ImportSQLite(context.Background(), source); e == nil {
		t.Fatal("failed import committed")
	}
	for _, table := range importTables {
		var count int
		if e = target.sql.QueryRow("SELECT COUNT(*) FROM " + table.name).Scan(&count); e != nil || count != 0 {
			t.Fatal("partial import published", table.name, count, e)
		}
	}
	target.sql.Exec("DROP TRIGGER fail_import ON events")
	if _, e = target.ImportSQLite(context.Background(), source); e != nil {
		t.Fatal("retry after rollback failed", e)
	}
}
func TestWriterLeaseExcludesAnotherWriterAndMigration(t *testing.T) {
	dsn := testdb.URL(t)
	d, e := Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	if e = d.AcquireWriter(context.Background()); e != nil {
		t.Fatal(e)
	}
	other, e := Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if e = other.AcquireWriter(context.Background()); e == nil {
		t.Fatal("second writer accepted")
	}
	src, store := setup(t)
	if e = store.Apply("a", nil, nil, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = other.ImportSQLite(context.Background(), sqliteFixture(t, src)); e == nil {
		t.Fatal("import accepted with active writer")
	}
	d.Close()
	if e = other.AcquireWriter(context.Background()); e != nil {
		t.Fatal("writer lease not released", e)
	}
}

func TestSQLiteImportUsesBinaryOrderingAcrossCollations(t *testing.T) {
	source, _ := setup(t)
	for _, key := range []string{"a", "A", "rdap_bootstrap_ipv4", "{\"check\":\"registration\"}"} {
		if e := source.CachePut(context.Background(), key, json.RawMessage(`{}`), time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
	}
	path := sqliteFixture(t, source)
	target, e := Open(testdb.URL(t))
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	var exists bool
	if e = target.sql.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_collation WHERE collname='en-US-x-icu')`).Scan(&exists); e != nil {
		t.Fatal(e)
	}
	if !exists {
		t.Skip("en-US ICU collation unavailable")
	}
	if _, e = target.sql.Exec(`ALTER TABLE check_cache ALTER COLUMN key TYPE text COLLATE "en-US-x-icu"`); e != nil {
		t.Fatal(e)
	}
	if _, e = target.ImportSQLite(context.Background(), path); e != nil {
		t.Fatal("collation changed logical-row fingerprint", e)
	}
}
func TestCatalogueTransactionsUseTheWriterLeaseConnection(t *testing.T) {
	dsn := testdb.URL(t)
	d, e := Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = d.AcquireWriter(context.Background()); e != nil {
		t.Fatal(e)
	}
	var pid int
	if e = d.writer.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); e != nil {
		t.Fatal(e)
	}
	statement := fmt.Sprintf(`CREATE FUNCTION check_lease() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF pg_backend_pid()<>%d THEN RAISE EXCEPTION 'transaction bypassed writer lease connection'; END IF; RETURN NEW; END $$; CREATE TRIGGER check_lease BEFORE INSERT OR UPDATE ON state FOR EACH ROW EXECUTE FUNCTION check_lease()`, pid)
	if _, e = d.sql.Exec(statement); e != nil {
		t.Fatal(e)
	}
	state := catalog.State{Version: 1, Offers: []catalog.Offer{}, Sources: []catalog.Source{}}
	if e = d.Save(state, "", time.Now(), true); e != nil {
		t.Fatal("write not fenced by lease connection", e)
	}
	other, e := Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if _, e = other.sql.Exec("SELECT pg_terminate_backend($1)", pid); e != nil {
		t.Fatal(e)
	}
	if e = other.AcquireWriter(context.Background()); e != nil {
		t.Fatal("replacement writer cannot acquire released lease", e)
	}
	if e = d.Save(state, "", time.Now(), true); e == nil {
		t.Fatal("old process committed after losing its lease")
	}
}

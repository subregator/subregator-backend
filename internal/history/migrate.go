package history

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type TableSummary struct {
	Count  int64  `json:"count"`
	SHA256 string `json:"sha256"`
}
type ImportReport struct {
	Tables          map[string]TableSummary `json:"tables"`
	Digest          string                  `json:"digest"`
	AlreadyImported bool                    `json:"already_imported"`
}
type importTable struct {
	name    string
	columns string
	order   string
	flags   map[int]bool
}

var importTables = []importTable{
	{"state", "id,payload,tracking_started", "id", nil},
	{"resources", "id,prefix,family,prefix_length,address_count,start,end", "id", nil},
	{"resource_providers", "resource_id,provider_id,first_seen,last_seen", "resource_id,provider_id", nil},
	{"listings", "id,provider_id,resource_id,first_seen,last_seen,removed_at,appearances,active,payload,hash", "id", map[int]bool{7: true}},
	{"events", "id,listing_id,provider_id,resource_id,next_resource_id,type,observed_at,resource_reappeared,before,after,changed_fields", "id", map[int]bool{7: true}},
	{"polls", "id,provider_id,observed_at,complete,count", "id", map[int]bool{3: true}},
	{"check_cache", "key,payload,expires_at,touched_at", "key", nil},
}

func columns(t importTable, postgres bool) string {
	cols := strings.Split(t.columns, ",")
	for i, c := range cols {
		cols[i] = `"` + c + `"`
		if postgres && t.name == "resources" && c == "prefix" {
			cols[i] += "::text"
		}
	}
	return strings.Join(cols, ",")
}
func readValues(rows *sql.Rows, table importTable) ([]any, error) {
	names := strings.Split(table.columns, ",")
	values := make([]any, len(names))
	pointers := make([]any, len(names))
	for i := range values {
		pointers[i] = &values[i]
	}
	if err := rows.Scan(pointers...); err != nil {
		return nil, err
	}
	for i, v := range values {
		switch v := v.(type) {
		case []byte:
			values[i] = append(make([]byte, 0, len(v)), v...)
		case string:
			switch names[i] {
			case "payload", "before", "after", "changed_fields", "start", "end":
				values[i] = []byte(v)
			}
		case bool:
			if v {
				values[i] = int64(1)
			} else {
				values[i] = int64(0)
			}
		}
	}
	return values, nil
}
func importOrder(t importTable, postgres bool) string {
	if !postgres || t.name == "events" || t.name == "polls" || t.name == "state" {
		return t.order
	}
	fields := strings.Split(t.order, ",")
	for i, field := range fields {
		fields[i] = `"` + field + `" COLLATE "C"`
	}
	return strings.Join(fields, ",")
}
func summarize(ctx context.Context, tx *sql.Tx, t importTable, postgres bool) (TableSummary, error) {
	rows, err := tx.QueryContext(ctx, "SELECT "+columns(t, postgres)+" FROM "+t.name+" ORDER BY "+importOrder(t, postgres))
	if err != nil {
		return TableSummary{}, err
	}
	defer rows.Close()
	h := sha256.New()
	summary := TableSummary{}
	for rows.Next() {
		values, err := readValues(rows, t)
		if err != nil {
			return summary, err
		}
		b, err := json.Marshal(values)
		if err != nil {
			return summary, err
		}
		h.Write(b)
		h.Write([]byte{'\n'})
		summary.Count++
	}
	summary.SHA256 = hex.EncodeToString(h.Sum(nil))
	return summary, rows.Err()
}
func (d *DB) ImportSQLite(ctx context.Context, path string) (ImportReport, error) {
	report := ImportReport{Tables: map[string]TableSummary{}}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return report, err
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.Mode().IsRegular() {
		return report, errors.New("SQLite source must be an existing regular file")
	}
	u := url.URL{Scheme: "file", Path: absolute}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(1)")
	u.RawQuery = q.Encode()
	source, err := sql.Open("sqlite", u.String())
	if err != nil {
		return report, err
	}
	defer source.Close()
	source.SetMaxOpenConns(1)
	old, err := source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return report, err
	}
	defer old.Rollback()
	var version int
	if err = old.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		return report, errors.New("unsupported SQLite schema version")
	}
	var integrity string
	if err = old.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		return report, errors.New("SQLite integrity check failed")
	}
	combined := sha256.New()
	for _, table := range importTables {
		summary, e := summarize(ctx, old, table, false)
		if e != nil {
			return report, fmt.Errorf("read SQLite %s: %w", table.name, e)
		}
		report.Tables[table.name] = summary
		fmt.Fprintf(combined, "%s:%d:%s\n", table.name, summary.Count, summary.SHA256)
	}
	report.Digest = hex.EncodeToString(combined.Sum(nil))
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	var available bool
	if err = tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1,hashtext(current_schema()))", writerLock).Scan(&available); err != nil || !available {
		return report, errors.New("stop the target catalogue writer before migration")
	}
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1,hashtext(current_schema()))", transactionLock); err != nil {
		return report, err
	}
	var prior []byte
	err = tx.QueryRowContext(ctx, "SELECT report FROM sqlite_imports WHERE digest=$1", report.Digest).Scan(&prior)
	if err == nil {
		if err = json.Unmarshal(prior, &report); err != nil {
			return report, err
		}
		report.AlreadyImported = true
		return report, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return report, err
	}
	for _, table := range importTables {
		var count int64
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table.name).Scan(&count); err != nil {
			return report, err
		}
		if count != 0 {
			return report, errors.New("PostgreSQL target must be empty; existing data will not be overwritten")
		}
	}
	for _, table := range importTables {
		rows, e := old.QueryContext(ctx, "SELECT "+columns(table, false)+" FROM "+table.name+" ORDER BY "+table.order)
		if e != nil {
			return report, e
		}
		colnames := strings.Split(table.columns, ",")
		quoted := make([]string, len(colnames))
		for i, c := range colnames {
			quoted[i] = `"` + c + `"`
		}
		args := []any{}
		groups := []string{}
		flush := func() error {
			if len(groups) == 0 {
				return nil
			}
			_, e := tx.ExecContext(ctx, "INSERT INTO "+table.name+"("+strings.Join(quoted, ",")+") VALUES "+strings.Join(groups, ","), args...)
			args = nil
			groups = nil
			return e
		}
		for rows.Next() {
			values, e := readValues(rows, table)
			if e != nil {
				rows.Close()
				return report, e
			}
			params := make([]string, len(values))
			for i, v := range values {
				if table.flags[i] {
					v = v == int64(1)
				}
				args = append(args, v)
				params[i] = fmt.Sprintf("$%d", len(args))
			}
			groups = append(groups, "("+strings.Join(params, ",")+")")
			if len(groups) == 500 {
				if e = flush(); e != nil {
					rows.Close()
					return report, fmt.Errorf("import %s: %w", table.name, e)
				}
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return report, e
		}
		if e = flush(); e != nil {
			return report, fmt.Errorf("import %s: %w", table.name, e)
		}
		summary, e := summarize(ctx, tx, table, true)
		if e != nil {
			return report, e
		}
		if summary != report.Tables[table.name] {
			return report, fmt.Errorf("verification failed for %s", table.name)
		}
	}
	for _, table := range []string{"events", "polls"} {
		var previous sql.NullInt64
		err = old.QueryRowContext(ctx, "SELECT seq FROM sqlite_sequence WHERE name=?", table).Scan(&previous)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return report, err
		}
		var maxID int64
		if err = tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM "+table).Scan(&maxID); err != nil {
			return report, err
		}
		next := max(maxID, previous.Int64) + 1
		if _, err = tx.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ALTER COLUMN id RESTART WITH %d", table, next)); err != nil {
			return report, err
		}
	}
	if _, err = tx.ExecContext(ctx, "ANALYZE state,resources,resource_providers,listings,events,polls,check_cache"); err != nil {
		return report, err
	}
	body, err := json.Marshal(report)
	if err != nil {
		return report, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO sqlite_imports(digest,report) VALUES($1,$2)", report.Digest, body); err != nil {
		return report, err
	}
	if err = tx.Commit(); err != nil {
		return report, err
	}
	return report, nil
}

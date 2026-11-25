package history

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestCacheEvictionPreservesDROPDownloadReservation(t *testing.T) {
	d, _ := setup(t)
	ctx := context.Background()
	expires := time.Now().Add(24 * time.Hour)
	if e := d.CachePut(ctx, "drop:v4", json.RawMessage(`{"next":"tomorrow"}`), expires); e != nil {
		t.Fatal(e)
	}
	_, e := d.sql.ExecContext(ctx, `INSERT INTO check_cache(key,payload,expires_at,touched_at) SELECT 'fixture:'||n,'{}'::bytea,0,$1 FROM generate_series(1,2001) n`, time.Now().Add(time.Hour).UnixMilli())
	if e != nil {
		t.Fatal(e)
	}
	if e = d.CachePut(ctx, "automatic:1.1.1.0/24", json.RawMessage(`{}`), expires); e != nil {
		t.Fatal(e)
	}
	_, _, found, e := d.CacheGet(ctx, "drop:v4")
	if e != nil || !found {
		t.Fatal("cache eviction lost the durable DROP reservation", e)
	}
	var count int
	if e = d.sql.QueryRowContext(ctx, `SELECT count(*) FROM check_cache WHERE key NOT LIKE 'drop:%'`).Scan(&count); e != nil || count != 2000 {
		t.Fatalf("cache is not bounded: %d %v", count, e)
	}
}

func TestDROPReservationSurvivesLegacyCacheEviction(t *testing.T) {
	d, _ := setup(t)
	ctx := context.Background()
	expires := time.Now().Add(24 * time.Hour).Truncate(time.Millisecond)
	payload := []byte(`{"next":"retained"}`)
	if _, err := d.sql.ExecContext(ctx, `INSERT INTO check_cache(key,payload,expires_at,touched_at) VALUES('drop:v4',$1,$2,0)`, payload, expires.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := d.init(ctx); err != nil {
		t.Fatal(err)
	}
	updated := json.RawMessage(`{"next":"updated"}`)
	expires = expires.Add(time.Hour)
	if err := d.CachePut(ctx, "drop:v4", updated, expires); err != nil {
		t.Fatal(err)
	}
	var legacy []byte
	var legacyExpiry int64
	if err := d.sql.QueryRowContext(ctx, `SELECT payload,expires_at FROM check_cache WHERE key='drop:v4'`).Scan(&legacy, &legacyExpiry); err != nil || string(legacy) != string(updated) || legacyExpiry != expires.UnixMilli() {
		t.Fatalf("rollback reader lost current reservation: %s %v", legacy, err)
	}
	payload = updated
	// The rollback version evicts every old cache row, including DROP keys.
	if _, err := d.sql.ExecContext(ctx, `DELETE FROM check_cache`); err != nil {
		t.Fatal(err)
	}
	if err := d.init(ctx); err != nil {
		t.Fatal(err)
	}
	got, expiry, found, err := d.CacheGet(ctx, "drop:v4")
	if err != nil || !found || string(got) != string(payload) || !expiry.Equal(expires) {
		t.Fatalf("rollback lost reservation: %s %v %v %v", got, expiry, found, err)
	}
}

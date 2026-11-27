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
	_, e := d.sql.ExecContext(ctx, `INSERT INTO check_cache(key,payload,expires_at,touched_at) SELECT 'fixture:'||n,'{}'::bytea,0,$1 FROM generate_series(1,50001) n`, time.Now().Add(time.Hour).UnixMilli())
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
	if e = d.sql.QueryRowContext(ctx, `SELECT count(*) FROM check_cache WHERE key NOT LIKE 'drop:%'`).Scan(&count); e != nil || count != 50000 {
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

func TestSourceLimitSurvivesCacheEviction(t *testing.T) {
	d, _ := setup(t)
	ctx := context.Background()
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
	payload, _ := json.Marshal(map[string]any{"until": until})
	if err := d.CachePut(ctx, "source_limit:RIPEstat", payload, until); err != nil {
		t.Fatal(err)
	}
	if _, err := d.sql.ExecContext(ctx, `INSERT INTO check_cache(key,payload,expires_at,touched_at) SELECT 'source-fixture:'||n,'{}'::bytea,0,$1 FROM generate_series(1,50001) n`, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := d.CachePut(ctx, "evict-source-fixture", json.RawMessage(`{}`), until); err != nil {
		t.Fatal(err)
	}
	if err := d.init(ctx); err != nil {
		t.Fatal(err)
	}
	b, expiry, found, err := d.CacheGet(ctx, "source_limit:RIPEstat")
	if err != nil || !found || string(b) != string(payload) || !expiry.Equal(until) {
		t.Fatalf("source quota reservation lost: %s %v %v", b, found, err)
	}
	if err := d.CachePut(ctx, "source_limit:RIPEstat", json.RawMessage(`{}`), until.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	b, _, _, _ = d.CacheGet(ctx, "source_limit:RIPEstat")
	if string(b) != string(payload) {
		t.Fatal("a shorter reservation overwrote a later source limit")
	}
}

func TestCacheRetainsCurrentCatalogueWorkingSet(t *testing.T) {
	d, _ := setup(t)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	if _, err := d.sql.ExecContext(ctx, `INSERT INTO check_cache(key,payload,expires_at,touched_at) SELECT 'catalogue:'||n,'{}'::bytea,$1,$2 FROM generate_series(1,20000) n`, expires.UnixMilli(), time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := d.CachePut(ctx, "latest", json.RawMessage(`{}`), expires); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM check_cache`).Scan(&count); err != nil || count != 20001 {
		t.Fatal("current catalogue working set evicted by another check", count, err)
	}
}

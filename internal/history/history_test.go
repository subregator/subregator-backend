package history

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/subregator/subregator-backend/internal/testdb"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

func provider(id string) catalog.Provider {
	return catalog.Provider{ID: id, Name: id, URL: "https://example.com", Policy: catalog.Policy{Publication: "approved", PrefixVisibility: "full", MinRefreshSeconds: 60}}
}
func offer(id, prefix string, price int64, at time.Time) catalog.Offer {
	return catalog.Offer{ExternalID: "sku", ProviderID: id, Model: "lease", Availability: "available", Resource: catalog.Resource{Family: 4, Prefix: &prefix, PrefixLength: 24, RIR: "APNIC"}, Geography: catalog.Geography{Basis: "provider_geolocation", Country: "AU"}, Quotes: []catalog.Quote{{ID: "monthly", Price: &catalog.Money{Currency: "USD", AmountMinor: price, MinorUnit: 2}, BillingMonths: 1, Taxes: "unknown"}}, URL: "https://example.com/offers/sku", ObservedAt: at}
}
func setup(t *testing.T) (*DB, *catalog.Store) {
	t.Helper()
	d, e := Open(testdb.URL(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.Close() })
	s, e := catalog.NewPersistentStore(d, "", []catalog.Provider{provider("a"), provider("b")})
	if e != nil {
		t.Fatal(e)
	}
	return d, s
}
func events(t *testing.T, d *DB, q Query) EventResult {
	t.Helper()
	if q.Providers == nil {
		q.Providers = []string{"a", "b"}
	}
	if q.Limit == 0 {
		q.Limit = 200
	}
	out, e := d.Events(context.Background(), q)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestListingLifecycleAndCrossProviderIdentity(t *testing.T) {
	d, s := setup(t)
	at := time.Now().UTC().Truncate(time.Millisecond)
	apply := func(id string, rows []catalog.Offer, e error, offset int) {
		t.Helper()
		err := s.Apply(id, rows, e, at.Add(time.Duration(offset)*time.Second))
		if (err != nil) != (e != nil) {
			t.Fatal(err)
		}
	}
	apply("a", []catalog.Offer{offer("a", "1.1.1.0/24", 1000, at)}, nil, 0)
	id := s.View().Offers[0].ID
	apply("a", []catalog.Offer{offer("a", "1.1.1.0/24", 1000, at.Add(time.Second))}, nil, 1)
	if len(events(t, d, Query{}).Items) != 1 {
		t.Fatal("timestamp-only update created change event")
	}
	apply("a", []catalog.Offer{offer("a", "1.1.1.0/24", 1100, at.Add(2*time.Second))}, nil, 2)
	apply("a", nil, errors.New("incomplete provider snapshot"), 3)
	if len(events(t, d, Query{}).Items) != 2 || len(s.View().Offers) != 1 {
		t.Fatal("failure created disappearance")
	}
	apply("a", []catalog.Offer{}, nil, 4)
	apply("a", []catalog.Offer{}, nil, 5)
	listing, e := d.Listing(context.Background(), id)
	if e != nil || listing.Active || listing.RemovedAt == nil || listing.Appearances != 1 {
		t.Fatal(e, listing)
	}
	apply("b", []catalog.Offer{offer("b", "1.1.1.0/24", 1200, at.Add(6*time.Second))}, nil, 6)
	apply("a", []catalog.Offer{offer("a", "1.1.1.0/24", 1100, at.Add(7*time.Second))}, nil, 7)
	out := events(t, d, Query{Resource: "1.1.1.0/24"})
	want := []string{"listed", "changed", "removed", "listed", "relisted"}
	if len(out.Items) != len(want) {
		t.Fatal(len(out.Items))
	}
	for i, event := range out.Items {
		if event.Type != want[i] {
			t.Fatal(i, event.Type)
		}
	}
	if out.Items[0].ResourceID != out.Items[3].ResourceID {
		t.Fatal("same exact prefix not linked across providers")
	}
	if len(out.Items[1].ChangedFields) != 1 || out.Items[1].ChangedFields[0] != "quotes" {
		t.Fatal("quote change missing")
	}
	listing, e = d.Listing(context.Background(), id)
	if e != nil || !listing.Active || listing.Appearances != 2 || listing.RemovedAt != nil {
		t.Fatal(e, listing)
	}
	resources, e := d.Resources(context.Background(), ResourceQuery{Providers: []string{"a", "b"}, Resource: "1.1.1.1", Limit: 10})
	if e != nil || len(resources.Items) != 1 || len(resources.Items[0].ProviderIDs) != 2 {
		t.Fatal(e, resources)
	}
	page := events(t, d, Query{Limit: 2})
	if page.NextAfterID == nil {
		t.Fatal("cursor missing")
	}
	next := events(t, d, Query{Limit: 2, AfterID: *page.NextAfterID})
	if next.Items[0].ID <= page.Items[1].ID {
		t.Fatal("event cursor repeated rows")
	}
}
func TestResourceChangesRetainBothPrefixHistories(t *testing.T) {
	d, s := setup(t)
	at := time.Now().UTC()
	if e := s.Apply("a", []catalog.Offer{offer("a", "1.1.1.0/24", 1000, at)}, nil, at); e != nil {
		t.Fatal(e)
	}
	if e := s.Apply("a", []catalog.Offer{offer("a", "8.8.8.0/24", 1000, at)}, nil, at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	old := events(t, d, Query{Resource: "1.1.1.0/24"})
	new := events(t, d, Query{Resource: "8.8.8.0/24"})
	if len(old.Items) != 2 || len(new.Items) != 1 || new.Items[0].Type != "resource_changed" {
		t.Fatal(old, new)
	}
	if new.Items[0].Before.Resource.Prefix == nil || *new.Items[0].Before.Resource.Prefix != "1.1.1.0/24" {
		t.Fatal("previous resource lost")
	}
}
func TestDatabaseRollbackPreventsPartialPublication(t *testing.T) {
	d, s := setup(t)
	at := time.Now().UTC()
	if e := s.Apply("a", []catalog.Offer{offer("a", "1.1.1.0/24", 1000, at)}, nil, at); e != nil {
		t.Fatal(e)
	}
	before := s.View().Generation
	if _, e := d.sql.Exec(`CREATE FUNCTION reject_event_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test'; END $$; CREATE TRIGGER reject_event BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION reject_event_fn()`); e != nil {
		t.Fatal(e)
	}
	if e := s.Apply("a", []catalog.Offer{offer("a", "8.8.8.0/24", 2000, at)}, nil, at.Add(time.Second)); e == nil {
		t.Fatal("failed transaction accepted")
	}
	if s.View().Generation != before {
		t.Fatal("undurable state published")
	}
	state, found, e := d.Load()
	if e != nil || !found || state.Offers[0].Quotes[0].Price.AmountMinor != 1000 {
		t.Fatal("snapshot not rolled back", e)
	}
	if len(events(t, d, Query{}).Items) != 1 {
		t.Fatal("partial history committed")
	}
}
func TestLegacyMigrationIsIdempotentAndPreservesJSON(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "catalog.json")
	p := []catalog.Provider{provider("a")}
	old, e := catalog.NewStore(legacyPath, p)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Now().UTC()
	old.Apply("a", []catalog.Offer{offer("a", "1.1.1.0/24", 1000, at)}, nil, at)
	before, _ := os.ReadFile(legacyPath)
	dbPath := testdb.URL(t)
	d, e := Open(dbPath)
	if e != nil {
		t.Fatal(e)
	}
	s, e := catalog.NewPersistentStore(d, legacyPath, p)
	if e != nil {
		t.Fatal(e)
	}
	id := s.View().Offers[0].ID
	out := events(t, d, Query{Providers: []string{"a"}})
	if len(out.Items) != 1 || out.Items[0].Type != "baseline" {
		t.Fatal("legacy state fabricated earlier lifecycle")
	}
	d.Close()
	d, e = Open(dbPath)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	s, e = catalog.NewPersistentStore(d, legacyPath, p)
	if e != nil || s.View().Offers[0].ID != id {
		t.Fatal("reload failed", e)
	}
	s.Apply("a", nil, nil, at.Add(time.Second))
	after, _ := os.ReadFile(legacyPath)
	if !bytes.Equal(before, after) {
		t.Fatal("legacy source overwritten")
	}
	if len(events(t, d, Query{Providers: []string{"a"}}).Items) != 2 {
		t.Fatal("baseline duplicated or removal missing")
	}

}
func TestMaskedPrefixesCannotBeCorrelated(t *testing.T) {
	d, e := Open(testdb.URL(t))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	a, b := provider("a"), provider("b")
	b.Policy.PrefixVisibility = "hidden"
	s, e := catalog.NewPersistentStore(d, "", []catalog.Provider{a, b})
	if e != nil {
		t.Fatal(e)
	}
	at := time.Now().UTC()
	for _, id := range []string{"a", "b"} {
		if e = s.Apply(id, []catalog.Offer{offer(id, "1.1.1.0/24", 1000, at)}, nil, at); e != nil {
			t.Fatal(e)
		}
	}
	out := events(t, d, Query{})
	if out.Items[0].ResourceID == out.Items[1].ResourceID {
		t.Fatal("hidden prefix correlated")
	}
	bJSON, _ := json.Marshal(out.Items[1])
	if bytes.Contains(bJSON, []byte("1.1.1.0")) {
		t.Fatal("hidden prefix leaked")
	}
	filtered := events(t, d, Query{Resource: "1.1.1.0/24"})
	if len(filtered.Items) != 1 {
		t.Fatal("hidden listing matched prefix")
	}
}

func TestResourceReappearsWithNewProviderListingID(t *testing.T) {
	d, s := setup(t)
	at := time.Now().UTC()
	first := offer("a", "1.1.1.0/24", 1000, at)
	if e := s.Apply("a", []catalog.Offer{first}, nil, at); e != nil {
		t.Fatal(e)
	}
	if e := s.Apply("a", nil, nil, at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	next := offer("a", "1.1.1.0/24", 1200, at.Add(2*time.Second))
	next.ExternalID = "new-sku"
	if e := s.Apply("a", []catalog.Offer{next}, nil, at.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	out := events(t, d, Query{Resource: "1.1.1.0/24"})
	if len(out.Items) != 3 || !out.Items[2].ResourceReappeared || out.Items[2].ListingID == out.Items[0].ListingID {
		t.Fatal("network reappearance lost when listing ID changed")
	}
	replacement := next
	replacement.ExternalID = "replacement-sku"
	if e := s.Apply("a", []catalog.Offer{replacement}, nil, at.Add(3*time.Second)); e != nil {
		t.Fatal(e)
	}
	out = events(t, d, Query{Resource: "1.1.1.0/24"})
	for _, event := range out.Items[3:] {
		if event.ResourceReappeared {
			t.Fatal("continuous resource presence counted as reappearance")
		}
	}
}

func TestIndexedResourceHistoryPreservesContainmentAndPagination(t *testing.T) {
	d, s := setup(t)
	at := time.Now().UTC()
	first := offer("a", "1.1.1.0/24", 1000, at)
	if e := s.Apply("a", []catalog.Offer{first}, nil, at); e != nil {
		t.Fatal(e)
	}
	prefix := "1.1.1.0/25"
	second := first
	second.Resource.Prefix = &prefix
	second.Resource.PrefixLength = 25
	if e := s.Apply("a", []catalog.Offer{second}, nil, at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if e := s.Apply("b", []catalog.Offer{offer("b", "1.1.1.0/24", 2000, at)}, nil, at); e != nil {
		t.Fatal(e)
	}
	page := events(t, d, Query{Providers: []string{"a"}, Resource: "1.1.1.1", Limit: 1})
	if len(page.Items) != 1 || page.NextAfterID == nil {
		t.Fatal("missing first page", page)
	}
	next := events(t, d, Query{Providers: []string{"a"}, Resource: "1.1.1.1", AfterID: *page.NextAfterID, Limit: 1})
	if len(next.Items) != 1 || next.Items[0].ID <= page.Items[0].ID || next.Items[0].Type != "resource_changed" || next.NextAfterID != nil {
		t.Fatal("duplicate, missing or cross-provider event", next)
	}
	all := events(t, d, Query{Providers: []string{"a"}, Resource: "1.1.1.129/24"})
	if len(all.Items) != 2 {
		t.Fatal("CIDR not canonicalized", all)
	}
	prefix = "2001:4860::/48"
	v6 := first
	v6.Resource = catalog.Resource{Family: 6, Prefix: &prefix, PrefixLength: 48, RIR: "ARIN"}
	if e := s.Apply("a", []catalog.Offer{v6}, nil, at.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	for _, target := range []string{"2001:4860::1", "2001:4860::1/48"} {
		out := events(t, d, Query{Resource: target})
		if len(out.Items) != 1 || out.Items[0].Type != "resource_changed" {
			t.Fatal("IPv6 correlation lost", target, out)
		}
	}
}

func BenchmarkHistoryHotPrefix100000(b *testing.B) {
	dsn := testdb.URL(b)
	d, e := Open(dsn)
	if e != nil {
		b.Fatal(e)
	}
	defer d.Close()
	s, e := catalog.NewPersistentStore(d, "", []catalog.Provider{provider("a")})
	if e != nil {
		b.Fatal(e)
	}
	at := time.Now().UTC()
	if e := s.Apply("a", []catalog.Offer{offer("a", "1.1.1.0/24", 1000, at)}, nil, at); e != nil {
		b.Fatal(e)
	}
	_, e = d.sql.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<99999) INSERT INTO events(listing_id,provider_id,resource_id,next_resource_id,type,observed_at,resource_reappeared,before,after,changed_fields) SELECT e.listing_id,e.provider_id,e.resource_id,e.next_resource_id,e.type,e.observed_at,e.resource_reappeared,e.before,e.after,e.changed_fields FROM events e,n WHERE e.id=1`)
	if e != nil {
		b.Fatal(e)
	}
	testdb.Analyze(b, dsn)
	for _, tc := range []struct {
		name  string
		after int64
		count int
	}{{"first", 0, 50}, {"tail", 99950, 50}, {"empty", 100000, 0}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, e := d.Events(context.Background(), Query{Providers: []string{"a"}, Resource: "1.1.1.0/24", AfterID: tc.after, Limit: 50})
				if e != nil || len(result.Items) != tc.count {
					b.Fatal("incorrect hot-prefix page", e, len(result.Items))
				}
			}
		})
	}
}

func TestHistoryReadersDoNotWaitForUncommittedWriter(t *testing.T) {
	d, s := setup(t)
	at := time.Now().UTC()
	if err := s.Apply("a", []catalog.Offer{offer("a", "1.1.1.0/24", 1000, at)}, nil, at); err != nil {
		t.Fatal(err)
	}
	tx, err := d.sql.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO events(listing_id,provider_id,resource_id,next_resource_id,type,observed_at,before,after,changed_fields) SELECT listing_id,provider_id,resource_id,next_resource_id,'changed',observed_at,before,after,changed_fields FROM events WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := d.Events(ctx, Query{Providers: []string{"a"}, Limit: 50})
	if err != nil || len(result.Items) != 1 {
		t.Fatal("reader blocked or observed uncommitted event", err, len(result.Items))
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	result, err = d.Events(ctx, Query{Providers: []string{"a"}, AfterID: 1, Limit: 50})
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != 2 {
		t.Fatal("committed event missing", err, result)
	}
}

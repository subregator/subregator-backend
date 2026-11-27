package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/subregator/subregator-backend/internal/intelligence"
	"github.com/subregator/subregator-backend/internal/testdb"
)

func archiveFixture(resource, check, state string, at time.Time) intelligence.ArchivedObservation {
	expires := at.Add(time.Hour)
	return intelligence.ArchivedObservation{Resource: resource, Check: check, Source: "fixture", SourceURL: "https://example.com/source", ObservedAt: &at, SourceUpdatedAt: &at, AttemptedAt: at, IngestedAt: at.Add(time.Second), ExpiresAt: &expires, Observation: intelligence.Observation{CollectionStatus: "succeeded", Freshness: "fresh", Completeness: "complete", Scope: intelligence.ObservationScope{Requested: resource, Resource: resource, Kind: "prefix", Relation: "exact"}}, State: json.RawMessage(state), Evidence: json.RawMessage(state), Comparable: true}
}

func TestObservationDurabilityReplayGapsAndOrdering(t *testing.T) {
	ctx := context.Background()
	dsn := testdb.URL(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { d.Close() }()
	at := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Microsecond)
	for _, resource := range []string{"1.1.1.0/24", "2606:4700::/48"} {
		first := archiveFixture(resource, "spamhaus_drop", `"listed"`, at)
		save := func(r intelligence.ArchivedObservation) {
			t.Helper()
			if e := d.SaveObservation(ctx, r); e != nil {
				t.Fatal(e)
			}
		}
		save(first)
		replay := first
		replay.IngestedAt = at.Add(10 * time.Hour)
		save(replay)
		repeat := archiveFixture(resource, "spamhaus_drop", `"listed"`, at.Add(time.Minute))
		save(repeat)
		failed := archiveFixture(resource, "spamhaus_drop", `null`, at.Add(2*time.Minute))
		failed.ObservedAt = nil
		failed.Comparable = false
		failed.Observation.CollectionStatus = "failed"
		save(failed)
		partial := archiveFixture(resource, "spamhaus_drop", `"not_listed"`, at.Add(3*time.Minute))
		partial.Observation.Completeness = "partial"
		save(partial)
		recovered := archiveFixture(resource, "spamhaus_drop", `"not_listed"`, at.Add(4*time.Minute))
		save(recovered)
		late := archiveFixture(resource, "spamhaus_drop", `"listed"`, at.Add(30*time.Second))
		save(late)
		if _, e := d.sql.Exec(`INSERT INTO check_cache SELECT 'eviction-'||g, '{}'::bytea,0,g FROM generate_series(1,50001) g ON CONFLICT DO NOTHING`); e != nil {
			t.Fatal(e)
		}
		if e := d.CachePut(ctx, "newest", json.RawMessage(`{}`), time.Now()); e != nil {
			t.Fatal(e)
		}
		var retained bool
		if e := d.sql.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM check_cache WHERE key='eviction-1')`).Scan(&retained); e != nil || retained {
			t.Fatal("cache fixture did not trigger eviction", retained, e)
		}
		out, e := d.Observations(ctx, resource, 0, 200)
		if e != nil {
			t.Fatal(e)
		}
		if len(out.Items) != 6 {
			t.Fatalf("duplicate replay: %+v", out)
		}
		want := []string{"observation", "observation", "gap", "gap", "delisted", "out_of_order"}
		for i, r := range out.Items {
			if r.Event != want[i] {
				t.Fatalf("%d: %+v", i, r)
			}
		}
		if out.Items[1].FirstSeen == nil || !out.Items[1].FirstSeen.Equal(at) {
			t.Fatal("lost first seen bound")
		}
		event := out.Items[4]
		if !event.Gap || event.PreviousSeen == nil || !event.PreviousSeen.Equal(*repeat.ObservedAt) || event.SourceUpdatedAt == nil || !event.IngestedAt.Equal(recovered.IngestedAt) {
			t.Fatalf("lost bounds/times: %+v", event)
		}
		page, e := d.Observations(ctx, resource, 0, 2)
		if e != nil || page.NextCursor == 0 {
			t.Fatal(e, page)
		}
		next, e := d.Observations(ctx, resource, page.NextCursor, 2)
		if e != nil || len(next.Items) != 2 || next.Items[0].ID <= page.NextCursor {
			t.Fatal(e, next)
		}
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Observations(ctx, "1.1.1.0/24", 0, 200)
	if err != nil || len(out.Items) != 6 {
		t.Fatal(err, out)
	}
}

func TestObservationAtomicityAndUnsafeAbsence(t *testing.T) {
	d, _ := setup(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-24 * time.Hour)
	first := archiveFixture("1.1.1.0/24", "spamhaus_drop", `"listed"`, at)
	if err := d.SaveObservation(ctx, first); err != nil {
		t.Fatal(err)
	}
	for i, status := range []string{"failed", "rate_limited", "access_denied", "no_data"} {
		r := archiveFixture(first.Resource, first.Check, `"not_listed"`, at.Add(time.Duration(i+1)*time.Minute))
		r.Observation.CollectionStatus = status
		if err := d.SaveObservation(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	stale := archiveFixture(first.Resource, first.Check, `"not_listed"`, at.Add(6*time.Minute))
	stale.Observation.Freshness = "stale"
	if err := d.SaveObservation(ctx, stale); err != nil {
		t.Fatal(err)
	}
	ctxCanceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := d.SaveObservation(ctxCanceled, archiveFixture(first.Resource, first.Check, `"not_listed"`, at.Add(7*time.Minute))); err == nil {
		t.Fatal("canceled write succeeded")
	}
	if _, err := d.sql.Exec(`CREATE FUNCTION reject_observation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'interrupted write'; END $$; CREATE TRIGGER reject_observation BEFORE INSERT ON check_observations FOR EACH ROW EXECUTE FUNCTION reject_observation()`); err != nil {
		t.Fatal(err)
	}
	recovery := archiveFixture(first.Resource, first.Check, `"not_listed"`, at.Add(8*time.Minute))
	if err := d.SaveObservation(ctx, recovery); err == nil {
		t.Fatal("interrupted persistence succeeded")
	}
	var count int
	if err := d.sql.QueryRow(`SELECT COUNT(*) FROM check_observations`).Scan(&count); err != nil || count != 6 {
		t.Fatal(err, count)
	}
	if _, err := d.sql.Exec(`DROP TRIGGER reject_observation ON check_observations`); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveObservation(ctx, recovery); err != nil {
		t.Fatal(err)
	}
	out, err := d.Observations(ctx, first.Resource, 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range out.Items[1:6] {
		if r.Event != "gap" {
			t.Fatal("unsafe absence", r)
		}
	}
	if out.Items[6].Event != "delisted" {
		t.Fatal("recovery lost baseline", out)
	}
	for _, check := range []string{"abuse", "irr", "spamhaus_zen"} {
		r := first
		r.Check = check
		if d.SaveObservation(ctx, r) == nil {
			t.Fatal("unapproved history accepted", check)
		}
	}
}

func TestObservationTransitionsAndScopeIsolation(t *testing.T) {
	d, _ := setup(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-24 * time.Hour)
	for check, event := range map[string]string{"prefix_overview": "bgp_origins_changed", "rpki": "rpki_transition", "registration": "registry_changed", "rdap": "registry_changed"} {
		a := archiveFixture("1.1.1.0/24", check, `{"value":"before"}`, at)
		b := archiveFixture(a.Resource, check, `{"value":"after"}`, at.Add(2*time.Hour))
		if check == "rdap" || check == "registration" {
			a.State = json.RawMessage(`[{"name":"before"}]`)
			b.State = json.RawMessage(`[{"name":"after"}]`)
		}
		for _, r := range []intelligence.ArchivedObservation{a, b} {
			if err := d.SaveObservation(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
		b.Observation.Scope.Resource = "1.1.0.0/16"
		b.Observation.Scope.Relation = "covering"
		b.ObservedAt = ptrTime(at.Add(3 * time.Hour))
		b.IngestedAt = at.Add(3 * time.Hour)
		b.ExpiresAt = ptrTime(at.Add(4 * time.Hour))
		b.Evidence = json.RawMessage(`{"value":"other_scope"}`)
		if err := d.SaveObservation(ctx, b); err != nil {
			t.Fatal(err)
		}
		out, err := d.Observations(ctx, a.Resource, 0, 200)
		if err != nil {
			t.Fatal(err)
		}
		var rows []intelligence.ArchivedObservation
		for _, r := range out.Items {
			if r.Check == check {
				rows = append(rows, r)
			}
		}
		if len(rows) != 3 || rows[1].Event != event || !rows[1].Gap || rows[2].Event != "observation" {
			t.Fatal(rows)
		}
	}
}
func ptrTime(t time.Time) *time.Time { return &t }

func TestObservationConflictingReplayCannotReplaceBaseline(t *testing.T) {
	d, _ := setup(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour)
	first := archiveFixture("1.1.1.0/24", "spamhaus_drop", `"listed"`, at)
	conflict := first
	conflict.State = json.RawMessage(`"not_listed"`)
	conflict.Evidence = conflict.State
	next := archiveFixture(first.Resource, first.Check, `"not_listed"`, at.Add(time.Minute))
	for _, r := range []intelligence.ArchivedObservation{first, conflict, next} {
		if err := d.SaveObservation(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	out, err := d.Observations(ctx, first.Resource, 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 3 || out.Items[1].Event != "out_of_order" || out.Items[2].Event != "delisted" || !out.Items[2].Gap || out.Items[2].PreviousSeen == nil || !out.Items[2].PreviousSeen.Equal(at) {
		t.Fatalf("conflicting replay changed baseline: %+v", out.Items)
	}
}

func TestObservationFailedReplayIsIdempotent(t *testing.T) {
	d, _ := setup(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour)
	failed := archiveFixture("1.1.1.0/24", "spamhaus_drop", `null`, at)
	failed.ObservedAt = nil
	failed.Comparable = false
	failed.Observation.CollectionStatus = "failed"
	if err := d.SaveObservation(ctx, failed); err != nil {
		t.Fatal(err)
	}
	failed.IngestedAt = at.Add(20 * time.Minute)
	if err := d.SaveObservation(ctx, failed); err != nil {
		t.Fatal(err)
	}
	out, err := d.Observations(ctx, failed.Resource, 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 1 {
		t.Fatalf("one failed attempt replay created %d rows", len(out.Items))
	}
}

func TestObservationMigrationPreservesVersionOneState(t *testing.T) {
	dsn := testdb.URL(t)
	legacy, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY); INSERT INTO schema_migrations VALUES(1); CREATE TABLE state(id SMALLINT PRIMARY KEY CHECK(id=1),payload BYTEA NOT NULL,tracking_started BIGINT NOT NULL); INSERT INTO state VALUES(1,'{"version":1}',1234)`)
	legacy.Close()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	state, found, err := d.Load()
	if err != nil || !found || state.Version != 1 {
		t.Fatal(err, found, state)
	}
	var version int
	var started int64
	if err = d.sql.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != 2 {
		t.Fatal(err, version)
	}
	if err = d.sql.QueryRow(`SELECT tracking_started FROM state WHERE id=1`).Scan(&started); err != nil || started != 1234 {
		t.Fatal(err, started)
	}
	out, err := d.Observations(context.Background(), "1.1.1.0/24", 0, 1)
	if err != nil || len(out.Items) != 0 {
		t.Fatal("migration invented history", err, out)
	}
}

func TestObservationLegacyRegistryStateUsesSameOrdering(t *testing.T) {
	d, _ := setup(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour)
	a := archiveFixture("1.1.1.0/24", "rdap", `[{"handle":"NET","statuses":["validated","active"],"entities":[],"events":[]}]`, at)
	if err := d.SaveObservation(ctx, a); err != nil {
		t.Fatal(err)
	}
	b := archiveFixture(a.Resource, a.Check, `[{"handle":"NET","statuses":["active","validated"],"entities":[],"events":[]}]`, at.Add(time.Minute))
	if err := d.SaveObservation(ctx, b); err != nil {
		t.Fatal(err)
	}
	out, err := d.Observations(ctx, a.Resource, 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 2 || out.Items[1].Event != "observation" || out.Items[1].FirstSeen == nil || !out.Items[1].FirstSeen.Equal(at) {
		t.Fatalf("legacy ordering caused false registry change: %+v", out)
	}
}

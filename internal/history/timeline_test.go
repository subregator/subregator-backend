package history

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

func TestTimelineStablePagesPolicyAndReplay(t *testing.T) {
	d, s := setup(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	prefix := "1.1.1.0/24"
	if err := s.Apply("a", []catalog.Offer{offer("a", prefix, 100, at)}, nil, at); err != nil {
		t.Fatal(err)
	}
	r := archiveFixture(prefix, "prefix_overview", `{"origins":[13335]}`, at)
	r.IngestedAt = at
	r.ObservedAt = &at
	if err := d.SaveObservation(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Check = "routing_history"
	r.Origin = "imported_history"
	r.Evidence = json.RawMessage(`{"records":[{"resource":"1.1.0.0/16","relation":"covering"}],"completeness":"partial"}`)
	if err := d.SaveObservation(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.IngestedAt = at.Add(time.Hour)
	r.AttemptedAt = at.Add(time.Hour)
	r.ObservedAt = &r.AttemptedAt
	if err := d.SaveObservation(ctx, r); err != nil {
		t.Fatal(err)
	}
	checks := []string{"prefix_overview", "routing_history"}
	first, err := d.Timeline(ctx, prefix, "", 1, []string{"a"}, checks)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 1 || first.NextCursor == "" || first.Items[0].Kind != "listing" || first.TrackingStartedAt == nil || first.ArchiveStartedAt == nil {
		t.Fatalf("%+v", first)
	}
	next, err := d.Timeline(ctx, prefix, first.NextCursor, 1, []string{"a"}, checks)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Items) != 1 || next.Items[0].Kind != "network" || next.Items[0].ID == first.Items[0].ID {
		t.Fatalf("%+v", next)
	}
	final, err := d.Timeline(ctx, prefix, next.NextCursor, 5, []string{"a"}, checks)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Items) != 1 || final.Items[0].Event != "historical_snapshot" || final.NextCursor != "" || final.Items[0].Observation.Origin != "imported_history" {
		t.Fatalf("%+v", final)
	}
	if _, err = d.Timeline(ctx, prefix, first.NextCursor, 1, []string{"a"}, nil); err == nil {
		t.Fatal("cursor survived check policy change")
	}
	if _, err = d.Timeline(ctx, "8.8.8.0/24", first.NextCursor, 1, []string{"a"}, checks); err == nil {
		t.Fatal("cursor crossed prefix")
	}
	hidden, err := d.Timeline(ctx, prefix, "", 5, []string{"b"}, checks)
	if err != nil || len(hidden.Items) != 0 || hidden.TrackingStartedAt != nil {
		t.Fatalf("hidden resource %+v %v", hidden, err)
	}
	disabled, err := d.Timeline(ctx, prefix, "", 5, []string{"a"}, nil)
	if err != nil || len(disabled.Items) != 1 {
		t.Fatalf("disabled archive %+v %v", disabled, err)
	}
	// A later ingestion with an earlier source date belongs to the next snapshot.
	r.Check = "prefix_overview"
	r.Origin = ""
	r.Evidence = json.RawMessage(`{"origins":[64500]}`)
	r.IngestedAt = at.Add(2 * time.Hour)
	if err = d.SaveObservation(ctx, r); err != nil {
		t.Fatal(err)
	}
	frozen, err := d.Timeline(ctx, prefix, first.NextCursor, 10, []string{"a"}, checks)
	if err != nil || len(frozen.Items) != 2 {
		t.Fatalf("snapshot changed %+v %v", frozen, err)
	}
}

func TestTimelinePageReleasesRowsBeforeBoundary(t *testing.T) {
	d, s := setup(t)
	d.sql.SetMaxOpenConns(1)
	at := time.Now().UTC().Add(-time.Minute)
	prefix := "1.1.1.0/24"
	if err := s.Apply("a", []catalog.Offer{offer("a", prefix, 100, at)}, nil, at); err != nil {
		t.Fatal(err)
	}
	r := archiveFixture(prefix, "prefix_overview", `{"origins":[13335]}`, at)
	if err := d.SaveObservation(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	page, err := d.Timeline(ctx, prefix, "", 1, []string{"a"}, []string{"prefix_overview"})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("paged timeline exhausted pool: %v", err)
	}
}

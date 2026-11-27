package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/subregator/subregator-backend/internal/catalog"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHistoricalSnapshotsSanitizedBoundedAndConfigured(t *testing.T) {
	target := Target{Value: "1.1.1.0/24", Kind: "prefix"}
	q := historicalQuery(target.Value, time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC))
	fixtures := map[string]string{
		"routing_history":      `{"query_starttime":"2026-11-20T00:00:00","query_endtime":"2026-11-27T00:00:00","by_origin":[{"origin":"13335","prefixes":[{"prefix":"1.1.0.0/16","timelines":[{"starttime":"2026-11-20T00:00:00","endtime":"2026-11-21T00:00:00"}]}]}]}`,
		"allocation_history":   `{"results":{"RIPE":[{"resource":"1.1.0.0/16","status":"allocated","timelines":[{"starttime":"2020-01-01","endtime":"2026-11-27"}]}]}}`,
		"transfer_history":     `{"transfers":[{"recipientResource":"1.1.0.0/16","transferTime":"2020-01-01T00:00:00","sourceRegistry":"ARIN","recipientRegistry":"RIPE","recipientHolderName":"never-persist"}]}`,
		"registration_history": `{"resource":"1.1.0.0/16","database":"RIPE","num_versions":1,"versions":[{"version":1,"date":"2020-01-01T00:00:00"}],"objects":[{"person":"never-persist","email":"never-persist"}]}`,
	}
	for name, raw := range fixtures {
		snapshot, err := normalizeHistorical(name, json.RawMessage(raw), target, q)
		if err != nil || len(snapshot.Records) != 1 || snapshot.Records[0].Relation != "covering" || snapshot.Completeness != "partial" {
			t.Fatalf("%s %+v %v", name, snapshot, err)
		}
		encoded, _ := json.Marshal(snapshot)
		if strings.Contains(string(encoded), "never-persist") {
			t.Fatal(string(encoded))
		}
	}
	periods := make([]string, 301)
	for i := range periods {
		periods[i] = fmt.Sprintf(`{"recipientResource":"1.1.1.0/24","transferTime":"2020-01-01T00:00:%02d"}`, i%60)
	}
	snapshot, err := normalizeHistorical("transfer_history", json.RawMessage(`{"transfers":[`+strings.Join(periods, ",")+`]}`), target, q)
	if err != nil || !snapshot.Truncated || len(snapshot.Records) > 300 {
		t.Fatal(snapshot, err)
	}
	cache := &recordingArchive{}
	s := New(cache, true, "", 120)
	expiry := time.Now().Add(time.Hour)
	observed := time.Now()
	rawMetric := Metric{Name: "routing_history", Source: "RIPEstat", Status: "ok", ObservedAt: &observed, ExpiresAt: &expiry, Data: json.RawMessage(fixtures["routing_history"])}
	s.archiveHistorical(context.WithValue(context.Background(), automaticBudgetKey{}, true), target, q, rawMetric)
	if len(cache.records) != 0 {
		t.Fatal("disabled history wrote")
	}
	if err = s.SetHistoricalChecks("abuse"); err == nil {
		t.Fatal("unsupported source accepted")
	}
	if err = s.SetHistoryChecks("routing_history"); err == nil {
		t.Fatal("current-check approval silently widened")
	}
	if err = s.SetHistoricalChecks("routing_history"); err != nil {
		t.Fatal(err)
	}
	s.archiveHistorical(context.Background(), target, q, rawMetric)
	if len(cache.records) != 0 {
		t.Fatal("public lookup imported source history")
	}
	s.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("starttime") != q.StartTime || r.URL.Query().Get("endtime") != q.EndTime || r.URL.Query().Get("max_rows") != "300" {
			t.Fatal(r.URL)
		}
		return response(200, `{"status":"ok","data":`+fixtures["routing_history"]+`}`), nil
	})
	m := s.metric(context.WithValue(context.Background(), automaticBudgetKey{}, true), target, q, "routing_history")
	if m.Status != "ok" || len(cache.records) != 1 || cache.records[0].Origin != "imported_history" || cache.records[0].Comparable {
		t.Fatal(m, cache.records)
	}
	failed := rawMetric
	failed.Status = "unavailable"
	failed.Data = json.RawMessage(`{"secret":"never-persist"}`)
	s.archiveHistorical(context.WithValue(context.Background(), automaticBudgetKey{}, true), target, q, failed)
	if len(cache.records) != 2 || cache.records[1].Observation.CollectionStatus != "failed" || string(cache.records[1].Evidence) != "null" {
		t.Fatal("failure did not remain gap", cache.records)
	}
	if _, err = s.Cached(context.Background(), Query{Resource: target.Value, Checks: []string{"routing_history"}, StartTime: q.StartTime, EndTime: q.EndTime}); err != nil || len(cache.records) != 2 {
		t.Fatal("cached read imported", err)
	}
}

func TestHistoricalAutomaticApprovalAndDiagnostics(t *testing.T) {
	cache := &recordingArchive{}
	s := New(cache, true, "", 600)
	provider := catalog.Provider{ID: "fixture", Name: "fixture", URL: "https://example.com", Policy: catalog.Policy{Publication: "approved", PrefixVisibility: "full", MinRefreshSeconds: 60}}
	store, err := catalog.NewStore("", []catalog.Provider{provider})
	if err != nil {
		t.Fatal(err)
	}
	prefix := "2001:4860::/32"
	offer := catalog.Offer{ExternalID: "fixture", ProviderID: "fixture", Model: "lease", Availability: "available", Resource: catalog.Resource{Prefix: &prefix, Family: 6, PrefixLength: 32}, URL: "https://example.com", Geography: catalog.Geography{Basis: "unknown"}, ObservedAt: time.Now()}
	if err = store.Apply("fixture", []catalog.Offer{offer}, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	auto := NewAutomatic(s)
	for _, check := range auto.Status(store).Checks {
		if check.Name == "routing_history" {
			t.Fatal("default enabled history")
		}
	}
	if err = s.SetHistoricalChecks("routing_history"); err != nil {
		t.Fatal(err)
	}
	s.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		return response(200, `{"status":"ok","data":{"by_origin":[],"resource":"2001:4860::/32"}}`), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); auto.Run(ctx, store) }()
	deadline := time.Now().Add(2 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		cache.mu.Lock()
		for _, r := range cache.records {
			found = found || r.Check == "routing_history"
		}
		cache.mu.Unlock()
		if found {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if !found {
		t.Fatal("approved historical queue did not collect")
	}
	statusFound := false
	for _, check := range auto.Status(store).Checks {
		statusFound = statusFound || check.Name == "routing_history"
	}
	if !statusFound {
		t.Fatal("configured queue absent from diagnostics")
	}
}

package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

func TestObservationScopeAndFreshness(t *testing.T) {
	now := time.Now().UTC()
	before, after, future := now.Add(-time.Minute), now.Add(time.Minute), now.Add(time.Hour)
	for _, tc := range []struct {
		name, resource, body, status, fresh, relation, completeness string
		observed, expires                                           *time.Time
	}{
		{"v4 exact", "1.1.1.0/24", `{"resource":"1.1.1.0/24","num_filtered_out":0}`, "ok", "fresh", "exact", "complete", &before, &after},
		{"v6 covering", "2001:4860:4860::/48", `{"resource":"2001:4860::/32","num_filtered_out":0}`, "ok", "fresh", "covering", "complete", &before, &after},
		{"partial", "1.1.1.0/24", `{"resource":"1.1.1.0/24","num_filtered_out":2}`, "ok", "fresh", "exact", "partial", &before, &after},
		{"unrelated", "1.1.1.0/24", `{"resource":"8.8.8.0/24"}`, "ok", "fresh", "unknown", "unknown", &before, &after},
		{"expired", "1.1.1.0/24", `{}`, "ok", "stale", "unknown", "unknown", &before, &now},
		{"retained", "1.1.1.0/24", `{}`, "stale", "stale", "unknown", "unknown", &before, &after},
		{"future timestamp", "1.1.1.0/24", `{}`, "ok", "unknown", "unknown", "unknown", &future, &future},
		{"missing timestamp", "1.1.1.0/24", `{}`, "ok", "unknown", "unknown", "unknown", nil, &after},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, err := ParseTarget(tc.resource)
			if err != nil {
				t.Fatal(err)
			}
			m := Metric{Name: "prefix_overview", Status: tc.status, ObservedAt: tc.observed, ExpiresAt: tc.expires, Data: json.RawMessage(tc.body)}
			o := metricObservation(m, target, Query{}, now)
			if o.Freshness != tc.fresh || o.Scope.Relation != tc.relation || o.Completeness != tc.completeness {
				t.Fatalf("unexpected observation: %+v", o)
			}
		})
	}
	for _, status := range []string{"pending", "disabled", "not_configured", "not_applicable", "no_data", "rate_limited", "unavailable"} {
		o := observation(status, nil, nil, now)
		if o.CollectionStatus == "succeeded" || o.Freshness != "unknown" || o.Completeness != "unknown" {
			t.Fatalf("failure represented as evidence: %+v", o)
		}
	}
	c := Check{Status: "listed", Freshness: "stale", ObservedAt: &before, ExpiresAt: &after}
	if got := checkObservation(c, "1.1.1.0/24", "spamhaus_drop", now); got.Freshness != "stale" || got.Scope.Relation != "overlap" {
		t.Fatalf("retained DROP observation passed: %+v", got)
	}
}

func TestDirectASNRankScope(t *testing.T) {
	now, expires := time.Now().UTC(), time.Now().UTC().Add(time.Minute)
	target, _ := ParseTarget("AS13335")
	m := Metric{Name: "asn_rank", Status: "ok", ObservedAt: &now, ExpiresAt: &expires, Data: json.RawMessage(`{"scope":"autonomous_system","asns":[{"asn":13335,"data":{"asn":"13335"}}]}`)}
	o := metricObservation(m, target, Query{}, now)
	if o.Scope.Relation != "exact" || o.Scope.Resource != "AS13335" {
		t.Fatalf("direct ASN rank was described as origin-derived: %+v", o)
	}
}

func TestCollectionCoverageUsesFinalEvidence(t *testing.T) {
	for _, retained := range []bool{true, false} {
		t.Run(fmt.Sprint("retained=", retained), func(t *testing.T) {
			store := coverageStore(t, 1)
			a := NewAutomatic(New(nil, false, "", 120))
			r := reportFixture(t)
			r.Resource.Value = "11.0.0.0/24"
			for i := range r.Metrics {
				r.Metrics[i].Data = []byte(strings.ReplaceAll(string(r.Metrics[i].Data), "1.1.1.0/24", r.Resource.Value))
			}
			if retained {
				a.publish(context.Background(), r.Resource.Value, r, unknownCheck())
				r.Metrics = []Metric{{Name: "prefix_overview", Status: "disabled"}, {Name: "rpki", Status: "disabled"}}
			} else {
				past := time.Now().Add(-time.Second)
				r.Metrics[0].ExpiresAt = &past
			}
			a.publish(context.Background(), r.Resource.Value, r, unknownCheck())
			status := a.Status(store)
			for _, c := range status.Checks[:2] {
				if c.Collection["succeeded"] != 1 || c.OldestAgeSeconds == nil {
					t.Fatalf("retained evidence was replaced by latest attempt: %+v", c)
				}
				if !retained && c.Freshness["fresh"] != 0 {
					t.Fatalf("stale BGP dependency did not bound coverage: %+v", c)
				}
			}
		})
	}
}

func TestUnobservedDisabledCoverage(t *testing.T) {
	store := coverageStore(t, 1)
	a := NewAutomatic(New(nil, false, "", 120))
	a.publish(context.Background(), "11.0.0.0/24", Report{Metrics: []Metric{{Name: "prefix_overview", Status: "disabled"}, {Name: "rpki", Status: "disabled"}}}, unknownCheck())
	for _, c := range a.Status(store).Checks[:2] {
		if c.Collection["disabled"] != 1 || c.Freshness["unknown"] != 1 || c.OldestAgeSeconds != nil {
			t.Fatalf("unobserved disabled check became a failure: %+v", c)
		}
	}
}

func coverageStore(t *testing.T, n int) *catalog.Store {
	t.Helper()
	provider := catalog.Provider{ID: "test", Name: "Test", URL: "https://example.com", Policy: catalog.Policy{Publication: "approved", PrefixVisibility: "full", MinRefreshSeconds: 60}}
	store, err := catalog.NewStore("", []catalog.Provider{provider})
	if err != nil {
		t.Fatal(err)
	}
	offers := []catalog.Offer{}
	for i := 0; i < n; i++ {
		prefix := fmt.Sprintf("11.%d.%d.0/24", i/256, i%256)
		offers = append(offers, catalog.Offer{ProviderID: "test", ExternalID: fmt.Sprint(i), Model: "lease", Availability: "available", Geography: catalog.Geography{Basis: "unknown"}, Resource: catalog.Resource{Family: 4, Prefix: &prefix, PrefixLength: 24}, Quotes: []catalog.Quote{}, URL: "https://example.com/offer"})
	}
	if err := store.Apply("test", offers, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestCollectionCoverageScenarios(t *testing.T) {
	for _, size := range []int{1, 100, 1000} {
		store := coverageStore(t, size)
		for _, rpm := range []int{1, 120, 600} {
			s := New(&memoryCache{}, true, "", rpm)
			a := NewAutomatic(s)
			cold := a.Status(store)
			if cold.EligiblePrefixes != size || cold.DuePrefixes != size || cold.UnscheduledPrefixes != size || cold.OldestDueSeconds != nil {
				t.Fatalf("wrong cold-start coverage: %+v", cold)
			}
			now, expires := time.Now().UTC(), time.Now().UTC().Add(time.Minute)
			for key := range publishedPrefixes(store) {
				a.publish(context.Background(), key, Report{Resource: Target{Value: key, Kind: "prefix"}, Metrics: []Metric{{Name: "registration", Status: "ok", ObservedAt: &now, ExpiresAt: &expires}}}, unknownCheck())
			}
			warm := a.Status(store)
			if warm.Checks[3].Collection["succeeded"] != size || warm.Checks[3].Freshness["fresh"] != size || warm.UnscheduledPrefixes != 0 {
				t.Fatalf("wrong warm coverage: %+v", warm)
			}
			restarted := NewAutomatic(New(s.cache, true, "", rpm)).Status(store)
			if restarted.Checks[3].Collection["pending"] != size || len(restarted.Upstreams) != 0 {
				t.Fatal("restart fabricated observed coverage")
			}
			payload, _ := json.Marshal(warm)
			if strings.Contains(string(payload), "11.0.") {
				t.Fatal("per-resource identifiers leaked")
			}
			t.Logf("prefixes=%d rpm=%d cold_pending=%d warm_fresh_registration=%d restart_pending=%d scheduler_floor_seconds=%.0f", size, rpm, cold.Checks[3].Collection["pending"], warm.Checks[3].Freshness["fresh"], restarted.Checks[3].Collection["pending"], warm.SchedulerSweepFloorSeconds)
		}
	}
}

func TestCollectionStatusConcurrentAndUpstreamCounters(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/auth":
			return response(403, "private upstream detail"), nil
		case "/quota":
			return response(429, `{}`), nil
		case "/missing":
			return response(404, `{}`), nil
		}
		return response(200, `{}`), nil
	})
	store := coverageStore(t, 1)
	a := NewAutomatic(s)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.publish(context.Background(), "11.0.0.0/24", Report{}, unknownCheck())
			a.Status(store)
		}()
	}
	wg.Wait()
	for _, path := range []string{"/auth", "/missing", "/ok", "/quota"} {
		s.readSource(context.Background(), "https://stat.ripe.net"+path+"?token=private", "private", 1024, true)
	}
	s.persistenceFailed()
	stats := a.Status(store)
	if len(stats.Upstreams) != 1 || stats.Upstreams[0].Requests != 4 || stats.Upstreams[0].Failures != 2 || stats.Upstreams[0].AuthFailures != 1 || stats.Upstreams[0].RateLimited != 1 || stats.Upstreams[0].NoData != 1 || stats.PersistenceFailures != 1 {
		t.Fatalf("incorrect bounded counters: %+v", stats)
	}
	data, _ := json.Marshal(stats)
	if strings.Contains(string(data), "private") {
		t.Fatal("upstream URL or credential exposed")
	}
	s.rpm = 1
	s.used = 1
	s.window = time.Now()
	if _, err := s.acquireRequest(context.Background()); !errors.Is(err, ErrBusy) || a.Status(store).BudgetDenials != 1 {
		t.Fatal("missing local budget denial", err)
	}
}

func TestCollectionWorkerCoverageAndRestart(t *testing.T) {
	store := coverageStore(t, 3)
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		time.Sleep(time.Millisecond)
		switch {
		case r.URL.Host == "www.spamhaus.org":
			return response(200, dropFixture(time.Now())), nil
		case strings.Contains(r.URL.Path, "prefix-overview"):
			return response(200, fmt.Sprintf(`{"status":"ok","data":{"resource":%q,"asns":[{"asn":13335},{"asn":15169}],"announced":true,"is_less_specific":false,"num_filtered_out":0}}`, r.URL.Query().Get("resource"))), nil
		case strings.Contains(r.URL.Path, "rpki-validation"):
			return response(200, fmt.Sprintf(`{"status":"ok","data":{"prefix":%q,"resource":%q,"status":"valid"}}`, r.URL.Query().Get("prefix"), r.URL.Query().Get("resource"))), nil
		case r.URL.Host == "stat.ripe.net":
			return response(200, `{"status":"ok","data":{}}`), nil
		default:
			return response(404, `{}`), nil
		}
	})
	s.rpm = 600
	run := func(service *Service) (*Automatic, time.Duration) {
		t.Helper()
		a := NewAutomatic(service)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); a.Run(ctx, store) }()
		defer func() { cancel(); <-done }()
		started := time.Now()
		for {
			status := a.Status(store)
			if status.Checks[3].Freshness["fresh"] == 3 && status.Checks[1].Collection["succeeded"] == 3 {
				return a, time.Since(started)
			}
			if time.Since(started) > 6*time.Second {
				t.Fatalf("collection did not complete: %+v", status)
			}
			time.Sleep(time.Millisecond)
		}
	}
	a, elapsed := run(s)
	warm := a.Status(store)
	if len(warm.Upstreams) == 0 || warm.Upstreams[0].Requests == 0 || warm.Checks[1].Freshness["fresh"] != 3 {
		t.Fatalf("worker coverage was not observed: %+v", warm)
	}
	for key := range publishedPrefixes(store) {
		if a.Get(key).RPKI.Status != "valid" || len(a.Get(key).BGP.Origins) != 2 {
			t.Fatal("multi-origin coverage lost")
		}
	}
	restartedService := New(s.cache, false, "", 600)
	restartedService.client.Transport = funcTransportFail(t)
	restored, restoreTime := run(restartedService)
	if len(restored.Status(store).Upstreams) != 0 {
		t.Fatal("restart consumed upstream requests")
	}
	t.Logf("three-prefix two-origin worker: cold_to_registration_and_rpki=%s restart_restore=%s upstream_groups=%d", elapsed.Round(time.Millisecond), restoreTime.Round(time.Millisecond), len(warm.Upstreams))
}

func funcTransportFail(t *testing.T) roundTrip {
	return func(*http.Request) (*http.Response, error) {
		t.Error("disabled restart contacted an upstream")
		return nil, errors.New("unexpected request")
	}
}

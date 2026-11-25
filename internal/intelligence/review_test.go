package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

func reviewStore(t *testing.T) *catalog.Store {
	t.Helper()
	p := catalog.Provider{ID: "test", Name: "Test", URL: "https://example.com", Policy: catalog.Policy{Publication: "approved", PrefixVisibility: "full", MinRefreshSeconds: 60}}
	store, err := catalog.NewStore("", []catalog.Provider{p})
	if err != nil {
		t.Fatal(err)
	}
	prefix := "1.1.1.0/24"
	o := catalog.Offer{ProviderID: "test", ExternalID: "one", Model: "lease", Availability: "available", Geography: catalog.Geography{Basis: "unknown"}, Resource: catalog.Resource{Family: 4, Prefix: &prefix, PrefixLength: 24}, Quotes: []catalog.Quote{}, URL: "https://example.com/one"}
	if err = store.Apply("test", []catalog.Offer{o}, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestCachedExpiredFailureHasNoStaleObservation(t *testing.T) {
	for _, status := range []string{"rate_limited", "unavailable", "disabled", "no_data", "ok"} {
		t.Run(status, func(t *testing.T) {
			s := New(&memoryCache{}, false, "", 120)
			past := time.Now().Add(-time.Hour)
			m := Metric{Name: "registration", Status: status, Data: json.RawMessage("null")}
			if status == "ok" || status == "no_data" {
				m.ObservedAt = &past
			}
			if status == "ok" {
				m.Data = json.RawMessage(`{"records":[]}`)
			}
			b, _ := json.Marshal(m)
			target, _ := ParseTarget("1.1.1.0/24")
			q := Query{Resource: target.Value, Checks: []string{"registration"}}
			s.cache.CachePut(context.Background(), metricKey(target, q, "registration"), b, past)
			r, err := s.Cached(context.Background(), q)
			want := status
			if status == "ok" {
				want = "stale"
			}
			if err != nil || r.Metrics[0].Status != want {
				t.Fatalf("got %+v %v; want %s", r, err, want)
			}
		})
	}
}

func TestAutomaticRestoresReportWithoutRawMetrics(t *testing.T) {
	s := New(&memoryCache{}, false, "", 120)
	bgp, rpki := summarize(reportFixture(t), time.Now())
	saved := OfferChecks{Resource: "1.1.1.0/24", BGP: bgp, RPKI: rpki}
	b, _ := json.Marshal(saved)
	s.cache.CachePut(context.Background(), "automatic:"+saved.Resource, b, time.Now().Add(time.Hour))
	a := NewAutomatic(s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	store := reviewStore(t)
	go func() { defer close(done); a.Run(ctx, store) }()
	deadline := time.After(3 * time.Second)
	for { // Wait for the restored report to be rewritten after an attempted refresh.
		raw, _, _, _ := s.cache.CacheGet(ctx, "automatic:"+saved.Resource)
		if string(raw) != string(b) {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("worker did not refresh restored report")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	<-done
	got := a.Get(saved.Resource)
	if got.BGP.Status != "announced" || got.RPKI.Status != "valid" || !got.BGP.ObservedAt.Equal(*bgp.ObservedAt) || !got.BGP.ExpiresAt.Equal(*bgp.ExpiresAt) {
		t.Fatalf("lost retained observations: %+v", got)
	}
	raw, _, _, _ := s.cache.CacheGet(context.Background(), "automatic:"+saved.Resource)
	var persisted OfferChecks
	json.Unmarshal(raw, &persisted)
	if persisted.RPKI.Status != "valid" {
		t.Fatal("durable observation overwritten")
	}
}

type completionFailureCache struct {
	memoryCache
	writes int
}

func (c *completionFailureCache) CachePut(ctx context.Context, key string, b json.RawMessage, expires time.Time) error {
	c.writes++
	if c.writes == 2 {
		return fmt.Errorf("completion write failed")
	}
	return c.memoryCache.CachePut(ctx, key, b, expires)
}
func TestDropRetriesCompletionPersistenceWithoutDownload(t *testing.T) {
	now := time.Now()
	var calls atomic.Int32
	s := mockService(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return response(200, dropFixture(now)), nil })
	cache := &completionFailureCache{}
	s.cache = cache
	prefix := netip.MustParsePrefix("1.1.1.0/24")
	f := dropFeed{}
	if c := f.check(context.Background(), s, prefix, now); c.Status != "listed" || c.Freshness != "stale" {
		t.Fatalf("unsaved result: %+v", c)
	}
	next := f.Next
	if c := f.check(context.Background(), s, prefix, now.Add(2*time.Minute)); c.Freshness != "fresh" {
		t.Fatalf("save did not recover: %+v", c)
	}
	restarted := dropFeed{}
	c := restarted.check(context.Background(), s, prefix, now.Add(3*time.Minute))
	if c.Status != "listed" || c.Freshness != "fresh" || calls.Load() != 1 || !restarted.Next.Equal(next) {
		t.Fatalf("restart lost dataset or schedule: %+v downloads=%d", c, calls.Load())
	}
}

type expiredOverviewCache struct{ Cache }

func (c expiredOverviewCache) CachePut(ctx context.Context, key string, data json.RawMessage, expires time.Time) error {
	if strings.Contains(key, `"Name":"prefix_overview"`) {
		expires = time.Now().Add(-time.Hour)
	}
	return c.Cache.CachePut(ctx, key, data, expires)
}

func TestAutomaticOneRequestBudgetCompletesMultiOriginRPKI(t *testing.T) {
	var s *Service
	var overviews, validations atomic.Int32
	s = mockService(t, func(r *http.Request) (*http.Response, error) {
		s.mu.Lock()
		if s.used != 1 {
			t.Errorf("minute budget exceeded: %d", s.used)
		}
		// Advance to just before the next window without sleeping for real minutes.
		s.window = time.Now().Add(-time.Minute + 10*time.Millisecond)
		s.mu.Unlock()
		switch {
		case strings.Contains(r.URL.Path, "prefix-overview"):
			overviews.Add(1)
			return response(200, `{"status":"ok","data":{"resource":"1.1.1.0/24","asns":[{"asn":1},{"asn":2},{"asn":3},{"asn":4}],"announced":true,"is_less_specific":false,"num_filtered_out":0}}`), nil
		case strings.Contains(r.URL.Path, "rpki-validation"):
			validations.Add(1)
			return response(200, fmt.Sprintf(`{"status":"ok","data":{"prefix":"1.1.1.0/24","resource":%q,"status":"valid"}}`, r.URL.Query().Get("resource"))), nil
		case strings.Contains(r.URL.Host, "spamhaus"):
			return response(200, dropFixture(time.Now())), nil
		default:
			return response(404, `{}`), nil
		}
	})
	s.cache = expiredOverviewCache{s.cache}
	s.rpm = 1
	a := NewAutomatic(s)
	store := reviewStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.Run(ctx, store) }()
	deadline := time.After(3 * time.Second)
	for a.Get("1.1.1.0/24").RPKI.Status != "valid" {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("RPKI starved: %+v", a.Get("1.1.1.0/24"))
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	<-done
	if overviews.Load() != 1 || validations.Load() != 4 {
		t.Fatalf("dependency requests: %d/%d", overviews.Load(), validations.Load())
	}
}

func TestAutomaticReplacesRetainedObservationsWithNewEvidence(t *testing.T) {
	for _, kind := range []string{"no_data", "not_announced", "changed_origins", "filtered_origins", "missing_completeness"} {
		t.Run(kind, func(t *testing.T) {
			r := reportFixture(t)
			bgp, rpki := summarize(r, time.Now())
			a := NewAutomatic(New(nil, false, "", 120))
			a.reports[r.Resource.Value] = OfferChecks{Resource: r.Resource.Value, BGP: bgp, RPKI: rpki}
			r.Metrics = r.Metrics[:1]
			switch kind {
			case "no_data":
				r.Metrics[0].Status = "no_data"
				r.Metrics[0].Data = json.RawMessage("null")
			case "not_announced":
				r.Metrics[0].Data = json.RawMessage(`{"resource":"1.1.1.0/24","is_less_specific":false,"announced":false,"num_filtered_out":0,"asns":[]}`)
			case "filtered_origins":
				r.Metrics[0].Data = json.RawMessage(strings.ReplaceAll(string(r.Metrics[0].Data), `"num_filtered_out":0`, `"num_filtered_out":1`))
			case "missing_completeness":
				r.Metrics[0].Data = json.RawMessage(strings.ReplaceAll(string(r.Metrics[0].Data), `"num_filtered_out":0,`, ``))
			case "changed_origins":
				r.Metrics[0].Data = json.RawMessage(strings.ReplaceAll(string(r.Metrics[0].Data), "13335", "13336"))
			}
			a.publish(context.Background(), r.Resource.Value, r, unknownCheck())
			got := a.Get(r.Resource.Value)
			if got.RPKI.Status == "valid" {
				t.Fatalf("retained obsolete validation: %+v", got)
			}
			if kind == "no_data" && got.BGP.Status != "no_data" || kind == "not_announced" && got.BGP.Status != "not_announced" {
				t.Fatalf("new evidence ignored: %+v", got)
			}
		})
	}
}

func TestAutomaticBudgetWaitCancelsWithoutLeakingSlots(t *testing.T) {
	s := New(nil, true, "", 1)
	release, err := s.acquireRequest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, err = s.acquireRequest(context.Background()); err != ErrBusy {
		t.Fatalf("interactive budget changed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), automaticBudgetKey{}, true), 10*time.Millisecond)
	defer cancel()
	if _, err = s.acquireRequest(ctx); err != context.DeadlineExceeded {
		t.Fatalf("wait ignored cancellation: %v", err)
	}
	if len(s.httpSlots) != 0 {
		t.Fatal("cancelled wait retained an HTTP slot")
	}
}

func TestAutomaticRetainsRPKIAcrossOriginReordering(t *testing.T) {
	r := reportFixture(t)
	r.Metrics[0].Data = json.RawMessage(`{"resource":"1.1.1.0/24","is_less_specific":false,"announced":true,"num_filtered_out":0,"asns":[{"asn":13336},{"asn":13335}]}`)
	r.Metrics[1].Data = json.RawMessage(`{"prefix":"1.1.1.0/24","origins":[{"asn":13335,"data":{"prefix":"1.1.1.0/24","resource":"13335","status":"valid"}},{"asn":13336,"data":{"prefix":"1.1.1.0/24","resource":"13336","status":"valid"}}]}`)
	bgp, rpki := summarize(r, time.Now())
	if rpki.Status != "valid" {
		t.Fatal("invalid fixture")
	}
	a := NewAutomatic(New(&memoryCache{}, false, "", 120))
	a.reports[r.Resource.Value] = OfferChecks{Resource: r.Resource.Value, BGP: bgp, RPKI: rpki}
	r.Metrics = r.Metrics[:1]
	r.Metrics[0].Data = json.RawMessage(`{"resource":"1.1.1.0/24","is_less_specific":false,"announced":true,"num_filtered_out":0,"asns":[{"asn":13335},{"asn":13336},{"asn":13335}]}`)
	for _, completed := range []bool{false, true} {
		if completed {
			r.Metrics = append(r.Metrics, Metric{Name: "rpki", Status: "unavailable", Data: json.RawMessage("null")})
		}
		a.publish(context.Background(), r.Resource.Value, r, unknownCheck())
		got := a.Get(r.Resource.Value)
		if bgp.Origins[0] != 13336 || bgp.Origins[1] != 13335 {
			t.Fatal("comparison mutated the previous published origin slice")
		}
		if got.RPKI.Status != "valid" || !got.RPKI.ObservedAt.Equal(*rpki.ObservedAt) || !got.RPKI.ExpiresAt.Equal(*rpki.ExpiresAt) {
			t.Fatalf("unchanged origin set lost observation: %+v", got)
		}
		raw, _, _, _ := a.service.cache.CacheGet(context.Background(), "automatic:"+r.Resource.Value)
		var stored OfferChecks
		if err := json.Unmarshal(raw, &stored); err != nil || stored.RPKI.Status != "valid" {
			t.Fatal("durable observation lost", err)
		}
	}
}

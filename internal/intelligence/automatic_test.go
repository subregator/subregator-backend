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

func reportFixture(t *testing.T) Report {
	t.Helper()
	now, expiry := time.Now().UTC(), time.Now().UTC().Add(5*time.Minute)
	return Report{Resource: Target{Value: "1.1.1.0/24", Kind: "prefix"}, Metrics: []Metric{
		{Name: "prefix_overview", Status: "ok", ObservedAt: &now, ExpiresAt: &expiry, Data: json.RawMessage(`{"resource":"1.1.1.0/24","is_less_specific":false,"announced":true,"num_filtered_out":0,"asns":[{"asn":13335}]}`)},
		{Name: "rpki", Status: "ok", ObservedAt: &now, ExpiresAt: &expiry, Data: json.RawMessage(`{"prefix":"1.1.1.0/24","origins":[{"asn":13335,"data":{"prefix":"1.1.1.0/24","resource":"13335","status":"valid"}}]}`)},
	}}
}
func TestAutomaticSummariesNeverInventPassingCoverage(t *testing.T) {
	for _, tc := range []struct {
		name, old, value, bgp, rpki string
		metric                      int
	}{
		{"complete", "", "", "announced", "valid", 0},
		{"covering", "\"is_less_specific\":false", "\"is_less_specific\":true", "covering_route", "unavailable", 0},
		{"wrong resource", "1.1.1.0/24", "1.1.0.0/16", "unavailable", "unavailable", 0},
		{"filtered", "\"num_filtered_out\":0", "\"num_filtered_out\":1", "announced", "partial", 0},
		{"missing origin", "\"asn\":13335", "\"asn\":13336", "announced", "partial", 1},
		{"wrong RPKI prefix", "1.1.1.0/24", "1.0.0.0/24", "announced", "unavailable", 1},
		{"invalid", "\"status\":\"valid\"", "\"status\":\"invalid_asn\"", "announced", "invalid", 1},
		{"no ROA", "\"status\":\"valid\"", "\"status\":\"unknown\"", "announced", "not_found", 1},
		{"malformed", "{", "!", "unavailable", "unavailable", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reportFixture(t)
			if tc.old != "" {
				r.Metrics[tc.metric].Data = []byte(strings.Replace(string(r.Metrics[tc.metric].Data), tc.old, tc.value, 1))
			}
			bgp, rpki := summarize(r, time.Now())
			if bgp.Status != tc.bgp || rpki.Status != tc.rpki {
				t.Fatalf("got %s/%s want %s/%s", bgp.Status, rpki.Status, tc.bgp, tc.rpki)
			}
		})
	}
	r := reportFixture(t)
	past := time.Now().Add(-time.Hour)
	r.Metrics[0].ExpiresAt = &past
	bgp, rpki := summarize(r, time.Now())
	if bgp.Freshness == "fresh" || rpki.Freshness == "fresh" {
		t.Fatal("stale dependency passed")
	}
}
func dropFixture(now time.Time) string {
	return fmt.Sprintf("{\"cidr\":\"1.1.0.0/16\",\"sblid\":\"SBL123\"}\n{\"type\":\"metadata\",\"timestamp\":%d,\"copyright\":\"The Spamhaus Project\",\"records\":1}\n", now.Unix())
}
func TestDropCompleteDatasetOverlapAndRestartBudget(t *testing.T) {
	now := time.Now().UTC()
	var calls atomic.Int32
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return response(200, dropFixture(now)), nil
	})
	f := dropFeed{}
	for _, raw := range []string{"1.1.1.0/24", "1.0.0.0/8", "2.0.0.0/8"} {
		c := f.check(context.Background(), s, netip.MustParsePrefix(raw), now)
		if c.Freshness != "fresh" || c.Copyright == "" {
			t.Fatalf("missing source provenance %+v", c)
		}
		listed := raw != "2.0.0.0/8"
		if (c.Status == "listed") != listed {
			t.Fatalf("wrong overlap %+v", c)
		}
	}
	restored := dropFeed{}
	restored.check(context.Background(), s, netip.MustParsePrefix("1.1.1.0/24"), now.Add(time.Minute))
	if calls.Load() != 1 {
		t.Fatalf("daily download limit violated: %d", calls.Load())
	}
	c := restored.check(context.Background(), s, netip.MustParsePrefix("1.1.1.0/24"), now.Add(27*time.Hour))
	if c.Freshness == "fresh" {
		t.Fatal("old source timestamp accepted as current")
	}
	for _, body := range []string{"", `{"cidr":"1.1.0.0/16","sblid":"SBL123"}`, strings.Replace(dropFixture(now), `"records":1`, `"records":2`, 1), dropFixture(now) + "{}\n", dropFixture(now.Add(time.Hour)), strings.Replace(dropFixture(now), "1.1.0.0/16", "1.1.1.1/16", 1)} {
		if _, e := parseDrop([]byte(body), true, now); e == nil {
			t.Fatalf("accepted incomplete/invalid source %q", body)
		}
	}
	if _, e := parseDrop([]byte(dropFixture(now)), false, now); e == nil {
		t.Fatal("wrong feed family accepted")
	}
}
func TestAutomaticWorkerDeduplicatesPublishedPrefixesAndRestores(t *testing.T) {
	var calls atomic.Int32
	now := time.Now()
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		switch {
		case strings.Contains(r.URL.Host, "spamhaus"):
			return response(200, dropFixture(now)), nil
		case strings.Contains(r.URL.Path, "prefix-overview"):
			return response(200, `{"status":"ok","data":{"resource":"1.1.1.0/24","asns":[{"asn":13335}],"announced":true,"is_less_specific":false,"num_filtered_out":0}}`), nil
		case strings.Contains(r.URL.Path, "rpki-validation"):
			return response(200, `{"status":"ok","data":{"prefix":"1.1.1.0/24","resource":"13335","status":"valid"}}`), nil
		default:
			return response(404, `{}`), nil
		}
	})
	provider := catalog.Provider{ID: "test", Name: "Test", URL: "https://example.com", Policy: catalog.Policy{Publication: "approved", PrefixVisibility: "full", MinRefreshSeconds: 60}}
	store, e := catalog.NewStore("", []catalog.Provider{provider})
	if e != nil {
		t.Fatal(e)
	}
	prefix := "1.1.1.0/24"
	offers := []catalog.Offer{}
	for _, id := range []string{"one", "two"} {
		offers = append(offers, catalog.Offer{ProviderID: "test", ExternalID: id, Model: "lease", Availability: "available", Geography: catalog.Geography{Basis: "unknown"}, Resource: catalog.Resource{Family: 4, Prefix: &prefix, PrefixLength: 24}, Quotes: []catalog.Quote{}, URL: "https://example.com/" + id})
	}
	if e = store.Apply("test", offers, nil, now); e != nil {
		t.Fatal(e)
	}
	a := NewAutomatic(s)
	if a.Get(prefix).BGP.Status != "pending" {
		t.Fatal("unseen prefix passed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.Run(ctx, store) }()
	deadline := time.After(3 * time.Second)
	for a.Get(prefix).RPKI.Status != "valid" || a.Get(prefix).Blocklist.Status != "listed" {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("worker did not publish")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	<-done
	if len(a.reports) != 1 || a.Get(prefix).RPKI.Status != "valid" || a.Get(prefix).Blocklist.Status != "listed" {
		t.Fatalf("wrong automatic result: %+v", a.Get(prefix))
	}
	count := calls.Load()
	for i := 0; i < 1000; i++ {
		a.Get(prefix)
	}
	if calls.Load() != count {
		t.Fatal("reading results started checks")
	}
	// A disabled restarted process must restore observations without contacting any source.
	s.network = false
	restored := NewAutomatic(s)
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { defer close(done); restored.Run(ctx, store) }()
	deadline = time.After(3 * time.Second)
	for restored.Get(prefix).BGP.Status == "pending" {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("restore failed")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	<-done
	if calls.Load() != count || restored.Get(prefix).BGP.Status != "announced" {
		t.Fatal("restart lost observation or contacted source")
	}
}

func TestRPKIReusesPrefixObservationAndPreservesSourceFailure(t *testing.T) {
	var overview atomic.Int32
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "prefix-overview") {
			overview.Add(1)
			return response(200, `{"status":"ok","data":{"resource":"1.1.1.0/24","asns":[{"asn":13335}]}}`), nil
		}
		return response(200, `{"status":"ok","data":{"prefix":"1.1.1.0/24","resource":"13335","status":"valid"}}`), nil
	})
	r, e := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"prefix_overview", "rpki"}})
	if e != nil || r.Partial || overview.Load() != 1 {
		t.Fatalf("duplicate dependency fetch: %d %+v %v", overview.Load(), r, e)
	}
	s = mockService(t, func(*http.Request) (*http.Response, error) { return response(429, `{}`), nil })
	r, e = s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"rpki"}})
	if e != nil || len(r.Metrics) != 1 || r.Metrics[0].Status != "rate_limited" {
		t.Fatalf("source failure became an absence observation: %+v %v", r, e)
	}
}

type failOnceCache struct {
	memoryCache
	failed bool
}

func (c *failOnceCache) CachePut(ctx context.Context, key string, b json.RawMessage, expires time.Time) error {
	if !c.failed {
		c.failed = true
		return fmt.Errorf("temporary database failure")
	}
	return c.memoryCache.CachePut(ctx, key, b, expires)
}
func TestDropRetriesDatabaseReservationAndSharesRequestBudget(t *testing.T) {
	now := time.Now()
	prefix := netip.MustParsePrefix("1.1.1.0/24")
	t.Run("database recovery", func(t *testing.T) {
		var calls atomic.Int32
		s := mockService(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return response(200, dropFixture(now)), nil })
		s.cache = &failOnceCache{}
		f := dropFeed{}
		f.check(context.Background(), s, prefix, now)
		if calls.Load() != 0 {
			t.Fatal("download started before durable reservation")
		}
		c := f.check(context.Background(), s, prefix, now.Add(2*time.Minute))
		if calls.Load() != 1 || c.Freshness != "fresh" {
			t.Fatal("database recovery did not resume collection")
		}
	})
	t.Run("shared budget", func(t *testing.T) {
		var calls atomic.Int32
		s := mockService(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return response(200, `{}`), nil })
		s.rpm = 1
		s.request(context.Background(), "https://stat.ripe.net/test", "")
		f := dropFeed{}
		f.check(context.Background(), s, prefix, now)
		if calls.Load() != 1 {
			t.Fatalf("DROP bypassed source request budget: %d", calls.Load())
		}
	})
}

type failReadCache struct {
	Cache
	failed bool
}

func (c *failReadCache) CacheGet(ctx context.Context, key string) (json.RawMessage, time.Time, bool, error) {
	if !c.failed {
		c.failed = true
		return nil, time.Time{}, false, fmt.Errorf("temporary cache read failure")
	}
	return c.Cache.CacheGet(ctx, key)
}
func TestDropCacheReadFailureCannotBypassDailyReservation(t *testing.T) {
	now := time.Now()
	var calls atomic.Int32
	s := mockService(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return response(200, dropFixture(now)), nil })
	prefix := netip.MustParsePrefix("1.1.1.0/24")
	first := dropFeed{}
	first.check(context.Background(), s, prefix, now)
	s.cache = &failReadCache{Cache: s.cache}
	restarted := dropFeed{}
	restarted.check(context.Background(), s, prefix, now.Add(time.Minute))
	if calls.Load() != 1 {
		t.Fatalf("cache read failure bypassed daily reservation: %d downloads", calls.Load())
	}
	restored := restarted.check(context.Background(), s, prefix, now.Add(2*time.Minute))
	if calls.Load() != 1 || restored.Freshness != "fresh" {
		t.Fatal("cached observation was not restored after database recovery")
	}
}

func TestAutomaticLowBudgetStillCollectsDROP(t *testing.T) {
	now := time.Now()
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Host, "spamhaus") {
			return response(200, dropFixture(now)), nil
		}
		return response(429, `{}`), nil
	})
	s.rpm = 1
	provider := catalog.Provider{ID: "test", Name: "Test", URL: "https://example.com", Policy: catalog.Policy{Publication: "approved", PrefixVisibility: "full", MinRefreshSeconds: 60}}
	store, e := catalog.NewStore("", []catalog.Provider{provider})
	if e != nil {
		t.Fatal(e)
	}
	prefix := "1.1.1.0/24"
	o := catalog.Offer{ProviderID: "test", ExternalID: "one", Model: "lease", Availability: "available", Geography: catalog.Geography{Basis: "unknown"}, Resource: catalog.Resource{Family: 4, Prefix: &prefix, PrefixLength: 24}, Quotes: []catalog.Quote{}, URL: "https://example.com/one"}
	if e = store.Apply("test", []catalog.Offer{o}, nil, now); e != nil {
		t.Fatal(e)
	}
	a := NewAutomatic(s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.Run(ctx, store) }()
	deadline := time.After(3 * time.Second)
	for a.Get(prefix).Blocklist.Status == "pending" {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("worker did not publish")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	<-done
	if a.Get(prefix).Blocklist.Status != "listed" {
		t.Fatal("per-prefix inspections starved the shared DROP feed")
	}
}

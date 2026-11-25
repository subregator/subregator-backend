package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type cached struct {
	data    json.RawMessage
	expires time.Time
}
type memoryCache struct {
	mu   sync.Mutex
	rows map[string]cached
}

func (c *memoryCache) CacheGet(_ context.Context, key string) (json.RawMessage, time.Time, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.rows[key]
	return r.data, r.expires, ok, nil
}
func (c *memoryCache) CachePut(_ context.Context, key string, b json.RawMessage, expires time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rows == nil {
		c.rows = map[string]cached{}
	}
	c.rows[key] = cached{b, expires}
	return nil
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}
func mockService(t *testing.T, fn roundTrip) *Service {
	t.Helper()
	s := New(&memoryCache{}, true, "", 120)
	s.client.Transport = fn
	return s
}
func TestTargetValidation(t *testing.T) {
	for _, raw := range []string{"1.1.1.1", "1.1.1.23/24", "2001:4860:4860::8888", "AS13335", "13335"} {
		if _, e := ParseTarget(raw); e != nil {
			t.Fatal(raw, e)
		}
	}
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "::1", "fe80::1%en0", "2001:db8::/32", "0.0.0.0/0", "8.0.0.0/5", "AS0", "AS64512", "AS4294967295", "http://example.com", "localhost", "1.1.1.1;id", "AS13335&token=x"} {
		if _, e := ParseTarget(raw); e == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}

func TestCachedConfigurationStates(t *testing.T) {
	s := New(nil, false, "", 120)
	for _, tc := range []struct{ resource, check, status string }{
		{"1.1.1.1", "registration", "disabled"},
		{"1.1.1.1", "ipinfo_lite", "not_configured"},
		{"AS13335", "prefix_overview", "not_applicable"},
	} {
		r, err := s.Cached(context.Background(), Query{Resource: tc.resource, Checks: []string{tc.check}})
		if err != nil || r.Metrics[0].Status != tc.status {
			t.Fatalf("%s: want %s, got %+v (%v)", tc.check, tc.status, r, err)
		}
	}
}

func TestNetworkObservationEnvelope(t *testing.T) {
	s := New(nil, true, "", 120)
	r, err := s.Cached(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"registration"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r.Metrics[0])
	var fields map[string]json.RawMessage
	json.Unmarshal(b, &fields)
	var observation struct {
		CollectionStatus string `json:"collection_status"`
		Freshness        string `json:"freshness"`
		Completeness     string `json:"completeness"`
		Scope            struct {
			Requested string `json:"requested"`
		} `json:"scope"`
	}
	if json.Unmarshal(fields["observation"], &observation) != nil || observation.CollectionStatus != "pending" || observation.Freshness != "unknown" || observation.Completeness != "unknown" || observation.Scope.Requested != "1.1.1.0/24" {
		t.Fatalf("missing honest observation envelope: %s", b)
	}
}
func TestFreeSourceCachingAndFailureFallback(t *testing.T) {
	var calls atomic.Int32
	var failing atomic.Bool
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Host != "stat.ripe.net" {
			t.Error("unexpected source")
		}
		if failing.Load() {
			return response(503, `{}`), nil
		}
		return response(200, `{"status":"ok","data":{"holder":"Example network"}}`), nil
	})
	q := Query{Resource: "1.1.1.0/24", Checks: []string{"registration"}}
	first, e := s.Inspect(context.Background(), q)
	if e != nil || first.Partial || calls.Load() != 1 {
		t.Fatal(e, first)
	}
	second, _ := s.Inspect(context.Background(), q)
	if !second.Metrics[0].Cached || calls.Load() != 1 {
		t.Fatal("cache not used")
	}
	cache := s.cache.(*memoryCache)
	cache.mu.Lock()
	for key, row := range cache.rows {
		row.expires = time.Now().Add(-time.Second)
		cache.rows[key] = row
	}
	cache.mu.Unlock()
	failing.Store(true)
	stale, _ := s.Inspect(context.Background(), q)
	if stale.Metrics[0].Status != "stale" || !stale.Metrics[0].ObservedAt.Equal(*first.Metrics[0].ObservedAt) || !stale.Partial {
		t.Fatal("failed refresh hid staleness", stale)
	}
}
func TestConcurrentRequestsDeduplicateUpstream(t *testing.T) {
	var calls atomic.Int32
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		time.Sleep(40 * time.Millisecond)
		return response(200, `{"status":"ok","data":{}}`), nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := s.Inspect(context.Background(), Query{Resource: "1.1.1.1", Checks: []string{"registration"}})
			if e != nil || r.Partial {
				t.Error(e, r)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("duplicate upstream requests", calls.Load())
	}
}
func TestOnlyFreeIPinfoEndpointAndFields(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://api.ipinfo.io/lite/1.1.1.1" || r.Header.Get("Authorization") != "Bearer test-free-token" {
			t.Error("incorrect free endpoint or authentication")
		}
		return response(200, `{"ip":"1.1.1.1","asn":"AS13335","country_code":"AU","privacy":{"vpn":true},"rank":100,"token":"test-free-token"}`), nil
	})
	s.token = "test-free-token"
	out, e := s.Inspect(context.Background(), Query{Resource: "1.1.1.1", Checks: []string{"ipinfo_lite"}})
	if e != nil || out.Partial {
		t.Fatal(e, out)
	}
	var fields map[string]any
	if e = json.Unmarshal(out.Metrics[0].Data, &fields); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"privacy", "rank", "token"} {
		if _, ok := fields[key]; ok {
			t.Fatal("paid field or token exposed")
		}
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "test-free-token") {
		t.Fatal("token exposed")
	}

}
func TestDisabledAndMissingTokenNeverCallUpstream(t *testing.T) {
	var calls atomic.Int32
	s := mockService(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return response(200, `{}`), nil })
	s.network = false
	out, _ := s.Inspect(context.Background(), Query{Resource: "1.1.1.1", Checks: []string{"registration", "ipinfo_lite"}})
	if out.Metrics[0].ObservedAt != nil {
		t.Fatal("unknown timestamp replaced with a synthetic date")
	}
	if calls.Load() != 0 || out.Metrics[0].Status != "disabled" || out.Metrics[1].Status != "not_configured" {
		t.Fatal(out)
	}
}
func TestRequestBudgetAndInvalidResponses(t *testing.T) {
	var calls atomic.Int32
	s := mockService(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return response(200, `{"status":"ok","data":{}}`), nil
	})
	s.rpm = 1
	out, e := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"registration", "routing_status"}})
	if e != nil || !out.Partial || calls.Load() != 1 {
		t.Fatal(e, out)
	}
	rateLimited := false
	for _, m := range out.Metrics {
		if m.Status == "rate_limited" {
			rateLimited = true
		}
	}
	if !rateLimited {
		t.Fatal("budget failure hidden")
	}
	for _, body := range []string{`not json`, strings.Repeat("x", (1<<20)+1), `{"status":"error","data":{}}`} {
		s := mockService(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		r, _ := s.Inspect(context.Background(), Query{Resource: "1.1.1.1", Checks: []string{"registration"}})
		if !r.Partial || r.Metrics[0].Status != "unavailable" {
			t.Fatal("invalid upstream accepted")
		}
	}
}
func TestRDAPRejectsUntrustedBootstrapURLs(t *testing.T) {
	var calls atomic.Int32
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Host != "data.iana.org" {
			t.Error("untrusted URL fetched")
		}
		return response(200, `{"services":[[["1.0.0.0/8"],["http://127.0.0.1/internal"]]]}`), nil
	})
	r, _ := s.Inspect(context.Background(), Query{Resource: "1.1.1.1", Checks: []string{"rdap"}})
	if !r.Partial || calls.Load() != 1 {
		t.Fatal("untrusted RDAP endpoint accepted")
	}
}
func TestRPKIUsesExplicitPrefixASNPair(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/data/network-info/data.json":
			return response(200, `{"status":"ok","data":{"prefix":"1.1.1.0/24","asns":["13335"]}}`), nil
		case "/data/rpki-validation/data.json":
			if r.URL.Query().Get("resource") != "13335" || r.URL.Query().Get("prefix") != "1.1.1.0/24" {
				t.Error("wrong RPKI pair")
			}
			return response(200, `{"status":"ok","data":{"status":"valid"}}`), nil
		}
		return nil, fmt.Errorf("unexpected request")
	})
	r, e := s.Inspect(context.Background(), Query{Resource: "1.1.1.1", Checks: []string{"rpki"}})
	if e != nil || r.Partial || !strings.Contains(string(r.Metrics[0].Data), `"valid"`) {
		t.Fatal(e, r)
	}
}

func TestFreeASRankIsLabeledAsASNTopology(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://api.asrank.caida.org/v2/restful/asns/13335" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected rank source or credentials")
		}
		return response(200, `{"data":{"asn":{"asn":"13335","rank":61}}}`), nil
	})
	r, e := s.Inspect(context.Background(), Query{Resource: "AS13335", Checks: []string{"asn_rank"}})
	if e != nil || r.Partial {
		t.Fatal(e, r)
	}
	var data map[string]json.RawMessage
	json.Unmarshal(r.Metrics[0].Data, &data)
	if string(data["scope"]) != `"autonomous_system"` || len(data["attribution"]) == 0 {
		t.Fatal("rank scope or attribution missing")
	}
}

func TestUnannouncedResourceIsNoDataNotAnOutage(t *testing.T) {
	s := mockService(t, func(*http.Request) (*http.Response, error) {
		return response(200, `{"status":"ok","data":{"prefix":"","asns":[]}}`), nil
	})
	result, e := s.Inspect(context.Background(), Query{Resource: "1.1.1.1", Checks: []string{"rpki"}})
	if e != nil || result.Metrics[0].Status != "no_data" {
		t.Fatal("absence confused with upstream outage", e, result)
	}
}

type delayedCacheRead struct {
	Cache
	once   sync.Once
	ready  chan struct{}
	resume chan struct{}
}

func (c *delayedCacheRead) CacheGet(ctx context.Context, key string) (json.RawMessage, time.Time, bool, error) {
	b, expires, found, e := c.Cache.CacheGet(ctx, key)
	delay := false
	c.once.Do(func() { delay = true; close(c.ready) })
	if delay {
		select {
		case <-c.resume:
		case <-ctx.Done():
			return nil, time.Time{}, false, ctx.Err()
		}
	}
	return b, expires, found, e
}
func TestConcurrentCacheMissAfterCompletedRefresh(t *testing.T) {
	var calls atomic.Int32
	s := mockService(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return response(200, `{"status":"ok","data":{"resource":"1.1.1.0/24"}}`), nil
	})
	cache := &delayedCacheRead{Cache: s.cache, ready: make(chan struct{}), resume: make(chan struct{})}
	s.cache = cache
	target, _ := ParseTarget("1.1.1.0/24")
	q := Query{Resource: target.Value}
	first := make(chan Metric, 1)
	go func() { first <- s.metric(context.Background(), target, q, "prefix_overview") }()
	<-cache.ready
	result := s.metric(context.Background(), target, q, "prefix_overview")
	close(cache.resume)
	delayed := <-first
	if result.Status != "ok" || delayed.Status != "ok" || calls.Load() != 1 {
		t.Fatalf("completed refresh was repeated after an earlier cache miss: calls=%d statuses=%s/%s", calls.Load(), result.Status, delayed.Status)
	}
}

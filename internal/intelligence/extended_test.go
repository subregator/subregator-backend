package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGeolocationAndDNSBLCoverage(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "maxmind-geo-lite") {
			return response(200, `{"status":"ok","data":{"located_resources":[{"resource":"163.5.251.0/24","locations":[{"country":"FR","city":"","latitude":48.8582,"longitude":2.3387,"covered_percentage":100}],"unknown_percentage":0}],"parameters":{"resource":"163.5.251.0/24"},"result_time":"2026-11-24T18:31:03"}}`), nil
		}
		return response(200, `{"status":"ok","data":{"blocklists":{"spamhaus_sbl":{"name":"SBL","operator":"Spamhaus"},"spamrats":{"name":"RATS"}},"data":{"spamhaus_sbl":{"status":"notlisted","query_time":"2026-11-26T00:00:00"},"spamrats":{"status":"failed","query_time":"2026-11-26T00:00:00"}},"pending_results":false,"parameters":{"resource":"163.5.251.1"}}}`), nil
	})
	r, e := s.Inspect(context.Background(), Query{Resource: "163.5.251.0/24", Checks: []string{"geolocation"}})
	if e != nil || len(r.Metrics) != 1 || r.Metrics[0].Status != "ok" || !strings.Contains(string(r.Metrics[0].Data), "database_estimate") {
		t.Fatal(e, r)
	}
	r, e = s.Inspect(context.Background(), Query{Resource: "163.5.251.1", Checks: []string{"dns_blocklists"}})
	if e != nil || !r.Partial || !strings.Contains(string(r.Metrics[0].Data), `"completeness":"partial"`) {
		t.Fatal("failed list became clean", e, r)
	}
}

func TestActiveMeasurementResumesWithoutResubmitting(t *testing.T) {
	posts := 0
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			posts++
			return response(202, `{"id":"test-measurement","probesCount":3}`), nil
		}
		if posts == 1 {
			return response(200, `{"id":"test-measurement","type":"ping","target":"163.5.251.1","status":"in-progress","results":[]}`), nil
		}
		return nil, nil
	})
	q := Query{Resource: "163.5.251.1", Checks: []string{"ping"}}
	r, e := s.Inspect(context.Background(), q)
	if e != nil || len(r.Metrics) != 1 || r.Metrics[0].Status != "pending" {
		t.Fatal(e, r)
	}
	c := s.cache.(*memoryCache)
	c.mu.Lock()
	for k, v := range c.rows {
		if strings.Contains(k, `"Name":"ping"`) {
			v.expires = time.Now().Add(-time.Second)
			c.rows[k] = v
		}
	}
	c.mu.Unlock()
	s.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			t.Error("duplicate measurement submitted")
		}
		return response(200, `{"id":"test-measurement","type":"ping","target":"163.5.251.1","status":"finished","results":[{"probe":{"country":"DE","asn":1},"result":{"status":"finished","resolvedAddress":"163.5.251.1","stats":{"total":3,"rcv":0,"drop":3,"loss":100,"min":null,"avg":null,"max":null}}}]}`), nil
	})
	r, e = s.Inspect(context.Background(), q)
	if e != nil || r.Metrics[0].Status != "ok" || posts != 1 || !strings.Contains(string(r.Metrics[0].Data), `"loss":100`) {
		t.Fatal(e, r, posts)
	}
}

func TestThroughputRequiresMatchingPublicEndpoint(t *testing.T) {
	s := mockService(t, func(*http.Request) (*http.Response, error) { return response(200, strings.Repeat("x", 65536)), nil })
	for _, u := range []string{"http://127.0.0.1/file", "http://163.5.250.1/file", "http://user:pass@163.5.251.1/file", "http://163.5.251.1:22/file"} {
		_, e := s.Inspect(context.Background(), Query{Resource: "163.5.251.0/24", Checks: []string{"throughput"}, TestURL: u})
		if e == nil {
			t.Fatalf("unsafe endpoint accepted %s", u)
		}
	}
	r, e := s.Inspect(context.Background(), Query{Resource: "163.5.251.0/24", Checks: []string{"throughput"}, TestURL: "http://163.5.251.1/test.bin"})
	if e != nil || r.Metrics[0].Status != "ok" {
		t.Fatal(e, r)
	}
	var d struct {
		Bytes int64   `json:"bytes_read"`
		Mbps  float64 `json:"mbps"`
	}
	if json.Unmarshal(r.Metrics[0].Data, &d) != nil || d.Bytes != 65536 || d.Mbps <= 0 {
		t.Fatal(string(r.Metrics[0].Data))
	}
}

func TestDNSBLChecksEveryAddressAndBoundsLargePrefixes(t *testing.T) {
	calls := 0
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls++
		resource := r.URL.Query().Get("resource")
		b, _ := json.Marshal(map[string]any{"status": "ok", "data": map[string]any{"blocklists": map[string]any{"test": map[string]string{"name": "Test list"}}, "data": map[string]any{"test": map[string]string{"status": "notlisted", "query_time": time.Now().UTC().Format(time.RFC3339)}}, "pending_results": false, "parameters": map[string]string{"resource": resource}}})
		return response(200, string(b)), nil
	})
	r, e := s.Inspect(context.Background(), Query{Resource: "163.5.251.0/31", Checks: []string{"dns_blocklists"}})
	if e != nil || r.Partial || calls != 2 || !strings.Contains(string(r.Metrics[0].Data), `"completed_addresses":2`) {
		t.Fatal(e, r, calls)
	}
	r, e = s.Inspect(context.Background(), Query{Resource: "163.5.0.0/16", Checks: []string{"dns_blocklists"}})
	if e != nil || r.Metrics[0].Status != "not_applicable" || calls != 2 {
		t.Fatal("unbounded scan", e, r, calls)
	}
}

func TestAllChecksAndAddressValidation(t *testing.T) {
	q := Query{Resource: "163.5.251.0/24", Checks: []string{"all"}, Address: "163.5.251.1"}
	if _, e := q.validate(); e != nil || len(q.Checks) != len(definitions) {
		t.Fatal(e, q)
	}
	for _, a := range []string{"127.0.0.1", "163.5.250.1", "AS218036"} {
		q = Query{Resource: "163.5.251.0/24", Checks: []string{"ping"}, Address: a}
		if _, e := q.validate(); e == nil {
			t.Fatal("invalid measurement target", a)
		}
	}
}

func TestDNSBLNeverPublishesPrivateResolverDetails(t *testing.T) {
	s := mockService(t, func(*http.Request) (*http.Response, error) {
		return response(200, `{"status":"ok","data":{"blocklists":{"test":{"name":"Test"}},"data":{"test":{"status":"failed:source-private-marker.test; DNS timeout","query_time":"2026-11-26T00:00:00"}},"pending_results":false,"parameters":{"resource":"163.5.251.1"}}}`), nil
	})
	r, e := s.Inspect(context.Background(), Query{Resource: "163.5.251.1", Checks: []string{"dns_blocklists"}})
	b, _ := json.Marshal(r)
	if e != nil || strings.Contains(string(b), "source-private-marker") {
		t.Fatal("source internal resolver details exposed")
	}
}

func TestPrefixDNSBLBoundsFailedRefreshAttempts(t *testing.T) {
	calls := 0
	s := mockService(t, func(*http.Request) (*http.Response, error) { calls++; return response(503, `{}`), nil })
	now, expires := time.Now().Add(-time.Hour), time.Now().Add(-time.Minute)
	for i := 0; i < 16; i++ {
		ip := fmt.Sprintf("163.5.251.%d", i)
		m := Metric{Name: "dns_blocklists", Status: "ok", SourceURL: "https://stat.ripe.net/data/dns-blocklists/data.json", ObservedAt: &now, ExpiresAt: &expires, Data: json.RawMessage(fmt.Sprintf(`{"address":"%s","completeness":"complete","findings":[]}`, ip))}
		b, _ := json.Marshal(m)
		s.cache.CachePut(context.Background(), metricKey(Target{Value: ip, Kind: "ip"}, Query{}, "dns_blocklists"), b, expires)
	}
	r, e := s.Inspect(context.Background(), Query{Resource: "163.5.251.0/28", Checks: []string{"dns_blocklists"}})
	if e != nil || !r.Partial || calls > 8 {
		t.Fatalf("failed refresh escaped batch limit: calls=%d err=%v", calls, e)
	}
}

func TestExtendedMissingObservationsRemainUnknown(t *testing.T) {
	s := New(nil, false, "", 120)
	r, e := s.Inspect(context.Background(), Query{Resource: "163.5.251.1", Checks: []string{"throughput", "geolocation", "ping"}})
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range r.Metrics {
		if m.Observation.Completeness != "unknown" {
			t.Fatalf("missing %s completeness=%q", m.Name, m.Observation.Completeness)
		}
	}
}

func TestPassiveCacheIgnoresMeasurementOptions(t *testing.T) {
	target := Target{Value: "163.5.251.0/24", Kind: "prefix"}
	for _, name := range []string{"registration", "dns_blocklists", "geolocation", "asn_relationships"} {
		a := metricKey(target, Query{}, name)
		b := metricKey(target, Query{Address: "163.5.251.1", TestURL: "http://163.5.251.1/test.bin"}, name)
		if a != b {
			t.Fatalf("%s cache fragmented by unrelated measurement options", name)
		}
	}
}

func TestPrefixDNSBLAdvancesPastIncompleteAddresses(t *testing.T) {
	calls := 0
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls++
		b, _ := json.Marshal(map[string]any{"status": "ok", "data": map[string]any{"blocklists": map[string]any{"test": map[string]string{"name": "Test"}}, "data": map[string]any{"test": map[string]string{"status": "failed", "query_time": time.Now().UTC().Format(time.RFC3339)}}, "pending_results": false, "parameters": map[string]string{"resource": r.URL.Query().Get("resource")}}})
		return response(200, string(b)), nil
	})
	q := Query{Resource: "163.5.251.0/28", Checks: []string{"dns_blocklists"}}
	s.Inspect(context.Background(), q)
	c := s.cache.(*memoryCache)
	target, _ := ParseTarget(q.Resource)
	key := metricKey(target, q, "dns_blocklists")
	c.mu.Lock()
	row := c.rows[key]
	row.expires = time.Now().Add(-time.Second)
	c.rows[key] = row
	c.mu.Unlock()
	r, e := s.Inspect(context.Background(), q)
	if e != nil || calls != 16 || !strings.Contains(string(r.Metrics[0].Data), `"processed_addresses":16`) {
		t.Fatal("incomplete first batch starved remaining addresses", e, calls)
	}
}

func TestDNSBLSourceErrorCodeIsNotAListing(t *testing.T) {
	s := mockService(t, func(*http.Request) (*http.Response, error) {
		return response(200, `{"status":"ok","data":{"blocklists":{"spamhaus_sbl":{"name":"SBL"}},"data":{"spamhaus_sbl":{"status":"listed:127.255.255.254","query_time":"2026-11-26T00:00:00"}},"pending_results":false,"parameters":{"resource":"163.5.251.1"}}}`), nil
	})
	r, e := s.Inspect(context.Background(), Query{Resource: "163.5.251.1", Checks: []string{"dns_blocklists"}})
	if e != nil || strings.Contains(string(r.Metrics[0].Data), `"status":"listed"`) {
		t.Fatal("source access error became a listing")
	}
}

func TestDNSBLMissingResultsHaveNoObservation(t *testing.T) {
	s := mockService(t, func(*http.Request) (*http.Response, error) {
		return response(200, `{"status":"ok","data":{"blocklists":{"test":{"name":"Test"}},"data":{},"pending_results":false,"parameters":{"resource":"163.5.251.1"}}}`), nil
	})
	r, e := s.Inspect(context.Background(), Query{Resource: "163.5.251.1", Checks: []string{"dns_blocklists"}})
	if e != nil || r.Metrics[0].Status == "ok" || r.Metrics[0].ObservedAt != nil {
		t.Fatal("empty source results invented an observation")
	}
}

func TestPrefixDNSBLDoesNotCountBudgetDenialsAsResponses(t *testing.T) {
	s := mockService(t, func(*http.Request) (*http.Response, error) { return response(200, `{}`), nil })
	s.rpm = 1
	s.request(context.Background(), "https://stat.ripe.net/test", "")
	r, e := s.Inspect(context.Background(), Query{Resource: "163.5.251.0/28", Checks: []string{"dns_blocklists"}})
	var d struct {
		Processed int `json:"processed_addresses"`
	}
	if e != nil || json.Unmarshal(r.Metrics[0].Data, &d) != nil || d.Processed != 0 {
		t.Fatal("budget denial counted as source response", d.Processed, e)
	}
}

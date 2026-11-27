package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

func irrMetadataFixture(now time.Time) string { return irrdStatusFixture(now) }

func enableIRR(t *testing.T, s *Service) {
	t.Helper()
	if err := s.EnableIRR(DefaultIRRdURL); err != nil {
		t.Fatal(err)
	}
}

func irrMetadataRequest(r *http.Request) bool {
	var body struct {
		Query string `json:"query"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&body)
	}
	return strings.Contains(body.Query, "databaseStatus")
}

func irrFixture(prefix string, asns ...uint32) string {
	rows := []any{}
	class := "route"
	if strings.Contains(prefix, ":") {
		class = "route6"
	}
	for _, asn := range asns {
		rows = append(rows, map[string]any{"objectClass": class, "prefix": prefix, "origin": fmt.Sprintf("AS%d", asn), "rpslPk": fmt.Sprintf("%sAS%d", prefix, asn), "source": "RIPE", "objectText": "private-contact@example.net", "rpkiStatus": "INVALID"})
	}
	b, _ := json.Marshal(map[string]any{"data": map[string]any{"rpslObjects": rows}, "bgpOrigins": []uint32{999}, "categoryOverall": "success"})
	return string(b)
}

func irrMetric(t *testing.T, prefix, routes, metadata string) Metric {
	t.Helper()
	target, _ := ParseTarget(prefix)
	d, err := normalizeIRR([]byte(routes), []byte(metadata), target, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now, expires := time.Now().UTC(), time.Now().UTC().Add(time.Hour)
	b, _ := json.Marshal(d)
	return Metric{Name: "irr", Status: "ok", Source: "IRRd", SourceURL: irrMetadataURL, Data: b, ObservedAt: &now, ExpiresAt: &expires}
}

func TestIRRConsistencyScopesAndOutcomes(t *testing.T) {
	for _, family := range []struct{ prefix, cover, child, class string }{
		{"1.1.1.0/24", "1.1.0.0/16", "1.1.1.0/25", "route"},
		{"2001:4860:4860::/48", "2001:4860::/32", "2001:4860:4860::/49", "route6"},
	} {
		for _, tc := range []struct {
			name, route string
			asns        []uint32
			want        string
		}{
			{"consistent", family.prefix, []uint32{13335}, "consistent"},
			{"conflict", family.prefix, []uint32{13336}, "conflict"},
			{"mixed conflict", family.prefix, []uint32{13335, 13336}, "conflict"},
			{"duplicates", family.prefix, []uint32{13335, 13335}, "consistent"},
			{"covering", family.cover, []uint32{13335}, "missing_objects"},
			{"contained", family.child, []uint32{13335}, "missing_objects"},
			{"missing", family.prefix, nil, "missing_objects"},
		} {
			t.Run(family.class+tc.name, func(t *testing.T) {
				r := reportFixture(t)
				r.Resource.Value = family.prefix
				r.Metrics[0].Data = []byte(strings.ReplaceAll(string(r.Metrics[0].Data), "1.1.1.0/24", family.prefix))
				m := irrMetric(t, family.prefix, irrFixture(tc.route, tc.asns...), irrMetadataFixture(time.Now()))
				r.Metrics = append(r.Metrics, m)
				c := summarizeIRR(r, time.Now())
				if c.IRR == nil || c.Status != tc.want || c.IRR.Completeness != "complete" {
					t.Fatalf("got %+v %+v", c, c.IRR)
				}
				if len(c.IRR.Objects) != len(tc.asns) {
					t.Fatal("duplicates lost", c.IRR.Objects)
				}
				for _, object := range c.IRR.Objects {
					if object.Class != family.class {
						t.Fatal(object)
					}
				}
				if strings.Contains(string(m.Data), "private-contact") || strings.Contains(string(m.Data), "categoryOverall") {
					t.Fatal("raw source text or score leaked")
				}
			})
		}
	}
}

func TestIRRUsesOwnObservedBGPAndFreshness(t *testing.T) {
	for _, kind := range []string{"absent", "unavailable", "stale_bgp", "filtered_bgp", "origin_change", "stale_registry", "missing_metadata"} {
		t.Run(kind, func(t *testing.T) {
			r := reportFixture(t)
			metadata := irrMetadataFixture(time.Now())
			switch kind {
			case "absent":
				r.Metrics[0].Data = json.RawMessage(`{"resource":"1.1.1.0/24","is_less_specific":false,"announced":false,"num_filtered_out":0,"asns":[]}`)
			case "unavailable":
				r.Metrics[0].Status = "unavailable"
			case "stale_bgp":
				past := time.Now().Add(-time.Hour)
				r.Metrics[0].ExpiresAt = &past
			case "filtered_bgp":
				r.Metrics[0].Data = []byte(strings.ReplaceAll(string(r.Metrics[0].Data), `"num_filtered_out":0`, `"num_filtered_out":1`))
			case "origin_change":
				r.Metrics[0].Data = []byte(strings.ReplaceAll(string(r.Metrics[0].Data), "13335", "13336"))
			case "stale_registry":
				metadata = irrMetadataFixture(time.Now().Add(-48 * time.Hour))
			case "missing_metadata":
				metadata = `{}`
			}
			r.Metrics = append(r.Metrics, irrMetric(t, r.Resource.Value, irrFixture(r.Resource.Value, 13335), metadata))
			c := summarizeIRR(r, time.Now())
			if c.Status == "consistent" {
				t.Fatal("uncertain evidence passed", c.IRR)
			}
			want := "bgp_unavailable"
			switch kind {
			case "absent":
				want = "bgp_absent"
			case "origin_change":
				want = "conflict"
			case "stale_registry", "missing_metadata":
				want = "partial"
			}
			if c.Status != want {
				t.Fatalf("want %s got %s", want, c.Status)
			}
			if kind == "stale_registry" && c.Freshness != "stale" {
				t.Fatal("old source date became fresh")
			}
		})
	}
}

func TestIRRDefaultOffUnsupportedScopeAndPublicReads(t *testing.T) {
	var calls atomic.Int32
	s := mockService(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return response(500, `{"secret":"not public"}`), nil
	})
	for _, enabled := range []bool{false, true} {
		s.irrEnabled = enabled
		for _, prefix := range []string{"1.0.0.0/8", "2001:4860::/28", "1.1.1.1", "AS13335"} {
			r, err := s.Inspect(context.Background(), Query{Resource: prefix, Checks: []string{"irr"}})
			if err != nil {
				t.Fatal(err)
			}
			want := "not_configured"
			if enabled {
				want = "not_applicable"
			}
			if r.Metrics[0].Status != want {
				t.Fatal(r)
			}
		}
	}
	s.Cached(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"irr"}})
	if calls.Load() != 0 {
		t.Fatal("unsupported/off/public read made requests", calls.Load())
	}
}

func TestIRRCollectorBudgetFailuresAndCache(t *testing.T) {
	for _, code := range []int{200, 401, 403, 404, 429, 503} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var calls atomic.Int32
			s := mockService(t, func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				if irrMetadataRequest(r) {
					return response(200, irrMetadataFixture(time.Now())), nil
				}
				if code == 200 {
					return response(200, irrFixture("1.1.1.0/24", 13335)), nil
				}
				out := response(code, `{"secret":"not public"}`)
				out.Header.Set("Retry-After", "3600")
				return out, nil
			})
			enableIRR(t, s)
			overview := reportFixture(t).Metrics[0]
			target, _ := ParseTarget("1.1.1.0/24")
			m := s.metric(context.Background(), target, Query{overview: &overview}, "irr")
			if code == 200 {
				if m.IRR == nil || m.IRR.Status != "consistent" || calls.Load() != 2 {
					t.Fatal(m, calls.Load())
				}
			} else if m.IRR != nil || m.Status == "ok" || calls.Load() != 1 || strings.Contains(string(m.Data), "secret") || code == 404 && m.Status == "no_data" {
				t.Fatal("source failure became missing objects", m)
			}
			if code == 429 {
				restarted := New(s.cache, true, "", 120)
				enableIRR(t, restarted)
				restarted.client.Transport = s.client.Transport
				if _, err := restarted.irrd(context.Background(), `query { databaseStatus { source } }`, nil); err == nil || calls.Load() != 1 {
					t.Fatal("source cooldown lost")
				}
			}
		})
	}
}

func TestIRRPartialMetadataAndObjectBounds(t *testing.T) {
	target, _ := ParseTarget("1.1.1.0/24")
	for _, raw := range []string{"null", `{}`, `{"error":"not a list"}`} {
		if _, err := normalizeIRR([]byte(raw), []byte(irrMetadataFixture(time.Now())), target, time.Now()); err == nil {
			t.Fatal("accepted invalid response")
		}
	}
	asns := make([]uint32, irrObjectLimit+1)
	for i := range asns {
		asns[i] = 13335
	}
	d, err := normalizeIRR([]byte(irrFixture(target.Value, asns...)), []byte(irrMetadataFixture(time.Now())), target, time.Now())
	if err != nil || !d.Truncated || len(d.Objects) != irrObjectLimit || d.Completeness != "partial" {
		t.Fatal(d, err)
	}
	d, err = normalizeIRR([]byte(`{"data":{"rpslObjects":[]}}`), []byte(`{}`), target, time.Now())
	if err != nil || d.Completeness != "partial" {
		t.Fatal("metadata gap became absence", d, err)
	}
}

func TestIRRAutomaticPublishOriginChangeAndRestart(t *testing.T) {
	var calls atomic.Int32
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		switch {
		case r.URL.Host == "subregator-irrd:8000":
			if irrMetadataRequest(r) {
				return response(200, irrMetadataFixture(time.Now())), nil
			}
			return response(200, irrFixture("1.1.1.0/24", 13335, 13335)), nil
		case strings.Contains(r.URL.Path, "prefix-overview"):
			return response(200, `{"status":"ok","data":{"resource":"1.1.1.0/24","announced":true,"is_less_specific":false,"num_filtered_out":0,"asns":[13335]}}`), nil
		case r.URL.Host == "www.spamhaus.org":
			return response(200, dropFixture(time.Now())), nil
		default:
			return response(503, `{}`), nil
		}
	})
	enableIRR(t, s)
	a := NewAutomatic(s)
	store := reviewStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.Run(ctx, store) }()
	deadline := time.Now().Add(3 * time.Second)
	for a.Get("1.1.1.0/24").IRR.Status != "consistent" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	c := a.Get("1.1.1.0/24").IRR
	if c.Status != "consistent" || len(c.IRR.Objects) != 2 {
		t.Fatal("worker lost objects", c)
	}
	overview := reportFixture(t).Metrics[0]
	overview.Data = json.RawMessage(`{"resource":"1.1.1.0/24","announced":true,"is_less_specific":false,"num_filtered_out":0,"asns":[13336]}`)
	target, _ := ParseTarget("1.1.1.0/24")
	b, _ := json.Marshal(overview)
	s.cache.CachePut(context.Background(), metricKey(target, Query{}, "prefix_overview"), b, *overview.ExpiresAt)
	a.completeCheck(context.Background(), checkResult{Key: target.Value, Name: "prefix_overview", Metric: overview})
	if c = a.Get(target.Value).IRR; c.Status != "conflict" {
		t.Fatal("origin change kept old IRR match", c)
	}
	count := calls.Load()
	s.network = false
	restored := NewAutomatic(s)
	restored.restoreSchedule(context.Background(), target.Value, append(slices.Clone(automaticChecks), "spamhaus_drop"))
	if c = restored.Get(target.Value).IRR; c.Status != "conflict" || len(c.IRR.Objects) != 2 || calls.Load() != count {
		t.Fatal("restart lost comparison or made request", c)
	}
	s.irrEnabled = false
	if c = restored.Get(target.Value).IRR; c.Status != "not_configured" || c.IRR != nil {
		t.Fatal("off gate published retained objects", c)
	}
}

func TestIRRMetadataFailureRemainsPartial(t *testing.T) {
	var calls atomic.Int32
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return response(200, irrFixture("1.1.1.0/24", 13335)), nil
	})
	enableIRR(t, s)
	s.rpm = 1
	target, _ := ParseTarget("1.1.1.0/24")
	overview := reportFixture(t).Metrics[0]
	m := s.metric(context.Background(), target, Query{overview: &overview}, "irr")
	if calls.Load() != 2 || m.IRR == nil || m.IRR.Status != "partial" || time.Until(*m.ExpiresAt) > time.Minute+time.Second {
		t.Fatal("metadata budget gap passed or retained for full TTL", m)
	}
}

func TestIRRRegressionReadsCannotMutatePublishedReport(t *testing.T) {
	s := New(nil, false, "", 120)
	enableIRR(t, s)
	a := NewAutomatic(s)
	r := reportFixture(t)
	r.Metrics = append(r.Metrics, irrMetric(t, r.Resource.Value, irrFixture(r.Resource.Value, 13335), irrMetadataFixture(time.Now())))
	check := summarizeIRR(r, time.Now())
	a.reports[r.Resource.Value] = OfferChecks{IRR: &check}
	before, _ := json.Marshal(a.reports[r.Resource.Value])
	a.Get(r.Resource.Value)
	after, _ := json.Marshal(a.reports[r.Resource.Value])
	if string(before) != string(after) {
		t.Fatal("read changed the shared published report")
	}
}

func TestIRRRegressionUnsupportedParametersNeverCollect(t *testing.T) {
	var calls atomic.Int32
	s := mockService(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return response(200, `[]`), nil })
	enableIRR(t, s)
	for _, q := range []Query{
		{Resource: "1.1.1.0/24", Checks: []string{"irr"}, ASN: 13335},
		{Resource: "1.1.1.0/24", Checks: []string{"irr"}, Version: "1"},
		{Resource: "1.1.1.0/24", Checks: []string{"irr"}, StartTime: "2020-01-01T00:00:00Z", EndTime: "2020-01-02T00:00:00Z"},
	} {
		r, err := s.Inspect(context.Background(), q)
		if err != nil || r.Metrics[0].Status != "not_applicable" || calls.Load() != 0 {
			t.Fatal("unsupported parameters collected current data", r, err, calls.Load())
		}
	}
}

func TestIRRHiddenPrefixesAndCancellation(t *testing.T) {
	t.Run("hidden", func(t *testing.T) {
		source := reviewStore(t)
		provider := source.View().Providers[0]
		provider.Policy.PrefixVisibility = "hidden"
		store, err := catalog.NewStore("", []catalog.Provider{provider})
		if err != nil {
			t.Fatal(err)
		}
		if err = store.Apply(provider.ID, source.View().Offers, nil, time.Now()); err != nil {
			t.Fatal(err)
		}
		if len(publishedPrefixes(store)) != 0 {
			t.Fatal("hidden prefix eligible for IRR")
		}
		var calls atomic.Int32
		s := mockService(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return response(200, `[]`), nil })
		enableIRR(t, s)
		a := NewAutomatic(s)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); a.Run(ctx, store) }()
		time.Sleep(10 * time.Millisecond)
		cancel()
		<-done
		if calls.Load() != 0 {
			t.Fatal("hidden prefix collected")
		}
	})
	t.Run("cancel", func(t *testing.T) {
		started := make(chan struct{})
		s := mockService(t, func(r *http.Request) (*http.Response, error) {
			if irrMetadataRequest(r) {
				close(started)
				<-r.Context().Done()
				return nil, r.Context().Err()
			}
			return response(200, irrFixture("1.1.1.0/24", 13335)), nil
		})
		enableIRR(t, s)
		ctx, cancel := context.WithCancel(context.Background())
		target, _ := ParseTarget("1.1.1.0/24")
		overview := reportFixture(t).Metrics[0]
		done := make(chan struct{})
		go func() { defer close(done); s.metric(ctx, target, Query{overview: &overview}, "irr") }()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("metadata not started")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("cancellation ignored")
		}
		_, _, found, _ := s.cache.CacheGet(context.Background(), metricKey(target, Query{}, "irr"))
		if found || len(s.httpSlots) != 0 {
			t.Fatal("cancelled collection saved data or retained HTTP slot")
		}
	})
}

func TestIRROversizedResponseCannotPass(t *testing.T) {
	s := mockService(t, func(*http.Request) (*http.Response, error) {
		return response(200, "["+strings.Repeat(" ", 1<<20)+"]"), nil
	})
	enableIRR(t, s)
	r, err := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"irr"}})
	if err != nil || r.Metrics[0].Status != "unavailable" || r.Metrics[0].IRR != nil {
		t.Fatal("oversized response accepted", err)
	}
}

func TestIRRRegressionExpiredEvidenceCannotRemainConsistent(t *testing.T) {
	r := reportFixture(t)
	m := irrMetric(t, r.Resource.Value, irrFixture(r.Resource.Value, 13335), irrMetadataFixture(time.Now()))
	past := time.Now().Add(-time.Hour)
	m.ExpiresAt = &past
	r.Metrics = append(r.Metrics, m)
	c := summarizeIRR(r, time.Now())
	if c.IRR.Status == "consistent" {
		t.Fatal("expired IRR evidence retained a passing explanation")
	}
}

func TestIRRRegressionReadAgesStoredPassingExplanation(t *testing.T) {
	s := New(nil, false, "", 120)
	enableIRR(t, s)
	a := NewAutomatic(s)
	r := reportFixture(t)
	r.Metrics = append(r.Metrics, irrMetric(t, r.Resource.Value, irrFixture(r.Resource.Value, 13335), irrMetadataFixture(time.Now())))
	check := summarizeIRR(r, time.Now())
	past := time.Now().Add(-time.Hour)
	check.ExpiresAt = &past
	a.reports[r.Resource.Value] = OfferChecks{IRR: &check}
	got := a.Get(r.Resource.Value).IRR
	if got.IRR.Status == "consistent" || got.Status == "consistent" || got.Freshness != "stale" {
		t.Fatal("stored passing IRR explanation did not expire")
	}
}

func TestIRRMultiOriginAndCrossRegistryConflict(t *testing.T) {
	r := reportFixture(t)
	r.Metrics[0].Data = json.RawMessage(`{"resource":"1.1.1.0/24","is_less_specific":false,"announced":true,"num_filtered_out":0,"asns":[13336,13335,13335]}`)
	for _, tc := range []struct {
		routes, status string
		missing        int
	}{
		{irrFixture(r.Resource.Value, 13335, 13336), "consistent", 0},
		{irrFixture(r.Resource.Value, 13335), "missing_objects", 1},
		{`{"data":{"rpslObjects":[{"objectClass":"route","prefix":"1.1.1.0/24","source":"RIPE","origin":"AS13335"},{"objectClass":"route","prefix":"1.1.1.0/24","source":"APNIC","origin":"AS13337"}]}}`, "conflict", 1},
	} {
		report := r
		report.Metrics = append(slices.Clone(r.Metrics), irrMetric(t, r.Resource.Value, tc.routes, irrMetadataFixture(time.Now())))
		c := summarizeIRR(report, time.Now())
		if c.Status != tc.status || len(c.IRR.MissingOrigins) != tc.missing {
			t.Fatal(c.IRR)
		}
	}
}

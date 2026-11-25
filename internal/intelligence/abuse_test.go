package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

func abuseFixture(now time.Time, subset bool, rows ...map[string]any) string {
	min, max, hosts := "1.1.1.0", "1.1.1.255", 256
	if subset {
		min, max, hosts = "1.1.1.1", "1.1.1.254", 254
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	b, _ := json.Marshal(map[string]any{"data": map[string]any{"networkAddress": "1.1.1.0", "netmask": "255.255.255.0", "minAddress": min, "maxAddress": max, "numPossibleHosts": hosts, "reportedAddress": rows}})
	return string(b)
}
func abuseRow(now time.Time) map[string]any {
	return map[string]any{"ipAddress": "1.1.1.2", "numReports": 3, "mostRecentReport": now.Add(-time.Hour).Format(time.RFC3339Nano), "abuseConfidenceScore": 70, "comment": "private complaint text", "reporterId": 123}
}
func abuseMetric(t *testing.T, subset bool, rows ...map[string]any) Metric {
	t.Helper()
	now := time.Now().UTC()
	target, _ := ParseTarget("1.1.1.0/24")
	detail, err := normalizeAbuse([]byte(abuseFixture(now, subset, rows...)), target, now.Add(-time.Second), now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(detail)
	expires := now.Add(24 * time.Hour)
	return Metric{Name: "abuse", Status: "ok", Source: "AbuseIPDB", SourceURL: abuseEndpoint, Data: b, ObservedAt: &now, ExpiresAt: &expires}
}

func TestAbuseScopeCountsTimesAndPrivacy(t *testing.T) {
	now := time.Now().UTC()
	target, _ := ParseTarget("1.1.1.0/24")
	for _, subset := range []bool{false, true} {
		for _, hasReports := range []bool{false, true} {
			rows := []map[string]any{}
			if hasReports {
				rows = append(rows, abuseRow(now))
			}
			raw := abuseFixture(now, subset, rows...)
			d, err := normalizeAbuse([]byte(raw), target, now.Add(-time.Second), now)
			if err != nil {
				t.Fatal(err)
			}
			want := "no_reports_in_window"
			if hasReports {
				want = "reports_observed"
			}
			if subset {
				want = "partial"
			}
			if d.Status != want || d.CountsAreLowerBounds != subset || d.WindowDays != 30 || d.IngestedAt != now || d.WindowBasis != "local_request_bounds" || d.DetailsCoverage != "not_collected" {
				t.Fatal(d)
			}
			if hasReports && (d.ReportedIPCount != 1 || d.ReportCount != 3 || d.LatestReportAt == nil || d.Addresses[0].SourceConfidence == nil || *d.Addresses[0].SourceConfidence != 70) {
				t.Fatal(d)
			}
			encoded, _ := json.Marshal(d)
			for _, private := range []string{"private complaint", "reporterId", "countryCode", "comment"} {
				if strings.Contains(string(encoded), private) {
					t.Fatal("raw complaint data leaked")
				}
			}
			m := abuseMetric(t, subset, rows...)
			m = decorateAbuse(m, target, now)
			observation := metricObservation(m, target, Query{}, now)
			if subset && (observation.Scope.Relation != "contained" || observation.Completeness != "partial" || observation.Scope.Resource == target.Value) {
				t.Fatal("host range became full prefix", observation)
			}
		}
	}
}

func TestAbuseMalformedUnknownAndTruncatedResponses(t *testing.T) {
	now := time.Now().UTC()
	target, _ := ParseTarget("1.1.1.0/24")
	for _, raw := range []string{`{}`, `{"data":null}`, `{"data":{}}`, strings.Replace(abuseFixture(now, false), `"reportedAddress":[]`, `"reportedAddress":null`, 1), strings.Replace(abuseFixture(now, false), "1.1.1.0", "2.2.2.0", 1), strings.Replace(abuseFixture(now, false), "255.255.255.0", "255.0.255.0", 1)} {
		if _, err := normalizeAbuse([]byte(raw), target, now, now); err == nil {
			t.Fatal("accepted invalid or wrong-scope response")
		}
	}
	for _, kind := range []string{"missing_time", "future_time", "old_time", "duplicate", "outside", "missing_count", "negative_count", "pagination", "truncated", "overflow"} {
		t.Run(kind, func(t *testing.T) {
			row := abuseRow(now)
			rows := []map[string]any{row}
			switch kind {
			case "missing_time":
				delete(row, "mostRecentReport")
			case "future_time":
				row["mostRecentReport"] = now.Add(time.Hour).Format(time.RFC3339Nano)
			case "old_time":
				row["mostRecentReport"] = now.Add(-40 * 24 * time.Hour).Format(time.RFC3339Nano)
			case "duplicate":
				rows = append(rows, row)
			case "outside":
				row["ipAddress"] = "2.2.2.2"
			case "missing_count":
				delete(row, "numReports")
			case "negative_count":
				row["numReports"] = -1
			case "overflow":
				row["numReports"] = int64(9223372036854775807)
				second := abuseRow(now)
				second["ipAddress"] = "1.1.1.3"
				rows = append(rows, second)
			}
			raw := abuseFixture(now, false, rows...)
			if kind == "pagination" {
				raw = strings.Replace(raw, `"data":{`, `"data":{"nextPageUrl":"https://invalid.example/?key=private",`, 1)
			}
			if kind == "truncated" {
				raw = strings.Replace(raw, `"data":{`, `"data":{"truncated":true,`, 1)
			}
			d, err := normalizeAbuse([]byte(raw), target, now, now)
			if kind == "overflow" {
				if err == nil {
					t.Fatal("report count overflow accepted")
				}
				return
			}
			if err != nil || d.Status != "partial" || d.Completeness != "partial" || !d.CountsAreLowerBounds {
				t.Fatal(d, err)
			}
			if kind == "duplicate" && d.ReportCount != 3 {
				t.Fatal("duplicate inflated totals")
			}
			b, _ := json.Marshal(d)
			if strings.Contains(string(b), "invalid.example") || strings.Contains(string(b), "key=") {
				t.Fatal("continuation URL leaked")
			}
		})
	}
}

func TestAbuseOffUnsupportedAndCachedReads(t *testing.T) {
	var calls atomic.Int32
	s := mockService(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return response(503, `{}`), nil })
	for _, q := range []Query{{Resource: "1.1.1.0/24", Checks: []string{"abuse"}}, {Resource: "1.1.0.0/16", Checks: []string{"abuse"}}} {
		r, err := s.Inspect(context.Background(), q)
		if err != nil || r.Metrics[0].Status != "not_configured" {
			t.Fatal(r, err)
		}
	}
	s.EnableAbuseIPDB("fixture-key")
	for _, q := range []Query{
		{Resource: "1.1.0.0/23", Checks: []string{"abuse"}},
		{Resource: "2001:4860::/32", Checks: []string{"abuse"}},
		{Resource: "2001:4860::/128", Checks: []string{"abuse"}},
		{Resource: "1.1.1.1", Checks: []string{"abuse"}},
		{Resource: "AS13335", Checks: []string{"abuse"}},
		{Resource: "1.1.1.0/24", Checks: []string{"abuse"}, ASN: 13335},
		{Resource: "1.1.1.0/24", Checks: []string{"abuse"}, Version: "1"},
		{Resource: "1.1.1.0/24", Checks: []string{"abuse"}, StartTime: "2020-01-01T00:00:00Z", EndTime: "2020-01-02T00:00:00Z"},
	} {
		r, err := s.Inspect(context.Background(), q)
		if err != nil || r.Metrics[0].Status != "not_applicable" {
			t.Fatal(r, err)
		}
	}
	s.Cached(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"abuse"}})
	if calls.Load() != 0 {
		t.Fatal("unsupported/off/public request collected a source")
	}
}

func TestAbuseHeadersErrorsAndSharedLimits(t *testing.T) {
	for _, code := range []int{200, 401, 402, 403, 404, 429, 503} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var calls atomic.Int32
			s := mockService(t, func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				if r.URL.Host != "api.abuseipdb.com" || r.Header.Get("Key") != "fixture-key" || r.Header.Get("Authorization") != "" || r.URL.Query().Get("maxAgeInDays") != "30" || r.URL.Query().Get("network") != "1.1.1.0/24" || strings.Contains(r.URL.RawQuery, "fixture-key") {
					t.Fatal("credential or query boundary failed")
				}
				if code == 200 {
					return response(200, abuseFixture(time.Now(), false, abuseRow(time.Now()))), nil
				}
				out := response(code, `{"errors":[{"detail":"fixture-key private payload"}]}`)
				if code == 429 {
					out.Header.Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(4*time.Hour).Unix()))
				}
				return out, nil
			})
			s.EnableAbuseIPDB("fixture-key")
			q := Query{Resource: "1.1.1.0/24", Checks: []string{"abuse"}}
			r, err := s.Inspect(context.Background(), q)
			if err != nil || calls.Load() != 1 {
				t.Fatal(err, calls.Load())
			}
			m := r.Metrics[0]
			if strings.Contains(m.Error, "fixture-key") || strings.Contains(string(m.Data), "private payload") {
				t.Fatal("upstream error leaked")
			}
			switch code {
			case 200:
				if m.Abuse == nil || m.Abuse.Status != "reports_observed" {
					t.Fatal(m)
				}
			case 402:
				if m.Status != "plan_limited" || time.Until(nextCheck(m, scheduledCheck{}, time.Now()).Next) < 23*time.Hour {
					t.Fatal("plan failure not explicit or repeatedly scheduled", m)
				}
			default:
				if m.Status == "ok" || m.Status == "no_data" || m.Abuse != nil {
					t.Fatal("source failure became zero reports", m)
				}
			}
			if code == 200 {
				cached, _ := s.Cached(context.Background(), q)
				if cached.Metrics[0].Abuse.ReportCount != 3 || calls.Load() != 1 {
					t.Fatal("cached read collected or lost observation")
				}
			}
			if code == 429 {
				if m.RetryAt == nil || time.Until(*m.RetryAt) < 3*time.Hour {
					t.Fatal("daily reset ignored")
				}
				restarted := New(s.cache, true, "", 120)
				restarted.EnableAbuseIPDB("fixture-key")
				restarted.client.Transport = s.client.Transport
				if _, err := restarted.request(context.Background(), abuseEndpoint, "fixture-key"); err == nil || calls.Load() != 1 {
					t.Fatal("quota window did not survive restart")
				}
			}
		})
	}
}

func TestAbuseExpiryReadImmutabilityAndAgingWindow(t *testing.T) {
	s := New(&memoryCache{}, false, "", 120)
	s.EnableAbuseIPDB("fixture-key")
	a := NewAutomatic(s)
	r := Report{Resource: Target{Value: "1.1.1.0/24", Kind: "prefix"}, Metrics: []Metric{abuseMetric(t, false, abuseRow(time.Now()))}}
	c := summarizeAbuse(r, time.Now())
	a.reports[r.Resource.Value] = OfferChecks{Abuse: &c}
	before, _ := json.Marshal(a.reports[r.Resource.Value])
	got := a.Get(r.Resource.Value).Abuse
	after, _ := json.Marshal(a.reports[r.Resource.Value])
	if string(before) != string(after) || got.Status != "reports_observed" {
		t.Fatal("read mutated shared observation")
	}
	past := time.Now().Add(-time.Hour)
	c.ExpiresAt = &past
	got = a.Get(r.Resource.Value).Abuse
	if got.Status != "partial" || got.Freshness != "stale" || got.Abuse.IngestedAt != c.Abuse.IngestedAt {
		t.Fatal("expiry passed or rewrote ingestion time")
	}
	r.Metrics = []Metric{abuseMetric(t, false)}
	c = summarizeAbuse(r, time.Now())
	if c.Status != "no_reports_in_window" || strings.Contains(c.Reason, "resolved") || c.Abuse.Semantics != "source_reports_not_cleanliness_tenant_attribution_or_resolution" {
		t.Fatal("aging out became resolution or cleanliness")
	}
	s.abuseEnabled = false
	a.reports[r.Resource.Value] = OfferChecks{Abuse: &c}
	if got = a.Get(r.Resource.Value).Abuse; got.Status != "not_configured" || got.Abuse != nil {
		t.Fatal("off gate exposed retained data")
	}
}

func TestAbuseRegressionErrorEnvelopeCannotEstablishZeroReports(t *testing.T) {
	now := time.Now().UTC()
	target, _ := ParseTarget("1.1.1.0/24")
	raw := strings.Replace(abuseFixture(now, false), `{"data":`, `{"errors":[{"detail":"incomplete source response"}],"data":`, 1)
	if _, err := normalizeAbuse([]byte(raw), target, now, now); err == nil {
		t.Fatal("source error envelope established zero reports")
	}
}

func TestAbuseRegressionPlanPauseExpires(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Second)
	next := nextCheck(Metric{Name: "abuse", Status: "plan_limited", ExpiresAt: &past}, scheduledCheck{}, now)
	if next.Next.IsZero() || next.Next.After(now.Add(time.Minute)) {
		t.Fatal("expired plan pause suppressed collection forever")
	}
}

func TestAbuseAutomaticWorkerRestartAndNoExtraDetailCalls(t *testing.T) {
	var abuseCalls atomic.Int32
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "api.abuseipdb.com" {
			abuseCalls.Add(1)
			if r.URL.Path != "/api/v2/check-block" {
				t.Fatal("per-IP details were fetched")
			}
			return response(200, abuseFixture(time.Now(), false, abuseRow(time.Now()))), nil
		}
		if r.Header.Get("Key") != "" {
			t.Fatal("abuse key forwarded to another source")
		}
		if r.URL.Host == "www.spamhaus.org" {
			return response(200, dropFixture(time.Now())), nil
		}
		return response(503, `{}`), nil
	})
	s.EnableAbuseIPDB("fixture-key")
	a := NewAutomatic(s)
	store := reviewStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.Run(ctx, store) }()
	deadline := time.Now().Add(3 * time.Second)
	for a.Get("1.1.1.0/24").Abuse.Status != "reports_observed" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if a.Get("1.1.1.0/24").Abuse.Status != "reports_observed" || abuseCalls.Load() != 1 {
		t.Fatal("worker failed or performed extra requests")
	}
	s.network = false
	restored := NewAutomatic(s)
	restored.restoreSchedule(context.Background(), "1.1.1.0/24", append(append([]string{}, automaticChecks...), "spamhaus_drop"))
	got := restored.Get("1.1.1.0/24").Abuse
	if got.Abuse == nil || got.Abuse.ReportCount != 3 || abuseCalls.Load() != 1 {
		t.Fatal("restart lost observations or fetched details")
	}
}

func TestAbuseCancellationSizeAndHiddenPrefixes(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		started := make(chan struct{})
		s := mockService(t, func(r *http.Request) (*http.Response, error) {
			close(started)
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		s.EnableAbuseIPDB("fixture-key")
		target, _ := ParseTarget("1.1.1.0/24")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); s.metric(ctx, target, Query{}, "abuse") }()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("request not started")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("request did not cancel")
		}
		_, _, found, _ := s.cache.CacheGet(context.Background(), metricKey(target, Query{}, "abuse"))
		if found || len(s.httpSlots) != 0 {
			t.Fatal("cancelled request persisted data or kept a slot")
		}
	})
	t.Run("oversized", func(t *testing.T) {
		s := mockService(t, func(*http.Request) (*http.Response, error) {
			return response(200, "{"+strings.Repeat(" ", 1<<20)+"}"), nil
		})
		s.EnableAbuseIPDB("fixture-key")
		r, _ := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"abuse"}})
		if r.Metrics[0].Status != "unavailable" || r.Metrics[0].Abuse != nil {
			t.Fatal("oversized payload accepted")
		}
	})
	t.Run("hidden", func(t *testing.T) {
		old := reviewStore(t)
		provider := old.View().Providers[0]
		provider.Policy.PrefixVisibility = "hidden"
		store, err := catalog.NewStore("", []catalog.Provider{provider})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Apply(provider.ID, old.View().Offers, nil, time.Now()); err != nil {
			t.Fatal(err)
		}
		var calls atomic.Int32
		s := mockService(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return response(200, `{}`), nil })
		s.EnableAbuseIPDB("fixture-key")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		a := NewAutomatic(s)
		go func() { defer close(done); a.Run(ctx, store) }()
		time.Sleep(10 * time.Millisecond)
		cancel()
		<-done
		if calls.Load() != 0 || len(publishedPrefixes(store)) != 0 {
			t.Fatal("hidden prefix collected")
		}
	})
}

func TestAbuseAddressBoundAndNarrowScope(t *testing.T) {
	now := time.Now().UTC()
	target, _ := ParseTarget("1.1.1.0/24")
	rows := make([]map[string]any, 257)
	for i := range rows {
		rows[i] = abuseRow(now)
	}
	d, err := normalizeAbuse([]byte(abuseFixture(now, false, rows...)), target, now, now)
	if err != nil || !d.Truncated || len(d.Addresses) > 256 || d.Status != "partial" {
		t.Fatal(d, err)
	}
	target, _ = ParseTarget("1.1.1.2/32")
	raw, _ := json.Marshal(map[string]any{"data": map[string]any{"networkAddress": "1.1.1.2", "netmask": "255.255.255.255", "minAddress": "1.1.1.2", "maxAddress": "1.1.1.2", "numPossibleHosts": 1, "reportedAddress": []map[string]any{abuseRow(now)}}})
	d, err = normalizeAbuse(raw, target, now, now)
	if err != nil || d.ScopeRelation != "exact" || d.ReportCount != 3 || d.Status != "reports_observed" {
		t.Fatal(d, err)
	}
}

func TestAbuseRegressionOutOfWindowSourceDateIsPreserved(t *testing.T) {
	now := time.Now().UTC()
	target, _ := ParseTarget("1.1.1.0/24")
	row := abuseRow(now)
	date := now.Add(-40 * 24 * time.Hour)
	row["mostRecentReport"] = date.Format(time.RFC3339Nano)
	d, err := normalizeAbuse([]byte(abuseFixture(now, false, row)), target, now, now)
	if err != nil || d.Status != "partial" || d.Addresses[0].LatestReportAt == nil || !d.Addresses[0].LatestReportAt.Equal(date) {
		t.Fatal("source report time discarded instead of retained as partial")
	}
}

package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/subregator/subregator-backend/internal/catalog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDropDuplicateRecordsRejected(t *testing.T) {
	now := time.Now().UTC()
	row := `{"cidr":"1.1.1.0/24","sblid":"SBL123"}`
	raw := fmt.Sprintf("%s\n%s\n{\"type\":\"metadata\",\"timestamp\":%d,\"copyright\":\"Spamhaus\",\"records\":2}\n", row, row, now.Unix())
	if _, err := parseDrop([]byte(raw), true, now); err == nil {
		t.Fatal("duplicate records accepted as a complete DROP dataset")
	}
}

func TestZENResponseScopeAndCodes(t *testing.T) {
	for _, resource := range []string{"1.1.1.0/24", "1.1.1.1/32", "1.1.1.1", "2001:4860::/32", "2001:4860::1/128"} {
		target, _ := ParseTarget(resource)
		d, err := normalizeZEN([]byte(`{"status":200,"resp":[1002,1003,1009,1004,1010,1011,1002]}`), target)
		if err != nil || len(d.Findings) != 3 || len(d.Findings[0].Codes) != 3 || len(d.Findings[2].Codes) != 2 {
			t.Fatal(d, err)
		}
		for _, finding := range d.Findings {
			if finding.Status != "listed" {
				t.Fatal(finding)
			}
		}
		if d.Findings[2].Reason != "Outbound mail policy; not an abuse conviction" {
			t.Fatal(d)
		}
		partial := resource == "1.1.1.0/24" || resource == "2001:4860::/32"
		if (d.Completeness == "partial") != partial || (d.ScopeRelation == "contained") != partial {
			t.Fatal(d)
		}
		for _, raw := range []string{`{}`, `{"status":404}`, `{"status":200,"resp":[]}`, `{"status":200,"resp":[1020]}`, `{"status":200,"resp":[1002,9999]}`, `{"status":429,"resp":[1002]}`, `{"status":200,"resp":[2002]}`} {
			if _, err := normalizeZEN([]byte(raw), target); err == nil {
				t.Fatal("accepted invalid/unknown source codes", raw)
			}
		}
	}
}

func TestZENMalformed404CannotBecomeNegative(t *testing.T) {
	for _, raw := range []string{`<html>proxy failure</html>`, `{}`, `{"status":404,"resp":[1002]}`, `{"status":403}`} {
		s := mockService(t, func(*http.Request) (*http.Response, error) { return response(404, raw), nil })
		s.EnableSpamhaus("fixture-private-key")
		r, err := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"spamhaus_zen"}})
		if err != nil || r.Metrics[0].Status != "unavailable" || r.Metrics[0].Blocklists != nil {
			t.Fatal("malformed 404 became a negative finding", r, err)
		}
	}
}

func TestZENTransportGateLimitsAndCache(t *testing.T) {
	for _, tc := range []struct {
		code         int
		body, status string
	}{{200, `{"status":200,"resp":[1004,1010]}`, "ok"}, {404, `{"status":404}`, "ok"}, {401, `{"status":401,"private":"secret"}`, "access_denied"}, {403, `{}`, "access_denied"}, {429, `{}`, "rate_limited"}, {503, `{}`, "unavailable"}, {200, `{"status":200,"resp":[1002,9999]}`, "unavailable"}} {
		t.Run(fmt.Sprint(tc.code, tc.status), func(t *testing.T) {
			calls := 0
			s := mockService(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != zenEndpoint+"1.1.1.0" || r.Header.Get("Authorization") != "Bearer fixture-private-key" || r.Header.Get("Key") != "" {
					t.Fatal("wrong request/header")
				}
				res := response(tc.code, tc.body)
				res.Header.Set("Retry-After", "3600")
				return res, nil
			})
			q := Query{Resource: "1.1.1.0/24", Checks: []string{"spamhaus_zen"}}
			r, _ := s.Inspect(context.Background(), q)
			if r.Metrics[0].Status != "not_configured" || calls != 0 {
				t.Fatal(r)
			}
			s.EnableSpamhaus("fixture-private-key")
			r, _ = s.Cached(context.Background(), q)
			if calls != 0 {
				t.Fatal("public read collected")
			}
			r, err := s.Inspect(context.Background(), q)
			m := r.Metrics[0]
			if err != nil || m.Status != tc.status || calls != 1 || !r.Partial {
				t.Fatal(r, err, calls)
			}
			if tc.status == "access_denied" || tc.status == "rate_limited" {
				c := summarizeBlocklists(r, time.Now())
				if c.Status != tc.status {
					t.Fatal("offer lost source failure state", c)
				}
			}

			b, _ := json.Marshal(r)
			if strings.Contains(string(b), "fixture-private-key") || strings.Contains(string(b), "secret") {
				t.Fatal("secret leak")
			}
			if tc.status == "ok" && (m.Blocklists == nil || m.Observation.Completeness != "partial" || m.Observation.Scope.Resource != "1.1.1.0" || m.SourceUpdatedAt != nil) {
				t.Fatal(m)
			}
			if tc.code == 429 {
				s2 := New(s.cache, true, "", 120)
				s2.EnableSpamhaus("fixture-private-key")
				s2.client = s.client
				q.Resource = "1.1.2.0/24"
				rr, _ := s2.Inspect(context.Background(), q)
				if rr.Metrics[0].Status != "rate_limited" || calls != 1 {
					t.Fatal("source cooldown lost", rr, calls)
				}
			}
		})
	}
}

func TestZENUnsupportedStaleAndOfferIsolation(t *testing.T) {
	s := mockService(t, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected source request"); return nil, nil })
	s.EnableSpamhaus("fixture")
	for _, q := range []Query{{Resource: "AS13335", Checks: []string{"spamhaus_zen"}}, {Resource: "1.1.1.0/24", Checks: []string{"spamhaus_zen"}, ASN: 13335}, {Resource: "1.1.1.0/24", Checks: []string{"spamhaus_zen"}, Version: "2"}} {
		r, err := s.Inspect(context.Background(), q)
		if err != nil || r.Metrics[0].Status != "not_applicable" {
			t.Fatal(r, err)
		}
	}
	target, _ := ParseTarget("1.1.1.0/24")
	ip, _ := blocklistAddress(target)
	detail := emptyZEN(target, ip)
	raw, _ := json.Marshal(detail)
	now := time.Now().UTC()
	past := now.Add(-time.Minute)
	m := decorateBlocklists(Metric{Name: "spamhaus_zen", Status: "ok", Data: raw, ObservedAt: &past, ExpiresAt: &past}, target, now)
	if m.Status != "stale" || m.Blocklists.Status != "partial" || !metricPartial(m) {
		t.Fatal(m)
	}
	a := NewAutomatic(s)
	a.reports[target.Value] = OfferChecks{ZEN: &Check{Status: "not_listed", Freshness: "fresh", ObservedAt: &past, ExpiresAt: &past, Blocklists: detail}}
	for i := 0; i < 2; i++ {
		r := a.Get(target.Value)
		if r.ZEN.Status != "partial" || r.ZEN.Observation.Completeness != "partial" {
			t.Fatal(r)
		}
	}
	if detail.Status != "not_listed" || a.reports[target.Value].ZEN.Status != "not_listed" {
		t.Fatal("cached publication mutated")
	}
	a.service.spamhausEnabled = false
	if a.Get(target.Value).ZEN.Blocklists != nil || a.Get(target.Value).ZEN.Status != "not_configured" {
		t.Fatal("disabled source leaked retained finding")
	}
}

func TestZENAutomaticWorkerRestartAndNoExtraCalls(t *testing.T) {
	var zenCalls atomic.Int32
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "apibl.spamhaus.net" {
			zenCalls.Add(1)
			if r.URL.Path != "/lookup/v1/ZEN/1.1.1.0" {
				t.Fatal("per-IP details were fetched")
			}
			return response(200, `{"status":200,"resp":[1004,1010]}`), nil
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatal("abuse key forwarded to another source")
		}
		if r.URL.Host == "www.spamhaus.org" {
			return response(200, dropFixture(time.Now())), nil
		}
		return response(503, `{}`), nil
	})
	s.EnableSpamhaus("fixture-key")
	a := NewAutomatic(s)
	store := reviewStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.Run(ctx, store) }()
	deadline := time.Now().Add(3 * time.Second)
	for a.Get("1.1.1.0/24").ZEN.Status != "listed" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if a.Get("1.1.1.0/24").ZEN.Status != "listed" || zenCalls.Load() != 1 {
		t.Fatal("worker failed or performed extra requests")
	}
	s.network = false
	restored := NewAutomatic(s)
	restored.restoreSchedule(context.Background(), "1.1.1.0/24", append(append([]string{}, automaticChecks...), "spamhaus_drop"))
	got := restored.Get("1.1.1.0/24").ZEN
	if got.Blocklists == nil || got.Blocklists.Findings[1].Status != "listed" || zenCalls.Load() != 1 {
		t.Fatal("restart lost observations or fetched details")
	}
}

func TestZENCancellationSizeAndHiddenPrefixes(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		started := make(chan struct{})
		s := mockService(t, func(r *http.Request) (*http.Response, error) {
			close(started)
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		s.EnableSpamhaus("fixture-key")
		target, _ := ParseTarget("1.1.1.0/24")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); s.metric(ctx, target, Query{}, "spamhaus_zen") }()
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
		_, _, found, _ := s.cache.CacheGet(context.Background(), metricKey(target, Query{}, "spamhaus_zen"))
		if found || len(s.httpSlots) != 0 {
			t.Fatal("cancelled request persisted data or kept a slot")
		}
	})
	t.Run("oversized", func(t *testing.T) {
		s := mockService(t, func(*http.Request) (*http.Response, error) {
			return response(200, "{"+strings.Repeat(" ", 1<<20)+"}"), nil
		})
		s.EnableSpamhaus("fixture-key")
		r, _ := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"spamhaus_zen"}})
		if r.Metrics[0].Status != "unavailable" || r.Metrics[0].Blocklists != nil {
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
		s.EnableSpamhaus("fixture-key")
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

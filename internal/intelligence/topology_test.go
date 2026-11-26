package intelligence

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTopologyChecksCollectAndShareASNCache(t *testing.T) {
	calls := 0
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls++
		switch r.URL.Host {
		case "api.asrank.caida.org":
			if !strings.Contains(r.URL.Query().Get("query"), `asn(asn:"43330")`) {
				t.Error("missing ASN in query")
			}
			return response(200, `{"data":{"asn":{"asn":"43330","asnName":"FOKIN","rank":10862,"asnLinks":{"totalCount":3,"pageInfo":{"hasNextPage":false},"edges":[{"node":{"relationship":"provider","asn0":{"asn":"43330"},"asn1":{"asn":"31133","asnName":"MF-MGSM-AS","rank":29}}},{"node":{"relationship":"customer","asn0":{"asn":"43330"},"asn1":{"asn":"202078","asnName":"MIXAS","rank":40816}}},{"node":{"relationship":"peer","asn0":{"asn":"43330"},"asn1":{"asn":"25091","asnName":"IP-Max","rank":325}}}]}}}}`), nil
		case "stat.ripe.net":
			if strings.Contains(r.URL.Path, "prefix-overview") {
				return response(200, `{"status":"ok","data":{"asns":[{"asn":43330}]}}`), nil
			}
			if r.URL.Query().Get("resource") != "AS43330" {
				t.Error("wrong prefixes ASN")
			}
			return response(200, `{"status":"ok","data":{"resource":"43330","prefixes":[{"prefix":"46.8.46.0/24","timelines":[]},{"prefix":"2a00:1450::/32","timelines":[]}]}}`), nil
		}
		t.Fatal("unexpected source")
		return nil, nil
	})
	ctx := context.Background()
	for _, name := range []string{"asn_relationships", "announced_prefixes"} {
		r, err := s.Inspect(ctx, Query{Resource: "AS43330", Checks: []string{name}})
		if err != nil || r.Partial {
			t.Fatalf("%s: %+v %v", name, r, err)
		}
		asnMetric := r.Metrics[0]
		data := string(asnMetric.Data)
		if name == "asn_relationships" {
			for _, field := range []string{`"upstreams":[`, `"downstreams":[`, `"peers":[`, `"truncated":false`, `"rank":29`, `"attribution"`} {
				if !strings.Contains(data, field) {
					t.Fatalf("missing %s: %s", field, data)
				}
			}
		} else if !strings.Contains(data, "2a00:1450::/32") {
			t.Fatal("IPv6 missing")
		}
		r, err = s.Inspect(ctx, Query{Resource: "46.8.46.0/24", Checks: []string{name}})
		if err != nil || r.Partial {
			t.Fatalf("origin lookup: %+v %v", r, err)
		}
		if r.Metrics[0].ObservedAt.After(*asnMetric.ObservedAt) || r.Metrics[0].ExpiresAt.After(*asnMetric.ExpiresAt) {
			t.Fatal("aggregate extended source freshness")
		}
		cached, err := s.Cached(ctx, Query{Resource: "46.8.46.0/24", Checks: []string{name}})
		if err != nil || cached.Partial {
			t.Fatal("not publicly cached", err, cached)
		}
	}
	if calls != 3 {
		t.Fatalf("ASN data not shared: %d calls", calls)
	}
}

func TestRelationshipsRejectInvalidOrIncompleteSource(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"errors":[{"message":"failed"}],"data":{"asn":null}}`,
		`{"data":{"asn":{"asn":"13335","asnLinks":{"totalCount":0,"pageInfo":{"hasNextPage":false},"edges":[]}}}}`,
		`{"data":{"asn":{"asn":"43330"}}}`,
		`{"data":{"asn":{"asn":"43330","asnLinks":{"totalCount":1,"pageInfo":{"hasNextPage":false},"edges":[]}}}}`,
		`{"data":{"asn":{"asn":"43330","asnLinks":{"totalCount":1,"pageInfo":{"hasNextPage":false},"edges":[{"node":{"relationship":"provider","asn0":{"asn":"31133"},"asn1":{"asn":"43330"}}}]}}}}`,
	} {
		s := mockService(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		r, err := s.Inspect(context.Background(), Query{Resource: "AS43330", Checks: []string{"asn_relationships"}})
		if err != nil || !r.Partial || r.Metrics[0].Status == "ok" {
			t.Fatalf("invalid source accepted: %s %+v %v", body, r, err)
		}
	}
}

func TestTopologyTruncationAndFailures(t *testing.T) {
	for _, tc := range []struct{ body, status string }{
		{`{"data":{"asn":{"asn":"43330","asnLinks":{"totalCount":501,"pageInfo":{"hasNextPage":true},"edges":[]}}}}`, "ok"},
		{`{"data":{"asn":null}}`, "no_data"},
	} {
		s := mockService(t, func(*http.Request) (*http.Response, error) { return response(200, tc.body), nil })
		r, err := s.Inspect(context.Background(), Query{Resource: "AS43330", Checks: []string{"asn_relationships"}})
		if err != nil || r.Metrics[0].Status != tc.status {
			t.Fatal(err, r)
		}
		if tc.status == "ok" && !strings.Contains(string(r.Metrics[0].Data), `"truncated":true`) {
			t.Fatal("truncation hidden")
		}
	}
	for _, code := range []int{429, 503} {
		s := mockService(t, func(*http.Request) (*http.Response, error) { return response(code, `{}`), nil })
		r, err := s.Inspect(context.Background(), Query{Resource: "AS43330", Checks: []string{"asn_relationships"}})
		want := "unavailable"
		if code == 429 {
			want = "rate_limited"
		}
		if err != nil || r.Metrics[0].Status != want {
			t.Fatal(err, r)
		}
	}
}

func TestAutomaticCollectsTopologyForPublicCache(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.Host, "spamhaus"):
			return response(200, dropFixture(time.Now())), nil
		case strings.Contains(r.URL.Path, "prefix-overview"):
			return response(200, `{"status":"ok","data":{"asns":[{"asn":43330}]}}`), nil
		case r.URL.Host == "api.asrank.caida.org":
			return response(200, `{"data":{"asn":{"asn":"43330","asnLinks":{"totalCount":0,"pageInfo":{"hasNextPage":false},"edges":[]}}}}`), nil
		case strings.Contains(r.URL.Path, "announced-prefixes"):
			return response(200, `{"status":"ok","data":{"resource":"43330","prefixes":[]}}`), nil
		default:
			return response(404, `{}`), nil
		}
	})
	a := NewAutomatic(s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	store := reviewStore(t)
	go func() { defer close(done); a.Run(ctx, store) }()
	defer func() { cancel(); <-done }()
	deadline := time.After(3 * time.Second)
	for {
		r, err := s.Cached(ctx, Query{Resource: "1.1.1.0/24", Checks: []string{"asn_relationships", "announced_prefixes"}})
		if err != nil {
			t.Fatal(err)
		}
		if !r.Partial {
			break
		}
		select {
		case <-deadline:
			t.Fatal("automatic topology not collected")
		case <-time.After(time.Millisecond):
		}
	}
	r, err := s.Cached(ctx, Query{Resource: "AS43330", Checks: []string{"asn_relationships", "announced_prefixes"}})
	if err != nil || r.Partial {
		t.Fatal("ASN cache not populated", err, r)
	}
}

func TestRDAPFollowsOnlyTrustedBudgetedReferrals(t *testing.T) {
	for _, destination := range []string{"https://rdap.db.ripe.net/ip/163.5.251.0", "https://example.com/ip/163.5.251.0", "http://127.0.0.1/private"} {
		calls := 0
		s := mockService(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Host == "data.iana.org" {
				return response(200, `{"services":[[["163.0.0.0/8"],["https://rdap.apnic.net/"]]]}`), nil
			}
			if r.URL.Host == "rdap.apnic.net" {
				v := response(301, `{}`)
				v.Header.Set("Location", destination)
				return v, nil
			}
			return response(200, `{"handle":"163.5.251.0 - 163.5.251.255","name":"InterLIR-Marketplace"}`), nil
		})
		r, err := s.Inspect(context.Background(), Query{Resource: "163.5.251.0/24", Checks: []string{"rdap"}})
		trusted := strings.HasPrefix(destination, "https://rdap.db.ripe.net/")
		if err != nil || (r.Metrics[0].Status == "ok") != trusted || calls != map[bool]int{true: 3, false: 2}[trusted] {
			t.Fatalf("referral %s: calls=%d %v %+v", destination, calls, err, r)
		}
	}
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "data.iana.org" {
			return response(200, `{"services":[[["163.0.0.0/8"],["https://rdap.apnic.net/"]]]}`), nil
		}
		v := response(301, `{}`)
		v.Header.Set("Location", "https://rdap.db.ripe.net/ip/163.5.251.0")
		return v, nil
	})
	s.rpm = 2
	r, err := s.Inspect(context.Background(), Query{Resource: "163.5.251.0/24", Checks: []string{"rdap"}})
	if err != nil || r.Metrics[0].Status != "rate_limited" {
		t.Fatal("referral bypassed budget", err, r)
	}
}

func TestPublicTopologyExpiresWithOriginObservation(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.asrank.caida.org" {
			t.Error("origin observation should be reused")
		}
		return response(200, `{"data":{"asn":{"asn":"43330","asnLinks":{"totalCount":0,"pageInfo":{"hasNextPage":false},"edges":[]}}}}`), nil
	})
	now, expiry := time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(30*time.Second)
	target, _ := ParseTarget("46.8.46.0/24")
	m := Metric{Name: "prefix_overview", Status: "ok", ObservedAt: &now, ExpiresAt: &expiry, Data: json.RawMessage(`{"asns":[{"asn":43330}]}`)}
	b, _ := json.Marshal(m)
	s.cache.CachePut(context.Background(), metricKey(target, Query{}, "prefix_overview"), b, expiry)
	r, err := s.Inspect(context.Background(), Query{Resource: target.Value, Checks: []string{"asn_relationships"}})
	if err != nil || r.Partial || r.Metrics[0].ExpiresAt.After(expiry) {
		t.Fatal("topology outlived origin observation", err, r)
	}
}

package intelligence

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRoutingRegressionFailedMetricCannotAnnounce(t *testing.T) {
	r := reportFixture(t)
	r.Metrics[0].Status = "unavailable"
	bgp, rpki := summarize(r, time.Now())
	if bgp.Status == "announced" || rpki.Status == "valid" {
		t.Fatalf("failed collection produced findings: %s/%s", bgp.Status, rpki.Status)
	}
}

func TestRoutingRegressionPartialRPKIRetainsOrigins(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "prefix-overview") {
			return response(200, `{"status":"ok","data":{"resource":"1.1.1.0/24","announced":true,"is_less_specific":false,"num_filtered_out":0,"asns":[{"asn":1},{"asn":2}]}}`), nil
		}
		if r.URL.Query().Get("resource") == "1" {
			return response(200, `{"status":"ok","data":{"prefix":"1.1.1.0/24","resource":"1","status":"valid"}}`), nil
		}
		return response(503, `{"secret":"must not escape"}`), nil
	})
	r, _ := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"rpki"}})
	var data struct {
		Origins []struct {
			ASN uint32 `json:"asn"`
		} `json:"origins"`
	}
	json.Unmarshal(r.Metrics[0].Data, &data)
	if len(data.Origins) != 2 || strings.Contains(string(r.Metrics[0].Data), "secret") {
		t.Fatalf("lost per-origin evidence: %+v", r)
	}
}

func TestRoutingExplanations(t *testing.T) {
	for _, prefix := range []string{"1.1.1.0/24", "2001:4860::/32"} {
		for _, state := range []string{"valid", "invalid_asn", "invalid_length", "unknown", "unexpected"} {
			t.Run(prefix+state, func(t *testing.T) {
				r := reportFixture(t)
				r.Resource.Value = prefix
				for i := range r.Metrics {
					r.Metrics[i].Data = []byte(strings.ReplaceAll(string(r.Metrics[i].Data), "1.1.1.0/24", prefix))
				}
				r.Metrics[1].Data = []byte(strings.ReplaceAll(string(r.Metrics[1].Data), `"valid"`, `"`+state+`"`))
				bgp, rpki := summarize(r, time.Now())
				if bgp.BGP == nil || bgp.BGP.Relation != "exact" || rpki.RPKI == nil || len(rpki.RPKI.Origins) != 1 {
					t.Fatalf("missing explanation: %+v %+v", bgp, rpki)
				}
				want := state
				if state == "unknown" {
					want = "not_found"
				}
				if state == "unexpected" {
					want = "unavailable"
				}
				if rpki.RPKI.Origins[0].Status != want {
					t.Fatal(rpki.RPKI)
				}
				if state == "unexpected" && rpki.Status != "partial" {
					t.Fatal("unsupported validation passed")
				}
			})
		}
	}
}

func TestRoutingROAsVisibilityAndCompaction(t *testing.T) {
	r := reportFixture(t)
	r.Metrics[0].Data = json.RawMessage(`{"resource":"1.1.1.0/24","is_less_specific":false,"announced":true,"num_filtered_out":0,"query_time":"2026-01-01T00:00:00","asns":[13335]}`)
	r.Metrics[1].Data = json.RawMessage(`{"prefix":"1.1.1.0/24","origins":[{"asn":13335,"source_url":"https://stat.ripe.net/fixture","data":{"prefix":"1.1.1.0/24","resource":13335,"status":"invalid_length","validating_roas":[{"prefix":"1.1.0.0/16","origin":"13335","max_length":23},{"prefix":"2.0.0.0/8","origin":1,"max_length":24}]}}]}`)
	routing := r.Metrics[0]
	routing.Name = "routing_status"
	routing.SourceURL = "https://stat.ripe.net/routing"
	routing.Data = json.RawMessage(`{"resource":"1.1.1.0/24","query_time":"2026-01-01T00:00:00","visibility":{"v4":{"ris_peers_seeing":12,"total_ris_peers":20}},"first_seen":{"time":"2025-01-01T00:00:00","prefix":"1.1.1.0/24","origin":"13335"},"last_seen":{"time":"2026-01-01T00:00:00","prefix":"1.1.1.0/24","origin":13335}}`)
	r.Metrics = append(r.Metrics, routing)
	for _, compact := range []bool{false, true} {
		if compact {
			for i := range r.Metrics {
				r.Metrics[i] = compactEvidence(r.Metrics[i])
			}
		}
		bgp, rpki := summarize(r, time.Now())
		if bgp.BGP.QueryTime == nil || bgp.BGP.Routing == nil || bgp.BGP.Routing.FirstSeen == nil || *bgp.BGP.Routing.PeersSeeing != 12 || *bgp.BGP.Routing.TotalPeers != 20 {
			t.Fatalf("lost routing context: %+v", bgp.BGP)
		}
		o := rpki.RPKI.Origins[0]
		if o.Status != "invalid_length" || len(o.CoveringROAs) != 1 || o.CoveringROAs[0].MaxLength != 23 || o.CoveringROAs[0].ASN != 13335 || o.SourceURL == "" {
			t.Fatalf("lost ROA: %+v", o)
		}
	}
}

func TestRoutingOriginLimitAndMixed(t *testing.T) {
	for _, count := range []int{2, 4, 5} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			validations := 0
			s := mockService(t, func(r *http.Request) (*http.Response, error) {
				if strings.Contains(r.URL.Path, "prefix-overview") {
					origins := []map[string]int{}
					for i := 1; i <= count; i++ {
						origins = append(origins, map[string]int{"asn": i})
					}
					b, _ := json.Marshal(map[string]any{"status": "ok", "data": map[string]any{"resource": "1.1.1.0/24", "announced": true, "is_less_specific": false, "num_filtered_out": 0, "asns": origins}})
					return response(200, string(b)), nil
				}
				validations++
				state := "valid"
				if r.URL.Query().Get("resource") == "2" {
					state = "invalid_asn"
				}
				b, _ := json.Marshal(map[string]any{"status": "ok", "data": map[string]any{"prefix": "1.1.1.0/24", "resource": r.URL.Query().Get("resource"), "status": state}})
				return response(200, string(b)), nil
			})
			r, _ := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"prefix_overview", "rpki"}})
			_, c := summarize(r, time.Now())
			if validations != min(count, 4) || len(c.RPKI.Origins) != min(count, 4) {
				t.Fatal("request bound or evidence lost", validations, c.RPKI)
			}
			if count <= 4 && c.Status != "mixed" || count > 4 && (c.Status != "partial" || !c.RPKI.Truncated || !r.Partial) {
				t.Fatalf("dishonest aggregate: %+v", c)
			}
		})
	}
}

func TestRoutingCachedOriginChangeAndProposedASN(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "prefix-overview") {
			return response(200, `{"status":"ok","data":{"resource":"1.1.1.0/24","announced":true,"is_less_specific":false,"num_filtered_out":0,"asns":[13335]}}`), nil
		}
		return response(200, `{"status":"ok","data":{"prefix":"1.1.1.0/24","resource":"13335","status":"valid"}}`), nil
	})
	q := Query{Resource: "1.1.1.0/24", Checks: []string{"rpki"}}
	r, _ := s.Inspect(context.Background(), q)
	if r.Metrics[0].RPKI.Status != "valid" {
		t.Fatal(r)
	}
	target, _ := ParseTarget(q.Resource)
	overview := reportFixture(t).Metrics[0]
	overview.Data = json.RawMessage(`{"resource":"1.1.1.0/24","announced":true,"is_less_specific":false,"num_filtered_out":0,"asns":[13336]}`)
	b, _ := json.Marshal(overview)
	s.cache.CachePut(context.Background(), metricKey(target, Query{}, "prefix_overview"), b, *overview.ExpiresAt)
	s.network = false
	r, _ = s.Cached(context.Background(), q)
	if !r.Partial || r.Metrics[0].RPKI.Status != "partial" {
		t.Fatal("obsolete origin passed", r)
	}
	s.network = true
	q.ASN = 13335
	r, _ = s.Inspect(context.Background(), q)
	if r.Metrics[0].RPKI.Basis != "proposed_asn" || r.Metrics[0].Observation.Scope.Relation != "prefix_asn" || r.Metrics[0].Observation.Scope.ASN != 13335 {
		t.Fatal("proposed ASN confused with origin", r)
	}
}

func TestRoutingAbsenceAndCoveringScope(t *testing.T) {
	for _, tc := range []struct{ data, status, relation, actual string }{
		{`{"resource":"1.1.1.0/24","is_less_specific":false,"announced":false,"num_filtered_out":0,"asns":[]}`, "not_announced", "exact", "1.1.1.0/24"},
		{`{"resource":"1.1.1.0/24","is_less_specific":false,"announced":false,"num_filtered_out":1,"asns":[]}`, "unavailable", "exact", "1.1.1.0/24"},
		{`{"resource":"1.1.0.0/16","is_less_specific":true,"announced":true,"num_filtered_out":0,"asns":[13335]}`, "covering_route", "covering", "1.1.0.0/16"},
		{`{"resource":"2.0.0.0/8","is_less_specific":true,"announced":true,"num_filtered_out":0,"asns":[13335]}`, "unavailable", "unknown", "2.0.0.0/8"},
	} {
		r := reportFixture(t)
		r.Metrics[0].Data = []byte(tc.data)
		b, _ := summarize(r, time.Now())
		if b.Status != tc.status || b.BGP.Relation != tc.relation || b.BGP.Prefix != tc.actual {
			t.Fatalf("wrong scope: %+v", b)
		}
	}
}

func TestRoutingFailureAndStaleCoverage(t *testing.T) {
	for _, status := range []int{401, 403, 404, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			s := mockService(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if strings.Contains(r.URL.Path, "prefix-overview") {
					return response(200, `{"status":"ok","data":{"resource":"1.1.1.0/24","announced":true,"is_less_specific":false,"num_filtered_out":0,"asns":[13335]}}`), nil
				}
				return response(status, `{"token":"private upstream payload"}`), nil
			})
			r, _ := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"rpki"}})
			if !r.Partial || r.Metrics[0].RPKI != nil || calls != 2 || strings.Contains(r.Metrics[0].Error, "private") {
				t.Fatal(r, calls)
			}
		})
	}
	r := reportFixture(t)
	past := time.Now().Add(-time.Hour)
	r.Metrics[0].ExpiresAt = &past
	b, v := summarize(r, time.Now())
	if b.Freshness != "stale" || v.Freshness != "stale" || v.ExpiresAt.After(past) {
		t.Fatal("stale dependency passed", b, v)
	}
	for _, m := range []Metric{r.Metrics[0], r.Metrics[1]} {
		m.ObservedAt = nil
		report := reportFixture(t)
		if m.Name == "prefix_overview" {
			report.Metrics[0] = m
		} else {
			report.Metrics[1] = m
		}
		b, v := summarize(report, time.Now())
		if m.Name == "prefix_overview" && b.Status == "announced" || v.Status == "valid" {
			t.Fatal("undated data passed", b, v)
		}
	}
}

func TestOriginDerivedChecksRemainBounded(t *testing.T) {
	for _, check := range []string{"asn_rank", "asn_neighbours", "rpki"} {
		t.Run(check, func(t *testing.T) {
			calls := 0
			s := mockService(t, func(r *http.Request) (*http.Response, error) {
				if strings.Contains(r.URL.Path, "prefix-overview") {
					return response(200, `{"status":"ok","data":{"resource":"1.1.1.0/24","announced":true,"is_less_specific":false,"num_filtered_out":0,"asns":[1,1,2,3,4,5]}}`), nil
				}
				calls++
				if strings.Contains(r.URL.Host, "asrank") {
					return response(200, `{"data":{"asn":{"asn":"1"}}}`), nil
				}
				return response(200, `{"status":"ok","data":{"prefix":"1.1.1.0/24","resource":"1","status":"valid"}}`), nil
			})
			s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{check}})
			if calls != 4 {
				t.Fatal("origin bound changed", calls)
			}
		})
	}
}

func TestRoutingRegressionMissingROAASNIsNotASZero(t *testing.T) {
	m := reportFixture(t).Metrics[1]
	m.Data = json.RawMessage(`{"prefix":"1.1.1.0/24","origins":[{"asn":13335,"data":{"prefix":"1.1.1.0/24","resource":13335,"status":"invalid_asn","validating_roas":[{"prefix":"1.1.0.0/16","max_length":24},{"prefix":"1.1.0.0/16","origin":"AS0","max_length":24}]}}]}`)
	d := rpkiExplanation(m)
	if len(d.Origins[0].CoveringROAs) != 1 || d.Origins[0].CoveringROAs[0].ASN != 0 {
		t.Fatalf("missing ASN became explicit AS0: %+v", d.Origins[0].CoveringROAs)
	}
}

func TestRoutingRegressionCoveringOriginCannotKeepValidExplanation(t *testing.T) {
	r := reportFixture(t)
	r.Metrics[0].Data = json.RawMessage(`{"resource":"1.1.0.0/16","is_less_specific":true,"announced":true,"num_filtered_out":0,"asns":[13335]}`)
	_, v := summarize(r, time.Now())
	if v.RPKI != nil && v.RPKI.Status == "valid" {
		t.Fatal("covering origin kept complete exact validation", v.RPKI)
	}
}

func TestRoutingRegressionLegacyProposedASNLabel(t *testing.T) {
	s := New(&memoryCache{}, false, "", 120)
	m := reportFixture(t).Metrics[1]
	b, _ := json.Marshal(m)
	target, _ := ParseTarget("1.1.1.0/24")
	q := Query{Resource: target.Value, Checks: []string{"rpki"}, ASN: 13335}
	s.cache.CachePut(context.Background(), metricKey(target, q, "rpki"), b, *m.ExpiresAt)
	r, _ := s.Cached(context.Background(), q)
	if r.Metrics[0].RPKI.Basis != "proposed_asn" || r.Metrics[0].Observation.Scope.Relation != "prefix_asn" {
		t.Fatal("legacy pair presented as observed origin", r.Metrics[0].RPKI)
	}
}

func TestRoutingIPv6VisibilityAndExplanationBounds(t *testing.T) {
	r := reportFixture(t)
	m := r.Metrics[0]
	m.Name = "routing_status"
	m.Data = json.RawMessage(`{"resource":"2001:4860::/32","query_time":"2026-01-01T00:00:00","visibility":{"v4":{"ris_peers_seeing":9,"total_ris_peers":10},"v6":{"ris_peers_seeing":2,"total_ris_peers":8}},"first_seen":{"time":"2020-01-01T00:00:00","prefix":"2001:4860::/32","origin":"15169"}}`)
	v := routingVisibility(m, Target{Value: "2001:4860::/32", Kind: "prefix"}, time.Now())
	if v == nil || *v.PeersSeeing != 2 || *v.TotalPeers != 8 || v.FirstSeen.Origin != 15169 {
		t.Fatal(v)
	}
	m.Data = json.RawMessage(`{"resource":"2001:4860::/32","visibility":{"v6":{"ris_peers_seeing":9,"total_ris_peers":8}},"first_seen":{"time":"2020-01-01T00:00:00","prefix":"2001:4860::/32"}}`)
	v = routingVisibility(m, Target{Value: "2001:4860::/32", Kind: "prefix"}, time.Now())
	if v.PeersSeeing != nil || v.FirstSeen != nil {
		t.Fatal("invented visibility or origin", v)
	}
	roas := []any{}
	for i := 0; i < 40; i++ {
		roas = append(roas, map[string]any{"prefix": "1.1.0.0/16", "origin": 13335, "max_length": 24})
	}
	raw, _ := json.Marshal(map[string]any{"prefix": "1.1.1.0/24", "origins": []any{map[string]any{"asn": 13335, "data": map[string]any{"prefix": "1.1.1.0/24", "resource": 13335, "status": "valid", "validating_roas": roas}}}})
	m = r.Metrics[1]
	m.Data = raw
	for _, compact := range []bool{false, true} {
		if compact {
			m = compactEvidence(m)
		}
		v := rpkiExplanation(m)
		if len(v.Origins[0].CoveringROAs) != 32 || !v.Origins[0].ROAsTruncated {
			t.Fatal("ROA limit hidden", v)
		}
	}
}

func TestRoutingUnknownAndDuplicateCompaction(t *testing.T) {
	r := reportFixture(t)
	r.Metrics[0].Data = json.RawMessage(`{"resource":"1.1.1.0/24","announced":true,"is_less_specific":false,"num_filtered_out":0,"asns":[13335,13335,13335,13335,13335]}`)
	r.Metrics[0] = compactEvidence(r.Metrics[0])
	_, v := summarize(r, time.Now())
	if v.Status != "valid" {
		t.Fatal("duplicates became omissions", v)
	}
	m := r.Metrics[1]
	m.Data = json.RawMessage(`{"prefix":"1.1.1.0/24"}`)
	m = decorateRouting(m, r.Resource, 0)
	if !metricPartial(m) {
		t.Fatal("empty validation passed")
	}
	m = r.Metrics[0]
	m.Data = json.RawMessage(`{}`)
	m = decorateRouting(m, r.Resource, 0)
	if !metricPartial(m) {
		t.Fatal("missing overview passed")
	}
	future := time.Now().Add(time.Hour)
	m = r.Metrics[1]
	m.ObservedAt = &future
	if rpkiExplanation(m) != nil {
		t.Fatal("future observation passed")
	}
}

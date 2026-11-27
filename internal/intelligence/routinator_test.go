package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func routinatorFixture(prefix string, asn uint32, state, reason, group string, generated time.Time) string {
	vrps := map[string]any{"matched": []any{}, "unmatched_as": []any{}, "unmatched_length": []any{}}
	if group != "" {
		vrp := map[string]string{"asn": fmt.Sprintf("AS%d", asn), "prefix": prefix, "max_length": strings.Split(prefix, "/")[1]}
		if group == "unmatched_as" {
			vrp["asn"] = fmt.Sprintf("AS%d", asn+1)
		}
		if group == "unmatched_length" {
			p, _ := netip.ParsePrefix(prefix)
			p = netip.PrefixFrom(p.Addr(), p.Bits()-1).Masked()
			vrp["prefix"] = p.String()
			vrp["max_length"] = strings.Split(p.String(), "/")[1]
		}
		vrps[group] = []any{vrp}
	}
	b, _ := json.Marshal(map[string]any{"generatedTime": generated.UTC(), "validated_route": map[string]any{"route": map[string]any{"prefix": prefix, "origin_asn": fmt.Sprintf("AS%d", asn)}, "validity": map[string]any{"state": state, "reason": reason, "VRPs": vrps}}})
	return string(b)
}
func routinatorStatusFixture(now time.Time) string {
	tals := map[string]any{}
	for _, name := range []string{"afrinic", "apnic", "arin", "lacnic", "ripe"} {
		tals[name] = map[string]int{"vrpsTotal": 1}
	}
	b, _ := json.Marshal(map[string]any{"lastUpdateDone": now.UTC(), "tals": tals})
	return string(b)
}
func TestRoutinatorNormalization(t *testing.T) {
	for _, prefix := range []string{"1.1.1.0/24", "2606:4700::/32"} {
		for _, tc := range []struct{ state, reason, group, want string }{{"valid", "", "matched", "valid"}, {"invalid", "as", "unmatched_as", "invalid_asn"}, {"invalid", "length", "unmatched_length", "invalid_length"}, {"not-found", "", "", "not_found"}} {
			raw := routinatorFixture(prefix, 13335, tc.state, tc.reason, tc.group, time.Now())
			b, _, err := normalizeRoutinator([]byte(raw), prefix, 13335)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(map[string]any{"prefix": prefix, "basis": "proposed_asn", "origins": []any{map[string]any{"asn": 13335, "data": json.RawMessage(b)}}})
			m := Metric{Status: "ok", Data: data, ObservedAt: observedNow()}
			result := rpkiExplanation(m)
			if result == nil || len(result.Origins) != 1 || result.Origins[0].Status != tc.want {
				t.Fatalf("bad normalized validation: %+v", result)
			}
			if tc.group != "" && len(result.Origins[0].CoveringROAs) != 1 {
				t.Fatal("VRP lost")
			}
		}
	}
	for _, raw := range []string{routinatorFixture("1.1.1.0/24", 13335, "valid", "", "matched", time.Now().Add(-2*time.Hour)), routinatorFixture("1.1.1.0/24", 13335, "valid", "", "", time.Now()), routinatorFixture("1.1.1.0/24", 1, "valid", "", "matched", time.Now())} {
		if _, _, err := normalizeRoutinator([]byte(raw), "1.1.1.0/24", 13335); err == nil {
			t.Fatal("invalid/stale validity accepted")
		}
	}
}
func TestRoutinatorPrivateBudgetProvenanceAndFailure(t *testing.T) {
	var calls atomic.Int32
	var unavailable atomic.Bool
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if unavailable.Load() {
			return nil, errors.New("offline")
		}
		if r.URL.Host != "routinator:8323" {
			t.Fatal("unexpected external request", r.URL)
		}
		if r.URL.Path == "/api/v1/status" {
			return response(200, routinatorStatusFixture(time.Now())), nil
		}
		return response(200, routinatorFixture("1.1.1.0/24", 13335, "valid", "", "matched", time.Now())), nil
	})
	if err := s.EnableRoutinator(DefaultRoutinatorURL); err != nil {
		t.Fatal(err)
	}
	s.rpm = 1
	s.used = 1
	s.window = time.Now()
	q := Query{Resource: "1.1.1.0/24", ASN: 13335, Checks: []string{"rpki"}}
	r, err := s.Inspect(context.Background(), q)
	m := r.Metrics[0]
	if err != nil || m.Status != "ok" || m.Source != "Routinator" || m.RPKI == nil || m.RPKI.Basis != "proposed_asn" || s.used != 1 || calls.Load() != 2 || strings.Contains(m.SourceURL, "ripe.net") || m.SourceUpdatedAt == nil {
		t.Fatalf("invalid local result/budget %+v %v calls%d", m, err, calls.Load())
	}
	before := calls.Load()
	cached, _ := s.Cached(context.Background(), q)
	if cached.Metrics[0].Source != "Routinator" || cached.Metrics[0].Observation.Freshness != "fresh" || calls.Load() != before {
		t.Fatal("cached read changed source or made requests")
	}
	unavailable.Store(true)
	if _, err := s.routinatorStatus(context.Background()); err == nil {
		t.Fatal("offline validator accepted")
	}
	cached, _ = s.Cached(context.Background(), q)
	if cached.Metrics[0].Observation.Freshness == "fresh" {
		t.Fatal("known failed validator retained fresh positive")
	}
	old := New(s.cache, true, "", 120)
	cached, _ = old.Cached(context.Background(), q)
	if cached.Metrics[0].Status != "pending" || cached.Metrics[0].Source != "RIPEstat" {
		t.Fatal("local cache leaked into legacy mode")
	}
	restarted := New(s.cache, true, "", 120)
	restarted.EnableRoutinator(DefaultRoutinatorURL)
	cached, _ = restarted.Cached(context.Background(), q)
	if cached.Metrics[0].Observation.Freshness == "fresh" {
		t.Fatal("restart trusted unconfirmed validator")
	}
}
func TestRoutinatorFreshnessBoundsAndCancellation(t *testing.T) {
	for _, stamp := range []time.Time{time.Time{}, time.Now().Add(-2 * time.Hour), time.Now().Add(2 * time.Hour)} {
		s := mockService(t, func(*http.Request) (*http.Response, error) { return response(200, routinatorStatusFixture(stamp)), nil })
		s.EnableRoutinator(DefaultRoutinatorURL)
		if _, err := s.routinatorStatus(context.Background()); err == nil || s.routinatorUsable() {
			t.Fatal("stale/uninitialized validator accepted")
		}
	}
	s := mockService(t, func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	s.EnableRoutinator(DefaultRoutinatorURL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.routinatorRead(ctx, "/api/v1/status"); err == nil {
		t.Fatal("cancellation lost")
	}
	if len(s.routinatorSlots) != 0 {
		t.Fatal("private concurrency leaked")
	}
	s.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		return response(200, `{"data":"`+strings.Repeat("x", 1<<20)+`"}`), nil
	})
	if _, err := s.routinatorRead(context.Background(), "/api/v1/status"); err == nil {
		t.Fatal("oversized response accepted")
	}
}
func TestRoutinatorEndpointValidation(t *testing.T) {
	for _, endpoint := range []string{DefaultRoutinatorURL, "http://127.0.0.1:8323", "http://10.1.2.3:8323", "http://[::1]:8323"} {
		if New(nil, false, "", 120).EnableRoutinator(endpoint) != nil {
			t.Fatal(endpoint)
		}
	}
	for _, endpoint := range []string{"http://1.1.1.1", "https://routinator:8323", "http://public.example.com", "http://routinator:0", "http://routinator:65536", "http://routinator?", "http://routinator/path", "http://user:pass@routinator"} {
		if New(nil, false, "", 120).EnableRoutinator(endpoint) == nil {
			t.Fatal("invalid endpoint accepted", endpoint)
		}
	}
}

func TestRoutinatorObservedOriginsRetainsBGPDependency(t *testing.T) {
	calls := 0
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host == "stat.ripe.net" {
			return response(200, `{"status":"ok","data":{"resource":"1.1.1.0/24","announced":true,"is_less_specific":false,"num_filtered_out":0,"asns":[{"asn":13335},{"asn":15169}]}}`), nil
		}
		if r.URL.Path == "/api/v1/status" {
			return response(200, routinatorStatusFixture(time.Now())), nil
		}
		asn := uint32(13335)
		if r.URL.Query().Get("asn") == "15169" {
			asn = 15169
		}
		return response(200, routinatorFixture("1.1.1.0/24", asn, "valid", "", "matched", time.Now())), nil
	})
	s.EnableRoutinator(DefaultRoutinatorURL)
	r, err := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"rpki"}})
	if err != nil || r.Metrics[0].RPKI == nil || len(r.Metrics[0].RPKI.Origins) != 2 || r.Metrics[0].RPKI.Basis != "observed_origins" || s.used != 1 || calls != 4 {
		t.Fatalf("origin dependency lost %+v %v used%d calls%d", r, err, s.used, calls)
	}
	a := NewAutomatic(s)
	target, _ := ParseTarget("1.1.1.0/24")
	overview := s.metric(context.Background(), target, Query{}, "prefix_overview")
	a.publish(context.Background(), target.Value, Report{Resource: target, Metrics: []Metric{overview, r.Metrics[0]}}, Check{})
	if a.Get(target.Value).RPKI.Source != "Routinator" {
		t.Fatal("offer provenance lost")
	}
	s.mu.Lock()
	s.routinatorHealthy = false
	s.mu.Unlock()
	if a.Get(target.Value).RPKI.Freshness == "fresh" {
		t.Fatal("offer accepted known failed validator")
	}
	legacy := NewAutomatic(New(s.cache, false, "", 120))
	legacy.restoreSchedule(context.Background(), target.Value, automaticChecks)
	if legacy.Get(target.Value).RPKI.Source == "Routinator" {
		t.Fatal("legacy restore retained local source")
	}
}

func TestRoutinatorRejectsInconsistentVRPCategories(t *testing.T) {
	for _, tc := range []struct{ name, group, field, value, state, reason string }{
		{"matched_wrong_asn", "matched", "asn", "AS15169", "valid", ""},
		{"matched_short_max_length", "matched", "max_length", "23", "valid", ""},
		{"unmatched_as_same_asn", "unmatched_as", "asn", "AS13335", "invalid", "as"},
		{"unmatched_length_permitted", "unmatched_length", "max_length", "24", "invalid", "length"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]any
			json.Unmarshal([]byte(routinatorFixture("1.1.1.0/24", 13335, tc.state, tc.reason, tc.group, time.Now())), &raw)
			vrps := raw["validated_route"].(map[string]any)["validity"].(map[string]any)["VRPs"].(map[string]any)
			vrp := vrps[tc.group].([]any)[0].(map[string]any)
			vrp[tc.field] = tc.value
			if tc.field == "max_length" && tc.value == "23" {
				vrp["prefix"] = "1.1.0.0/23"
			}
			b, _ := json.Marshal(raw)
			if _, _, err := normalizeRoutinator(b, "1.1.1.0/24", 13335); err == nil {
				t.Fatal("inconsistent VRP category accepted")
			}
		})
	}
}

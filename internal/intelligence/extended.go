package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

func (s *Service) geolocation(ctx context.Context, target Target) (Metric, error) {
	m, err := s.ripe(ctx, "maxmind-geo-lite", url.Values{"resource": {target.Value}})
	if err != nil {
		return Metric{}, err
	}
	var d struct {
		Located []struct {
			Resource  string  `json:"resource"`
			Unknown   float64 `json:"unknown_percentage"`
			Locations []struct {
				Country   string  `json:"country"`
				Latitude  float64 `json:"latitude"`
				Longitude float64 `json:"longitude"`
			} `json:"locations"`
		} `json:"located_resources"`
		Parameters struct {
			Resource string `json:"resource"`
		} `json:"parameters"`
	}
	if json.Unmarshal(m.Data, &d) != nil || d.Parameters.Resource != target.Value || d.Located == nil {
		return Metric{}, errors.New("invalid geolocation response")
	}
	complete := "complete"
	if len(d.Located) == 0 {
		complete = "partial"
	}
	for _, r := range d.Located {
		actual, e := ParseTarget(r.Resource)
		if e != nil || actual.Value != target.Value || r.Unknown < 0 || r.Unknown > 100 {
			return Metric{}, errors.New("geolocation scope mismatch")
		}
		if r.Unknown > 0 || len(r.Locations) == 0 {
			complete = "partial"
		}
		for _, l := range r.Locations {
			if l.Latitude < -90 || l.Latitude > 90 || l.Longitude < -180 || l.Longitude > 180 {
				return Metric{}, errors.New("invalid geolocation coordinates")
			}
		}
	}
	m.Data, _ = json.Marshal(map[string]any{"requested": target.Value, "completeness": complete, "basis": "database_estimate", "physical_location_verified": false, "attribution": "GeoLite2 data created by MaxMind, https://www.maxmind.com", "data": m.Data})
	return m, nil
}

type dnsFinding struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Operator       string   `json:"operator"`
	URL            string   `json:"url"`
	Status         string   `json:"status"`
	QueryTime      string   `json:"query_time,omitempty"`
	Codes          []string `json:"codes,omitempty"`
	Interpretation string   `json:"interpretation,omitempty"`
}

type dnsObservation struct {
	Address      string       `json:"address"`
	Completeness string       `json:"completeness"`
	Pending      bool         `json:"pending_results"`
	Findings     []dnsFinding `json:"findings"`
	Semantics    string       `json:"semantics"`
}

func (s *Service) dnsBlocklists(ctx context.Context, target Target) (Metric, error) {
	if target.Kind == "prefix" {
		return s.prefixBlocklists(ctx, target)
	}
	m, err := s.ripe(ctx, "dns-blocklists", url.Values{"resource": {target.Value}})
	if err != nil {
		return Metric{}, err
	}
	var d struct {
		Lists   map[string]struct{ Name, Operator, URL string } `json:"blocklists"`
		Results map[string]struct {
			Status    string `json:"status"`
			QueryTime string `json:"query_time"`
		} `json:"data"`
		Pending    *bool `json:"pending_results"`
		Parameters struct {
			Resource string `json:"resource"`
		} `json:"parameters"`
	}
	if json.Unmarshal(m.Data, &d) != nil || d.Parameters.Resource != target.Value || d.Pending == nil || len(d.Lists) == 0 || len(d.Lists) > 100 || d.Results == nil {
		return Metric{}, errors.New("invalid DNSBL response")
	}
	var oldest *time.Time
	out := dnsObservation{Address: target.Value, Completeness: "complete", Pending: *d.Pending, Findings: []dnsFinding{}, Semantics: "only_named_lists_and_queried_addresses_not_universal_reputation; PBL is outbound mail policy"}
	keys := make([]string, 0, len(d.Lists))
	for k := range d.Lists {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, id := range keys {
		l, r := d.Lists[id], d.Results[id]
		status, detail, _ := strings.Cut(r.Status, ":")
		codes := []string{}
		switch status {
		case "", "init":
			if out.Pending {
				status = "pending"
			} else {
				status = "unknown"
			}
		case "listed", "notlisted", "failed", "unsupported", "toomanyrequesttoday", "pending":
		default:
			status = "unknown"
		}
		if status == "listed" {
			for _, v := range strings.FieldsFunc(detail, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
				if ip, e := netip.ParseAddr(v); e == nil && ip.IsLoopback() {
					codes = append(codes, ip.String())
					if strings.HasPrefix(ip.String(), "127.255.255.") {
						status = "failed"
					}
				}
			}
		}
		interpretation := ""
		if id == "spamhaus_pbl" {
			interpretation = "Outbound mail policy, not an abuse conviction"
		}
		if id == "spfbl_dnsbl" {
			for _, code := range codes {
				if code == "127.0.0.4" {
					interpretation = "No identifiable outgoing mail service or non-mail/NAT/residential policy flag; not evidence of spam or compromise"
				}
			}
		}
		r.Status = status

		stamp, err := time.Parse(time.RFC3339, r.QueryTime)
		if err != nil {
			stamp, err = time.Parse("2006-01-02T15:04:05", r.QueryTime)
		}
		if err != nil || stamp.After(time.Now().Add(time.Minute)) {
			out.Completeness = "partial"
		} else if oldest == nil || stamp.Before(*oldest) {
			oldest = &stamp
		}

		if r.Status == "" {
			r.Status = "pending"
		}
		if r.Status != "listed" && r.Status != "notlisted" {
			out.Completeness = "partial"
		}
		out.Findings = append(out.Findings, dnsFinding{ID: id, Name: l.Name, Operator: l.Operator, URL: l.URL, Status: r.Status, QueryTime: r.QueryTime, Codes: codes, Interpretation: interpretation})
	}
	if out.Pending {
		out.Completeness = "partial"
		m.Status = "pending"
		m.ObservedAt = nil
	}
	if len(d.Results) == 0 && !out.Pending {
		m.Status = "unavailable"
		m.Error = "Source returned no per-list results"
		m.ObservedAt = nil
	}
	if oldest != nil {
		m.SourceUpdatedAt = oldest
		if !out.Pending {
			m.ObservedAt = oldest
		}
		expiry := oldest.Add(time.Duration(definitions["dns_blocklists"].TTLSeconds) * time.Second)
		m.ExpiresAt = &expiry
		if !out.Pending && !time.Now().Before(expiry) {
			m.Status = "stale"
		}
	}
	m.Data, _ = json.Marshal(out)
	if out.Completeness != "complete" {
		expiry := time.Now().UTC().Add(15 * time.Second)
		m.ExpiresAt = &expiry
	}
	return m, nil
}

func (s *Service) prefixBlocklists(ctx context.Context, target Target) (Metric, error) {
	p := netip.MustParsePrefix(target.Value)
	results := []Metric{}
	addresses := []string{}
	for ip := p.Addr(); p.Contains(ip); ip = ip.Next() {
		report, _ := s.Cached(ctx, Query{Resource: ip.String(), Checks: []string{"dns_blocklists"}})
		results = append(results, report.Metrics[0])
		addresses = append(addresses, ip.String())
		if !ip.Next().IsValid() {
			break
		}
	}
	candidates := make([]int, 0, len(results))
	for i := range results {
		candidates = append(candidates, i)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := results[candidates[i]].ExpiresAt, results[candidates[j]].ExpiresAt
		if a == nil {
			return b != nil
		}
		return b != nil && a.Before(*b)
	})
	requests := 0
	for _, i := range candidates {
		m := results[i]
		if requests >= 8 || ctx.Err() != nil {
			break
		}
		if m.Status == "ok" && m.Observation.Freshness == "fresh" && m.Observation.Completeness == "complete" {
			continue
		}
		t := Target{Value: addresses[i], Kind: "ip"}
		m = s.metric(ctx, t, Query{Resource: t.Value}, "dns_blocklists")
		requests++
		results[i] = m
	}
	complete := "complete"
	checked, processed := 0, 0
	for _, m := range results {
		if m.SourceURL != "" || m.Error != "" {
			processed++
		}
		if m.Status != "ok" || m.Observation.Freshness != "fresh" || m.Observation.Completeness != "complete" {
			complete = "partial"
		} else {
			checked++
		}
	}
	expiry := time.Now().UTC().Add(15 * time.Second)
	b, _ := json.Marshal(map[string]any{"requested": target.Value, "completeness": complete, "total_addresses": len(results), "completed_addresses": checked, "processed_addresses": processed, "addresses": results, "semantics": "all_addresses_in_requested_prefix; only_source_named_lists; retry_after_15_seconds_for_pending_results"})
	return Metric{Data: b, ObservedAt: observedNow(), ExpiresAt: &expiry, SourceURL: "https://stat.ripe.net/docs/data-api/api-endpoints/dns-blocklists"}, nil
}

func extendedObservation(m Metric, target Target, o Observation) Observation {
	switch m.Name {
	case "geolocation", "dns_blocklists", "ping", "traceroute", "throughput":
	default:
		return o
	}
	var d struct {
		Completeness string `json:"completeness"`
		Address      string `json:"address"`
	}
	if json.Unmarshal(m.Data, &d) != nil || (d.Completeness != "complete" && d.Completeness != "partial") {
		return o
	}
	o.Completeness = d.Completeness
	o.Scope.Resource = target.Value
	o.Scope.Relation = "exact"
	if d.Address != "" && d.Address != target.Value {
		o.Scope.Resource = d.Address
		o.Scope.Kind = "ip"
		o.Scope.Relation = "contained"
	}
	return o
}

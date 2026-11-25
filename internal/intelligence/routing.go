package intelligence

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type BGPExplanation struct {
	Prefix           string             `json:"prefix,omitempty"`
	Relation         string             `json:"relation"`
	Origins          []uint32           `json:"origins"`
	Completeness     string             `json:"completeness"`
	FilteredPrefixes *int               `json:"filtered_prefixes,omitempty"`
	QueryTime        *time.Time         `json:"query_time,omitempty"`
	Routing          *RoutingVisibility `json:"routing,omitempty"`
}

type RoutingVisibility struct {
	Observation Observation `json:"observation"`
	SourceURL   string      `json:"source_url,omitempty"`
	ObservedAt  *time.Time  `json:"observed_at"`
	ExpiresAt   *time.Time  `json:"expires_at"`
	QueryTime   *time.Time  `json:"query_time,omitempty"`
	PeersSeeing *int        `json:"peers_seeing,omitempty"`
	TotalPeers  *int        `json:"total_peers,omitempty"`
	FirstSeen   *RouteSeen  `json:"first_seen,omitempty"`
	LastSeen    *RouteSeen  `json:"last_seen,omitempty"`
}

type RouteSeen struct {
	Time   time.Time `json:"time"`
	Prefix string    `json:"prefix"`
	Origin uint32    `json:"origin"`
}

type ROA struct {
	Prefix    string `json:"prefix"`
	ASN       uint32 `json:"asn"`
	MaxLength int    `json:"max_length"`
}

type OriginValidation struct {
	ASN           uint32     `json:"asn"`
	Status        string     `json:"status"`
	SourceURL     string     `json:"source_url,omitempty"`
	ObservedAt    *time.Time `json:"observed_at"`
	ROAsTruncated bool       `json:"roas_truncated"`
	CoveringROAs  []ROA      `json:"covering_roas"`
}

type RPKIExplanation struct {
	OriginObservedAt *time.Time         `json:"origin_observed_at,omitempty"`
	OriginExpiresAt  *time.Time         `json:"origin_expires_at,omitempty"`
	Prefix           string             `json:"prefix"`
	Basis            string             `json:"basis"`
	Status           string             `json:"status"`
	Completeness     string             `json:"completeness"`
	OriginLimit      int                `json:"origin_limit"`
	Truncated        bool               `json:"truncated"`
	Origins          []OriginValidation `json:"origins"`
}

type prefixOverview struct {
	Resource  string            `json:"resource"`
	Less      *bool             `json:"is_less_specific"`
	Announced *bool             `json:"announced"`
	Filtered  *int              `json:"num_filtered_out"`
	QueryTime string            `json:"query_time,omitempty"`
	ASNs      []json.RawMessage `json:"asns"`
}

func sourceTime(raw string) *time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, raw); err == nil && !t.After(time.Now().Add(time.Minute)) {
			return &t
		}
	}
	return nil
}

func bgpExplanation(m Metric, target Target) *BGPExplanation {
	if m.ObservedAt == nil || m.ObservedAt.After(time.Now().Add(time.Minute)) || m.Status != "ok" && m.Status != "stale" {
		return nil
	}
	var d prefixOverview
	if json.Unmarshal(m.Data, &d) != nil {
		return nil
	}
	actual, err := netip.ParsePrefix(d.Resource)
	if err != nil {
		return nil
	}
	b := &BGPExplanation{Prefix: actual.Masked().String(), Relation: "unknown", Completeness: "unknown", Origins: []uint32{}, FilteredPrefixes: d.Filtered, QueryTime: sourceTime(d.QueryTime)}
	if d.Filtered != nil && *d.Filtered < 0 {
		b.FilteredPrefixes = nil
	}
	if p, err := netip.ParsePrefix(target.Value); err == nil {
		if actual.Masked() == p && d.Less != nil && *d.Less {
			b.Relation = "covering"
			b.Prefix = ""
		} else if actual.Masked() == p && d.Less != nil && !*d.Less {
			b.Relation = "exact"
		} else if actual.Bits() < p.Bits() && actual.Contains(p.Addr()) && d.Less != nil && *d.Less {
			b.Relation = "covering"
		}
	} else if ip, err := netip.ParseAddr(target.Value); err == nil && actual.Contains(ip) {
		b.Relation = "covering"
	}
	valid := d.ASNs != nil
	seen := map[uint32]bool{}
	for _, raw := range d.ASNs {
		n := originASN(raw)
		if n == 0 {
			valid = false
			continue
		}
		if !seen[n] {
			b.Origins = append(b.Origins, n)
			seen[n] = true
		}
	}
	if b.Relation != "unknown" && b.Prefix != "" && d.Filtered != nil && *d.Filtered >= 0 && valid {
		b.Completeness = "complete"
		if *d.Filtered > 0 {
			b.Completeness = "partial"
		}
	}
	return b
}

func routingVisibility(m Metric, target Target, now time.Time) *RoutingVisibility {
	if m.ObservedAt == nil || m.ObservedAt.After(time.Now().Add(time.Minute)) || m.Status != "ok" && m.Status != "stale" {
		return nil
	}
	var d struct {
		Resource   string `json:"resource"`
		QueryTime  string `json:"query_time"`
		Visibility map[string]struct {
			Seeing *int `json:"ris_peers_seeing"`
			Total  *int `json:"total_ris_peers"`
		} `json:"visibility"`
		First json.RawMessage `json:"first_seen"`
		Last  json.RawMessage `json:"last_seen"`
	}
	if json.Unmarshal(m.Data, &d) != nil || d.Resource != target.Value {
		return nil
	}
	v := &RoutingVisibility{Observation: metricObservation(m, target, Query{}, now), SourceURL: m.SourceURL, ObservedAt: m.ObservedAt, ExpiresAt: m.ExpiresAt, QueryTime: sourceTime(d.QueryTime)}
	family := "v4"
	if p, err := netip.ParsePrefix(target.Value); err == nil && p.Addr().Is6() {
		family = "v6"
	}
	counts := d.Visibility[family]
	if counts.Seeing != nil && counts.Total != nil && *counts.Seeing >= 0 && *counts.Total >= *counts.Seeing {
		v.PeersSeeing = counts.Seeing
		v.TotalPeers = counts.Total
	}
	v.FirstSeen = routeSeen(d.First, target)
	v.LastSeen = routeSeen(d.Last, target)
	return v
}

func routeSeen(raw json.RawMessage, target Target) *RouteSeen {
	var d struct {
		Time   string          `json:"time"`
		Prefix string          `json:"prefix"`
		Origin json.RawMessage `json:"origin"`
	}
	if json.Unmarshal(raw, &d) != nil {
		return nil
	}
	p, err := netip.ParsePrefix(d.Prefix)
	requested, e := netip.ParsePrefix(target.Value)
	t := sourceTime(d.Time)
	if err != nil || e != nil || p.Bits() > requested.Bits() || !p.Contains(requested.Addr()) || t == nil || originASN(d.Origin) == 0 {
		return nil
	}
	return &RouteSeen{Time: *t, Prefix: p.Masked().String(), Origin: originASN(d.Origin)}
}

func rpkiExplanation(m Metric) *RPKIExplanation {
	if m.ObservedAt == nil || m.ObservedAt.After(time.Now().Add(time.Minute)) || m.Status != "ok" && m.Status != "stale" {
		return nil
	}
	var d struct {
		Prefix             string     `json:"prefix"`
		Basis              string     `json:"basis"`
		Truncated          bool       `json:"truncated"`
		OriginCompleteness string     `json:"origin_completeness"`
		OriginObservedAt   *time.Time `json:"origin_observed_at"`
		OriginExpiresAt    *time.Time `json:"origin_expires_at"`
		Origins            []struct {
			ASN        uint32          `json:"asn"`
			SourceURL  string          `json:"source_url"`
			ObservedAt *time.Time      `json:"observed_at"`
			Data       json.RawMessage `json:"data"`
		} `json:"origins"`
	}
	if json.Unmarshal(m.Data, &d) != nil {
		return nil
	}
	p, err := netip.ParsePrefix(d.Prefix)
	if err != nil {
		return nil
	}
	basis := d.Basis
	if basis == "" {
		basis = "observed_origins"
	}
	if basis != "observed_origins" && basis != "proposed_asn" {
		return nil
	}
	out := &RPKIExplanation{OriginObservedAt: d.OriginObservedAt, OriginExpiresAt: d.OriginExpiresAt, Prefix: p.Masked().String(), Basis: basis, Status: "partial", Completeness: "complete", OriginLimit: 4, Truncated: d.Truncated || len(d.Origins) > 4, Origins: []OriginValidation{}}
	if d.Truncated || len(d.Origins) == 0 || len(d.Origins) > 4 || d.OriginCompleteness != "" && d.OriginCompleteness != "complete" {
		out.Completeness = "partial"
	}
	seen := map[uint32]bool{}
	states := map[string]bool{}
	for _, o := range d.Origins[:min(4, len(d.Origins))] {
		if o.ASN == 0 {
			out.Completeness = "partial"
			continue
		}
		v := OriginValidation{ASN: o.ASN, Status: "unavailable", SourceURL: o.SourceURL, ObservedAt: o.ObservedAt, CoveringROAs: []ROA{}}
		var data struct {
			Prefix        string            `json:"prefix"`
			Resource      json.RawMessage   `json:"resource"`
			Status        string            `json:"status"`
			Validating    []json.RawMessage `json:"validating_roas"`
			ROAsTruncated bool              `json:"roas_truncated"`
		}
		if o.ASN != 0 && !seen[o.ASN] && json.Unmarshal(o.Data, &data) == nil && samePrefix(data.Prefix, p.Masked()) && originASN(data.Resource) == o.ASN {
			switch data.Status {
			case "valid", "invalid_asn", "invalid_length":
				v.Status = data.Status
			case "unknown":
				v.Status = "not_found"
			}
			if v.Status != "unavailable" && v.ObservedAt == nil {
				v.ObservedAt = m.ObservedAt
			}
			v.ROAsTruncated = data.ROAsTruncated || len(data.Validating) > 32
			for _, raw := range data.Validating[:min(32, len(data.Validating))] {
				var roa struct {
					Prefix string          `json:"prefix"`
					Origin json.RawMessage `json:"origin"`
					ASN    json.RawMessage `json:"asn"`
					Max    *int            `json:"max_length"`
				}
				if json.Unmarshal(raw, &roa) != nil {
					continue
				}
				rp, e := netip.ParsePrefix(roa.Prefix)
				asn, validASN := roaASN(roa.Origin)
				if !validASN {
					asn, validASN = roaASN(roa.ASN)
				}
				if validASN && e == nil && rp == rp.Masked() && rp.Bits() <= p.Bits() && rp.Contains(p.Addr()) && roa.Max != nil && *roa.Max >= rp.Bits() && *roa.Max <= rp.Addr().BitLen() {
					v.CoveringROAs = append(v.CoveringROAs, ROA{Prefix: rp.String(), ASN: asn, MaxLength: *roa.Max})
				}
			}
		}
		seen[o.ASN] = true
		if v.ObservedAt != nil && v.ObservedAt.After(time.Now().Add(time.Minute)) {
			v.Status = "unavailable"
			v.ObservedAt = nil
		}
		if v.Status == "unavailable" {
			out.Completeness = "partial"
		}
		states[v.Status] = true
		out.Origins = append(out.Origins, v)
	}
	if out.Completeness == "complete" {
		switch {
		case len(states) > 1:
			out.Status = "mixed"
		case states["valid"]:
			out.Status = "valid"
		case states["not_found"]:
			out.Status = "not_found"
		default:
			out.Status = "invalid"
		}
	}
	return out
}

func decorateRouting(m Metric, target Target, asn uint32) Metric {
	if m.Name == "prefix_overview" {
		m.BGP = bgpExplanation(m, target)
	}
	if m.Name == "rpki" {
		m.RPKI = rpkiExplanation(m)
		if m.RPKI != nil && asn != 0 {
			m.RPKI.Basis = "proposed_asn"
			if len(m.RPKI.Origins) != 1 || m.RPKI.Origins[0].ASN != asn {
				m.RPKI.Status = "partial"
				m.RPKI.Completeness = "partial"
			}
		}
		if m.RPKI != nil && m.RPKI.Basis == "observed_origins" && m.RPKI.OriginExpiresAt != nil {
			if m.ExpiresAt == nil || m.RPKI.OriginExpiresAt.Before(*m.ExpiresAt) {
				m.ExpiresAt = m.RPKI.OriginExpiresAt
			}
			if !time.Now().Before(*m.ExpiresAt) {
				m.Status = "stale"
			}
		}
	}
	return m
}

func metricPartial(m Metric) bool {
	return m.Status != "ok" || m.Name == "abuse" && (m.Abuse == nil || m.Abuse.Completeness != "complete") || m.Name == "irr" && m.IRR == nil || m.IRR != nil && (m.IRR.Completeness != "complete" || m.IRR.Status == "bgp_unavailable" || m.IRR.Status == "partial") || m.Name == "rpki" && m.RPKI == nil || m.Name == "prefix_overview" && m.BGP == nil || m.RPKI != nil && m.RPKI.Completeness != "complete" || m.BGP != nil && m.BGP.Completeness != "complete"
}

func reconcileRPKI(m *Metric, overview Metric) {
	b := overview.BGP
	origins := []uint32{}
	for _, o := range m.RPKI.Origins {
		origins = append(origins, o.ASN)
	}
	if b == nil || b.Relation != "exact" || b.Prefix != m.RPKI.Prefix || b.Completeness != "complete" || !sameOrigins(origins, b.Origins) {
		m.RPKI.Completeness = "partial"
		m.RPKI.Status = "partial"
	}
	if overview.ExpiresAt != nil && (m.ExpiresAt == nil || overview.ExpiresAt.Before(*m.ExpiresAt)) {
		m.ExpiresAt = overview.ExpiresAt
	}
	if overview.Status != "ok" || overview.ExpiresAt == nil || !time.Now().Before(*overview.ExpiresAt) {
		m.Status = "stale"
	}
}

func roaASN(raw json.RawMessage) (uint32, bool) {
	var text string
	if json.Unmarshal(raw, &text) != nil {
		text = string(raw)
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(text), "AS"), 10, 32)
	return uint32(n), err == nil
}

func attachRoutingContext(r *Report) {
	var routing Metric
	for _, m := range r.Metrics {
		if m.Name == "routing_status" {
			routing = m
		}
	}
	if routing.Name == "" {
		return
	}
	for i := range r.Metrics {
		if r.Metrics[i].BGP != nil {
			r.Metrics[i].BGP.Routing = routingVisibility(routing, r.Resource, time.Now())
		}
	}
}

package intelligence

import (
	"encoding/json"
	"net/netip"
	"slices"
	"time"
)

type ObservationScope struct {
	Requested string `json:"requested"`
	Kind      string `json:"kind"`
	Resource  string `json:"resource,omitempty"`
	Relation  string `json:"relation"`
	ASN       uint32 `json:"asn,omitempty"`
	StartTime string `json:"start_time,omitempty"`
	EndTime   string `json:"end_time,omitempty"`
	Version   string `json:"version,omitempty"`
}

type Observation struct {
	CollectionStatus string           `json:"collection_status"`
	Freshness        string           `json:"freshness"`
	Completeness     string           `json:"completeness"`
	Scope            ObservationScope `json:"scope"`
	FailureReason    string           `json:"failure_reason,omitempty"`
}

func observation(status string, observed, expires *time.Time, now time.Time) Observation {
	o := Observation{CollectionStatus: "unknown", Freshness: "unknown", Completeness: "unknown"}
	switch status {
	case "pending", "disabled", "not_configured", "not_applicable", "no_data", "rate_limited":
		o.CollectionStatus = status
	case "unavailable":
		o.CollectionStatus = "failed"
	case "ok", "stale", "announced", "not_announced", "covering_route", "valid", "invalid", "not_found", "mixed", "partial", "listed", "not_listed":
		if observed != nil {
			o.CollectionStatus = "succeeded"
		}
	}
	if observed != nil && !observed.After(now.Add(time.Minute)) && (expires == nil || !observed.After(*expires)) {
		o.Freshness = "stale"
		if expires != nil && now.Before(*expires) && status != "stale" {
			o.Freshness = "fresh"
		}
	}
	return o
}

func metricObservation(m Metric, target Target, q Query, now time.Time) Observation {
	o := observation(m.Status, m.ObservedAt, m.ExpiresAt, now)
	o.Scope = ObservationScope{Requested: target.Value, Kind: target.Kind, Relation: "unknown", ASN: q.ASN, StartTime: q.StartTime, EndTime: q.EndTime, Version: q.Version}
	if m.Status != "ok" && m.Status != "no_data" {
		o.FailureReason = m.Error
	}
	if m.Status != "ok" && m.Status != "stale" || m.ObservedAt == nil {
		return o
	}
	if m.Registration != nil {
		o.Completeness = m.Registration.Completeness
		if len(m.Registration.Records) == 1 {
			scope := m.Registration.Records[0].Range
			o.Scope.Resource = scope.Resource
			o.Scope.Relation = scope.Relation
		}
		return o
	}
	var data struct {
		Resource string `json:"resource"`
		Prefix   string `json:"prefix"`
		Filtered *int   `json:"num_filtered_out"`
		ASNs     []struct {
			ASN uint32 `json:"asn"`
		} `json:"asns"`
	}
	if json.Unmarshal(m.Data, &data) != nil {
		return o
	}
	raw := data.Resource
	if m.Name == "rpki" {
		raw = data.Prefix
	}
	if actual, err := ParseTarget(raw); err == nil {
		o.Scope.Resource = actual.Value
		if actual == target {
			o.Scope.Relation = "exact"
		} else if p, err := netip.ParsePrefix(actual.Value); err == nil {
			if requested, err := netip.ParsePrefix(target.Value); err == nil && p.Bits() < requested.Bits() && p.Contains(requested.Addr()) {
				o.Scope.Relation = "covering"
			} else if ip, err := netip.ParseAddr(target.Value); err == nil && p.Contains(ip) {
				o.Scope.Relation = "covering"
			}
		}
	}
	if m.Name == "prefix_overview" && o.Scope.Relation != "unknown" && data.Filtered != nil {
		if *data.Filtered == 0 {
			o.Completeness = "complete"
		} else {
			o.Completeness = "partial"
		}
	}
	if (m.Name == "asn_rank" || m.Name == "asn_neighbours") && target.Kind != "asn" {
		o.Scope.Resource = ""
		o.Scope.Relation = "origin_asns"
	} else if m.Name == "asn_rank" && target.Kind == "asn" && len(data.ASNs) == 1 && data.ASNs[0].ASN == target.ASN {
		o.Scope.Resource = target.Value
		o.Scope.Relation = "exact"
	}
	return o
}

func checkObservation(c Check, resource, name string, now time.Time) Observation {
	o := observation(c.Status, c.ObservedAt, c.ExpiresAt, now)
	if c.Freshness != "fresh" {
		o.Freshness = c.Freshness
		if o.Freshness != "stale" {
			o.Freshness = "unknown"
		}
	}
	o.Scope = ObservationScope{Requested: resource, Kind: "prefix", Relation: "unknown"}
	if o.CollectionStatus == "failed" {
		o.FailureReason = c.Reason
	}
	if c.ObservedAt == nil {
		return o
	}
	switch {
	case name == "spamhaus_drop" && (c.Status == "listed" || c.Status == "not_listed"):
		o.Scope.Relation = "overlap"
		o.Scope.Resource = resource
		o.Completeness = "complete"
	case c.Status == "covering_route":
		o.Scope.Relation = "covering"
	case c.Status == "announced" || c.Status == "not_announced" || name == "rpki" && slices.Contains([]string{"valid", "invalid", "not_found", "mixed", "partial"}, c.Status):
		o.Scope.Relation = "exact"
		o.Scope.Resource = resource
		if name == "rpki" {
			o.Completeness = "unknown"
			if c.Status == "valid" || c.Status == "not_found" || c.Status == "mixed" {
				o.Completeness = "complete"
			} else if c.Status == "partial" {
				o.Completeness = "partial"
			}
		}
	}
	return o
}

func (s *Service) initialMetric(target Target, name string) Metric {
	d := definitions[name]
	m := Metric{Name: name, Status: "pending", Source: d.Source, Coverage: d.Coverage, Data: json.RawMessage("null")}
	if !slices.Contains(d.Kinds, target.Kind) {
		m.Status = "not_applicable"
	} else if name == "ipinfo_lite" && s.token == "" {
		m.Status = "not_configured"
		m.Error = "Optional IPinfo Lite free token is not configured"
	}
	return m
}

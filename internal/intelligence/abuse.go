package intelligence

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"net/url"
	"time"
)

const abuseEndpoint = "https://api.abuseipdb.com/api/v2/check-block"
const abuseWindowDays = 30
const abuseAddressLimit = 256

var errSourcePlan = errors.New("source plan does not permit query")

type ReportedAddress struct {
	Address          string     `json:"address"`
	Reports          int64      `json:"reports"`
	LatestReportAt   *time.Time `json:"latest_report_at,omitempty"`
	SourceConfidence *int       `json:"source_confidence,omitempty"`
}

type AbuseObservation struct {
	Prefix               string            `json:"prefix"`
	Status               string            `json:"status"`
	Completeness         string            `json:"completeness"`
	ScopeRelation        string            `json:"scope_relation"`
	RangeStart           string            `json:"range_start"`
	RangeEnd             string            `json:"range_end"`
	PossibleHosts        uint64            `json:"possible_hosts"`
	WindowDays           int               `json:"window_days"`
	WindowStart          time.Time         `json:"window_start"`
	WindowEnd            time.Time         `json:"window_end"`
	WindowBasis          string            `json:"window_basis"`
	IngestedAt           time.Time         `json:"ingested_at"`
	ReportedIPCount      int               `json:"reported_ip_count"`
	ReportCount          int64             `json:"report_count"`
	LatestReportAt       *time.Time        `json:"latest_report_at,omitempty"`
	CountsAreLowerBounds bool              `json:"counts_are_lower_bounds"`
	Truncated            bool              `json:"truncated"`
	AddressLimit         int               `json:"address_limit"`
	Addresses            []ReportedAddress `json:"addresses"`
	DetailsCoverage      string            `json:"details_coverage"`
	Semantics            string            `json:"semantics"`
}

// EnableAbuseIPDB must run before collection, after account and data-use approval.
func (s *Service) EnableAbuseIPDB(key string) { s.abuseEnabled = true; s.abuseKey = key }
func (s *Service) abuseConfigured() bool      { return s.abuseEnabled && s.abuseKey != "" }

func abuseSupported(target Target) bool {
	p, err := netip.ParsePrefix(target.Value)
	return err == nil && target.Kind == "prefix" && p.Addr().Is4() && p.Bits() >= 24
}

func (s *Service) abuse(ctx context.Context, target Target) (Metric, error) {
	started := time.Now().UTC()
	rawURL := abuseEndpoint + "?" + url.Values{"network": {target.Value}, "maxAgeInDays": {"30"}}.Encode()
	b, err := s.request(ctx, rawURL, s.abuseKey)
	if errors.Is(err, ErrNoData) {
		return Metric{}, errors.New("abuse source unavailable")
	}
	if err != nil {
		return Metric{}, err
	}
	captured := time.Now().UTC()
	detail, err := normalizeAbuse(b, target, started, captured)
	if err != nil {
		return Metric{}, err
	}
	data, _ := json.Marshal(detail)
	return Metric{Abuse: detail, Data: data, ObservedAt: &captured, SourceURL: rawURL}, nil
}

func normalizeAbuse(raw json.RawMessage, target Target, started, captured time.Time) (*AbuseObservation, error) {
	var envelope struct {
		Errors []json.RawMessage `json:"errors"`
		Data   *struct {
			Network   string  `json:"networkAddress"`
			Mask      string  `json:"netmask"`
			Min       string  `json:"minAddress"`
			Max       string  `json:"maxAddress"`
			Hosts     *uint64 `json:"numPossibleHosts"`
			Truncated bool    `json:"truncated"`
			HasMore   bool    `json:"hasMore"`
			Next      string  `json:"nextPageUrl"`
			Reported  []struct {
				IP         string  `json:"ipAddress"`
				Reports    *int64  `json:"numReports"`
				Latest     *string `json:"mostRecentReport"`
				Confidence *int    `json:"abuseConfidenceScore"`
			} `json:"reportedAddress"`
		} `json:"data"`
		Meta struct {
			Truncated bool   `json:"truncated"`
			HasMore   bool   `json:"hasMore"`
			Next      string `json:"nextPageUrl"`
		} `json:"meta"`
		Links struct {
			Next string `json:"next"`
		} `json:"links"`
	}
	invalid := errors.New("invalid abuse source response")
	if !abuseSupported(target) || captured.Before(started) || json.Unmarshal(raw, &envelope) != nil || envelope.Data == nil || len(envelope.Errors) > 0 {
		return nil, invalid
	}
	d := envelope.Data
	p, _ := netip.ParsePrefix(target.Value)
	network, err := netip.ParseAddr(d.Network)
	if err != nil || network != p.Addr() {
		return nil, invalid
	}
	mask, err := netip.ParseAddr(d.Mask)
	if err != nil || !mask.Is4() {
		return nil, invalid
	}
	maskBytes := mask.As4()
	bits, total := net.IPMask(maskBytes[:]).Size()
	if total != 32 || bits != p.Bits() || d.Hosts == nil || d.Reported == nil {
		return nil, invalid
	}
	minIP, e1 := netip.ParseAddr(d.Min)
	maxIP, e2 := netip.ParseAddr(d.Max)
	if e1 != nil || e2 != nil || !p.Contains(minIP) || !p.Contains(maxIP) || minIP.Compare(maxIP) > 0 {
		return nil, invalid
	}
	first := p.Addr().As4()
	lastValue := binary.BigEndian.Uint32(first[:]) + uint32((uint64(1)<<uint(32-p.Bits()))-1)
	minBytes, maxBytes := minIP.As4(), maxIP.As4()
	minValue, maxValue := binary.BigEndian.Uint32(minBytes[:]), binary.BigEndian.Uint32(maxBytes[:])
	out := &AbuseObservation{Prefix: target.Value, Status: "no_reports_in_window", Completeness: "complete", ScopeRelation: "exact", RangeStart: minIP.String(), RangeEnd: maxIP.String(), PossibleHosts: *d.Hosts, WindowDays: abuseWindowDays, WindowStart: started.Add(-abuseWindowDays * 24 * time.Hour), WindowEnd: captured, WindowBasis: "local_request_bounds", IngestedAt: captured, AddressLimit: abuseAddressLimit, Addresses: []ReportedAddress{}, DetailsCoverage: "not_collected", Semantics: "source_reports_not_cleanliness_tenant_attribution_or_resolution"}
	if minIP != p.Addr() || maxValue != lastValue {
		out.ScopeRelation = "contained"
		out.Completeness = "partial"
	}
	if *d.Hosts != uint64(maxValue)-uint64(minValue)+1 {
		out.Completeness = "partial"
	}
	if d.Truncated || d.HasMore || d.Next != "" || envelope.Meta.Truncated || envelope.Meta.HasMore || envelope.Meta.Next != "" || envelope.Links.Next != "" || len(d.Reported) > abuseAddressLimit {
		out.Truncated = true
		out.Completeness = "partial"
	}
	seen := map[netip.Addr]bool{}
	for _, row := range d.Reported[:min(abuseAddressLimit, len(d.Reported))] {
		ip, e := netip.ParseAddr(row.IP)
		if e != nil || !p.Contains(ip) || ip.Compare(minIP) < 0 || ip.Compare(maxIP) > 0 || seen[ip] || row.Reports == nil || *row.Reports <= 0 {
			out.Completeness = "partial"
			continue
		}
		seen[ip] = true
		if *row.Reports > math.MaxInt64-out.ReportCount {
			return nil, invalid
		}
		entry := ReportedAddress{Address: ip.String(), Reports: *row.Reports}
		if row.Latest != nil {
			if date, e := time.Parse(time.RFC3339Nano, *row.Latest); e == nil {
				if date.After(captured) || date.Before(out.WindowStart) {
					out.Completeness = "partial"
				}
				entry.LatestReportAt = &date
				if out.LatestReportAt == nil || date.After(*out.LatestReportAt) {
					out.LatestReportAt = &date
				}
			}
		}
		if entry.LatestReportAt == nil {
			out.Completeness = "partial"
		}
		if row.Confidence != nil {
			if *row.Confidence >= 0 && *row.Confidence <= 100 {
				entry.SourceConfidence = row.Confidence
			} else {
				out.Completeness = "partial"
			}
		}
		out.Addresses = append(out.Addresses, entry)
		out.ReportCount += entry.Reports
	}
	out.ReportedIPCount = len(out.Addresses)
	out.CountsAreLowerBounds = out.Completeness != "complete"
	if out.ReportCount > 0 {
		out.Status = "reports_observed"
	}
	if out.Completeness != "complete" {
		out.Status = "partial"
	}
	return out, nil
}

func decorateAbuse(m Metric, target Target, now time.Time) Metric {
	m.Abuse = nil
	if m.Name != "abuse" || m.ObservedAt == nil || m.ObservedAt.After(now.Add(time.Minute)) || m.Status != "ok" && m.Status != "stale" {
		return m
	}
	var detail AbuseObservation
	if json.Unmarshal(m.Data, &detail) != nil || detail.Prefix != target.Value || detail.WindowDays != abuseWindowDays || detail.Addresses == nil || detail.WindowEnd.Before(detail.WindowStart) || detail.IngestedAt.IsZero() || detail.IngestedAt.After(now.Add(time.Minute)) {
		return m
	}
	if m.ExpiresAt == nil || !now.Before(*m.ExpiresAt) {
		m.Status = "stale"
	}
	if m.Status == "stale" {
		detail.Status = "partial"
	}
	m.Abuse = &detail
	return m
}

func summarizeAbuse(r Report, now time.Time) Check {
	var m Metric
	for _, metric := range r.Metrics {
		if metric.Name == "abuse" {
			m = metric
		}
	}
	m = decorateAbuse(m, r.Resource, now)
	check := metricCheck(m, now)
	check.Abuse = m.Abuse
	if m.Abuse != nil {
		check.Status = m.Abuse.Status
		check.Reason = "Source reports in a query window; not cleanliness, resolution or attribution to a tenant"
	}
	switch m.Status {
	case "not_configured", "not_applicable", "disabled", "plan_limited":
		check.Status = m.Status
	}
	return check
}

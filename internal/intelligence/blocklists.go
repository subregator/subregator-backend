package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"
)

var errSourceAccess = errors.New("source access denied")

const zenEndpoint = "https://apibl.spamhaus.net/lookup/v1/ZEN/"

type ListFinding struct {
	List   string `json:"list"`
	Status string `json:"status"`
	Codes  []int  `json:"codes"`
	Reason string `json:"reason"`
}

type BlocklistObservation struct {
	Requested     string        `json:"requested"`
	Address       string        `json:"address"`
	Status        string        `json:"status"`
	Completeness  string        `json:"completeness"`
	ScopeRelation string        `json:"scope_relation"`
	Selection     string        `json:"selection"`
	Findings      []ListFinding `json:"findings"`
	Semantics     string        `json:"semantics"`
}

// EnableSpamhaus must run before workers start, after product and data-use approval.
func (s *Service) EnableSpamhaus(key string) { s.spamhausEnabled = true; s.spamhausKey = key }
func (s *Service) spamhausConfigured() bool  { return s.spamhausEnabled && s.spamhausKey != "" }

func blocklistAddress(target Target) (netip.Addr, bool) {
	if target.Kind == "ip" {
		ip, err := netip.ParseAddr(target.Value)
		return ip, err == nil
	}
	if target.Kind == "prefix" {
		p, err := netip.ParsePrefix(target.Value)
		if err == nil {
			return p.Addr(), true
		}
	}
	return netip.Addr{}, false
}

func normalizeZEN(raw []byte, target Target) (*BlocklistObservation, error) {
	bad := errors.New("invalid Spamhaus response")
	ip, ok := blocklistAddress(target)
	if !ok {
		return nil, bad
	}
	var envelope struct {
		Status int   `json:"status"`
		Codes  []int `json:"resp"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Status != 200 || len(envelope.Codes) == 0 || len(envelope.Codes) > 16 {
		return nil, bad
	}
	out := emptyZEN(target, ip)
	seen := map[int]bool{}
	for _, code := range envelope.Codes {
		if seen[code] {
			continue
		}
		seen[code] = true
		index := -1
		switch code {
		case 1002, 1003, 1009:
			index = 0
		case 1004:
			index = 1
		case 1010, 1011:
			index = 2
		default:
			return nil, bad
		}
		out.Findings[index].Status = "listed"
		out.Findings[index].Codes = append(out.Findings[index].Codes, code)
	}
	out.Status = "listed"
	return out, nil
}

func emptyZEN(target Target, ip netip.Addr) *BlocklistObservation {
	out := &BlocklistObservation{Requested: target.Value, Address: ip.String(), Status: "not_listed", Completeness: "complete", ScopeRelation: "exact", Selection: "requested_address", Semantics: "source_scoped_lists_not_safety_ownership_or_tenant_attribution", Findings: []ListFinding{
		{List: "SBL", Status: "not_listed", Codes: []int{}, Reason: "Spamhaus SBL, including CSS and DROP flags; applies only to the queried IP"},
		{List: "XBL", Status: "not_listed", Codes: []int{}, Reason: "Spamhaus compromised-host source finding; applies only to the queried IP"},
		{List: "PBL", Status: "not_listed", Codes: []int{}, Reason: "Outbound mail policy; not an abuse conviction"},
	}}
	if p, err := netip.ParsePrefix(target.Value); err == nil && p.Bits() != ip.BitLen() {
		out.Completeness = "partial"
		out.ScopeRelation = "contained"
		out.Selection = "prefix_first_address"
	}
	return out
}

func (s *Service) zen(ctx context.Context, target Target) (Metric, error) {
	ip, ok := blocklistAddress(target)
	if !ok {
		return Metric{}, errors.New("unsupported Spamhaus scope")
	}
	source := zenEndpoint + ip.String()
	raw, err := s.request(ctx, source, s.spamhausKey)
	var detail *BlocklistObservation
	if errors.Is(err, ErrNoData) {
		detail = emptyZEN(target, ip)
	} else if err == nil {
		detail, err = normalizeZEN(raw, target)
	}
	if err != nil && !errors.Is(err, ErrNoData) {
		return Metric{}, err
	}
	data, _ := json.Marshal(detail)
	return Metric{Data: data, Blocklists: detail, ObservedAt: observedNow(), SourceURL: source}, nil
}

func decorateBlocklists(m Metric, target Target, now time.Time) Metric {
	m.Blocklists = nil
	if m.Name != "spamhaus_zen" || m.ObservedAt == nil || m.ObservedAt.After(now.Add(time.Minute)) || (m.Status != "ok" && m.Status != "stale") {
		return m
	}
	var d BlocklistObservation
	ip, ok := blocklistAddress(target)
	if !ok || json.Unmarshal(m.Data, &d) != nil || d.Requested != target.Value || d.Address != ip.String() || len(d.Findings) != 3 {
		return m
	}
	expected := emptyZEN(target, ip)
	if d.Completeness != expected.Completeness || d.ScopeRelation != expected.ScopeRelation || d.Selection != expected.Selection {
		return m
	}
	if m.ExpiresAt == nil || !now.Before(*m.ExpiresAt) {
		m.Status = "stale"
	}
	if m.Status == "stale" {
		d.Status = "partial"
	}
	m.Blocklists = &d
	return m
}
func summarizeBlocklists(r Report, now time.Time) Check {
	var m Metric
	for _, metric := range r.Metrics {
		if metric.Name == "spamhaus_zen" {
			m = metric
		}
	}
	m = decorateBlocklists(m, r.Resource, now)
	c := metricCheck(m, now)
	c.Blocklists = m.Blocklists
	if m.Blocklists != nil {
		c.Status = m.Blocklists.Status
		c.Reason = "One queried IP only; prefix coverage may be partial; PBL is mail policy"
	}
	switch m.Status {
	case "not_configured", "not_applicable", "disabled", "access_denied", "rate_limited":
		c.Status = m.Status
	}
	return c
}

package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"time"
)

const irrBase = "https://irrexplorer.nlnog.net/api/"
const irrObjectLimit = 200

var irrRegistryName = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,31}$`)

type IRRObject struct {
	Class      string `json:"class"`
	Prefix     string `json:"prefix"`
	Origin     uint32 `json:"origin"`
	Registry   string `json:"registry"`
	ID         string `json:"id,omitempty"`
	Relation   string `json:"relation"`
	MatchesBGP *bool  `json:"matches_bgp,omitempty"`
}

type IRRRegistry struct {
	Name      string     `json:"name"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	Freshness string     `json:"freshness"`
}

type IRRComparison struct {
	Status      string      `json:"status"`
	Observation Observation `json:"observation"`
	Origins     []uint32    `json:"origins"`
	ObservedAt  *time.Time  `json:"observed_at"`
	ExpiresAt   *time.Time  `json:"expires_at"`
	SourceURL   string      `json:"source_url,omitempty"`
}

type IRRExplanation struct {
	Prefix             string         `json:"prefix"`
	Status             string         `json:"status"`
	Completeness       string         `json:"completeness"`
	Truncated          bool           `json:"truncated"`
	ObjectLimit        int            `json:"object_limit"`
	Objects            []IRRObject    `json:"objects"`
	Registries         []IRRRegistry  `json:"registries"`
	MissingOrigins     []uint32       `json:"missing_origins"`
	BGP                *IRRComparison `json:"bgp,omitempty"`
	MetadataURL        string         `json:"metadata_url"`
	MetadataObservedAt *time.Time     `json:"metadata_observed_at,omitempty"`
}

func irrSupported(target Target) bool {
	p, err := netip.ParsePrefix(target.Value)
	return err == nil && target.Kind == "prefix" && (p.Addr().Is4() && p.Bits() >= 9 || p.Addr().Is6() && p.Bits() >= 29)
}

func (s *Service) irr(ctx context.Context, target Target) (Metric, error) {
	rawURL := irrBase + "prefixes/prefix/" + target.Value
	routes, err := s.request(ctx, rawURL, "")
	if errors.Is(err, ErrNoData) {
		return Metric{}, errors.New("IRR source unavailable")
	}
	if err != nil {
		return Metric{}, err
	}
	metadata, metadataError := s.request(ctx, irrBase+"metadata/", "")
	detail, err := normalizeIRR(routes, metadata, target, time.Now())
	if err != nil {
		return Metric{}, err
	}
	if metadataError == nil {
		detail.MetadataObservedAt = observedNow()
	}
	b, _ := json.Marshal(detail)
	m := Metric{IRR: detail, Data: b, ObservedAt: observedNow(), SourceURL: rawURL}
	var limited *sourceLimited
	if errors.As(metadataError, &limited) {
		m.RetryAt = &limited.Until
	}
	return m, nil
}

func normalizeIRR(routes, metadata json.RawMessage, target Target, now time.Time) (*IRRExplanation, error) {
	var rows []struct {
		Prefix string `json:"prefix"`
		Routes map[string][]struct {
			ASN uint32 `json:"asn"`
			ID  string `json:"rpslPk"`
		} `json:"irrRoutes"`
	}
	if json.Unmarshal(routes, &rows) != nil || rows == nil {
		return nil, errors.New("invalid IRR response")
	}
	requested, err := netip.ParsePrefix(target.Value)
	if err != nil {
		return nil, errors.New("unsupported IRR scope")
	}
	out := &IRRExplanation{Prefix: target.Value, Status: "bgp_unavailable", Completeness: "complete", ObjectLimit: irrObjectLimit, Objects: []IRRObject{}, Registries: []IRRRegistry{}, MissingOrigins: []uint32{}, MetadataURL: irrBase + "metadata/"}
	count := 0
	for _, row := range rows {
		p, e := netip.ParsePrefix(row.Prefix)
		if e != nil || p != p.Masked() || !p.Overlaps(requested) || row.Routes == nil {
			out.Completeness = "partial"
			continue
		}
		relation := "exact"
		if p.Bits() < requested.Bits() {
			relation = "covering"
		} else if p.Bits() > requested.Bits() {
			relation = "contained"
		}
		class := "route"
		if p.Addr().Is6() {
			class = "route6"
		}
		sources := make([]string, 0, len(row.Routes))
		for source := range row.Routes {
			sources = append(sources, source)
		}
		sort.Strings(sources)
		for _, source := range sources {
			for _, object := range row.Routes[source] {
				count++
				if count > irrObjectLimit {
					out.Truncated = true
					out.Completeness = "partial"
					continue
				}
				if !irrRegistryName.MatchString(source) || source == "RPKI" || len(object.ID) > 200 || object.ASN == 0 {
					out.Completeness = "partial"
					continue
				}
				out.Objects = append(out.Objects, IRRObject{Class: class, Prefix: p.String(), Origin: object.ASN, Registry: source, ID: object.ID, Relation: relation})
			}
		}
	}
	var meta struct {
		LastUpdate struct {
			IRR map[string]string `json:"irr"`
		} `json:"last_update"`
	}
	if json.Unmarshal(metadata, &meta) != nil || len(meta.LastUpdate.IRR) == 0 {
		out.Completeness = "partial"
	}
	names := make([]string, 0, len(meta.LastUpdate.IRR))
	for name := range meta.LastUpdate.IRR {
		if name != "RPKI" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if len(out.Registries) >= 64 {
			out.Completeness = "partial"
			break
		}
		if !irrRegistryName.MatchString(name) {
			out.Completeness = "partial"
			continue
		}
		raw := meta.LastUpdate.IRR[name]
		t, e := time.Parse("2006-01-02 15:04:05.999999999Z07:00", raw)
		if e != nil {
			t, e = time.Parse(time.RFC3339Nano, raw)
		}
		entry := IRRRegistry{Name: name, Freshness: "unknown"}
		if e == nil && !t.After(now.Add(time.Minute)) {
			entry.UpdatedAt = &t
			entry.Freshness = "fresh"
			if now.Sub(t) > 24*time.Hour {
				entry.Freshness = "stale"
			}
		}
		if entry.Freshness == "unknown" {
			out.Completeness = "partial"
		}
		out.Registries = append(out.Registries, entry)
	}
	for _, object := range out.Objects {
		if !slices.ContainsFunc(out.Registries, func(r IRRRegistry) bool { return r.Name == object.Registry }) {
			out.Completeness = "partial"
		}
	}
	if len(out.Registries) == 0 {
		out.Completeness = "partial"
	}
	return out, nil
}

func decorateIRR(m Metric, target Target, now time.Time) Metric {
	m.IRR = nil
	if m.Name != "irr" || m.ObservedAt == nil || m.ObservedAt.After(now.Add(time.Minute)) || m.Status != "ok" && m.Status != "stale" {
		return m
	}
	if m.ExpiresAt == nil || !now.Before(*m.ExpiresAt) {
		m.Status = "stale"
	}
	var detail IRRExplanation
	if json.Unmarshal(m.Data, &detail) != nil || detail.Prefix != target.Value || detail.Objects == nil || detail.Registries == nil {
		return m
	}
	detail.BGP = nil
	detail.MissingOrigins = []uint32{}
	detail.Status = "bgp_unavailable"
	for i := range detail.Objects {
		detail.Objects[i].MatchesBGP = nil
	}
	for i := range detail.Registries {
		r := &detail.Registries[i]
		r.Freshness = "unknown"
		if r.UpdatedAt != nil && !r.UpdatedAt.After(now.Add(time.Minute)) {
			r.Freshness = "fresh"
			if now.Sub(*r.UpdatedAt) > 24*time.Hour {
				r.Freshness = "stale"
				m.Status = "stale"
			}
		}
		if r.Freshness == "unknown" {
			detail.Completeness = "partial"
		}
	}
	if detail.Truncated || detail.Completeness != "complete" {
		detail.Completeness = "partial"
		detail.Status = "partial"
	}
	m.IRR = &detail
	return m
}

func compareIRR(m *Metric, overview Metric, target Target, now time.Time) {
	if m.IRR == nil {
		return
	}
	detail := m.IRR
	bgp, _ := summarize(Report{Resource: target, Metrics: []Metric{overview}}, now)
	bgp.Observation = checkObservation(bgp, target.Value, "prefix_overview", now)
	detail.BGP = &IRRComparison{Status: bgp.Status, Observation: bgp.Observation, Origins: slices.Clone(bgp.Origins), ObservedAt: bgp.ObservedAt, ExpiresAt: bgp.ExpiresAt, SourceURL: bgp.SourceURL}
	if detail.BGP.Origins == nil {
		detail.BGP.Origins = []uint32{}
	}
	if bgp.ExpiresAt != nil && (m.ExpiresAt == nil || bgp.ExpiresAt.Before(*m.ExpiresAt)) {
		m.ExpiresAt = bgp.ExpiresAt
	}
	if detail.Completeness != "complete" || m.Status == "stale" {
		detail.Status = "partial"
		return
	}
	if bgp.Freshness != "fresh" || bgp.Observation.Completeness != "complete" {
		detail.Status = "bgp_unavailable"
		return
	}
	if bgp.Status == "not_announced" {
		detail.Status = "bgp_absent"
		return
	}
	if bgp.Status != "announced" {
		detail.Status = "bgp_unavailable"
		return
	}
	matched := map[uint32]bool{}
	conflict := false
	for i := range detail.Objects {
		object := &detail.Objects[i]
		if object.Relation != "exact" {
			continue
		}
		match := slices.Contains(bgp.Origins, object.Origin)
		object.MatchesBGP = &match
		if match {
			matched[object.Origin] = true
		} else {
			conflict = true
		}
	}
	for _, asn := range bgp.Origins {
		if !matched[asn] {
			detail.MissingOrigins = append(detail.MissingOrigins, asn)
		}
	}
	switch {
	case conflict:
		detail.Status = "conflict"
	case len(detail.MissingOrigins) > 0:
		detail.Status = "missing_objects"
	default:
		detail.Status = "consistent"
	}
}

func summarizeIRR(r Report, now time.Time) Check {
	var irr, overview Metric
	for _, m := range r.Metrics {
		if m.Name == "irr" {
			irr = m
		}
		if m.Name == "prefix_overview" {
			overview = m
		}
	}
	irr = decorateIRR(irr, r.Resource, now)
	compareIRR(&irr, overview, r.Resource, now)
	check := metricCheck(irr, now)
	check.IRR = irr.IRR
	if irr.IRR != nil {
		check.Status = irr.IRR.Status
		check.Reason = "IRR objects compared with RIS origins; not ownership or universal routing acceptance"
	}
	if irr.Status == "not_configured" || irr.Status == "not_applicable" || irr.Status == "disabled" {
		check.Status = irr.Status
	}
	return check
}

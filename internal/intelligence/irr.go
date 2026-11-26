package intelligence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const DefaultIRRdURL = "http://subregator-irrd:8000/graphql/"
const irrMetadataURL = "https://github.com/subregator/subregator-backend/blob/main/docs/irr.md"
const irrObjectLimit = 200

var irrRegistryURLs = map[string]string{
	"RIPE":         "https://ftp.ripe.net/ripe/dbase/split/",
	"RIPE-NONAUTH": "https://ftp.ripe.net/ripe/dbase/split/",
	"ARIN":         "https://www.arin.net/resources/manage/irr/",
	"APNIC":        "https://ftp.apnic.net/apnic/whois/",
	"LACNIC":       "https://irr.lacnic.net/",
	"AFRINIC":      "https://afrinic.net/irr-guide",
}

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
	URL           string     `json:"url,omitempty"`
	TimestampKind string     `json:"timestamp_kind,omitempty"`
	Name          string     `json:"name"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
	Freshness     string     `json:"freshness"`
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

// EnableIRR must run before collection starts.
func (s *Service) EnableIRR(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 2048 || strings.TrimSpace(endpoint) != endpoint || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "/graphql/" && u.Path != "/graphql") || strings.HasSuffix(u.Host, ":") {
		return errors.New("invalid IRRd GraphQL endpoint")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return errors.New("invalid IRRd GraphQL endpoint")
		}
	}
	s.irrdURL, s.irrEnabled = u.String(), true
	return nil
}

func (s *Service) irrd(ctx context.Context, query string, variables map[string]any) (json.RawMessage, error) {
	if err := s.checkSourceLimit(ctx, s.irrdURL); err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, sourceBudgetKey{}, s.irrdURL)
	release, err := s.acquireRequest(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	body, _ := json.Marshal(map[string]any{"query": query, "variables": variables})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.irrdURL, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid IRRd request")
	}
	request.Header.Set("Content-Type", "application/json")
	raw, err := s.readRequest(ctx, request, "", 1<<20, true)
	if err != nil {
		if errors.Is(err, ErrNoData) {
			return nil, errors.New("IRRd endpoint unavailable")
		}
		return nil, err
	}
	var envelope struct {
		Data   json.RawMessage   `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Errors) > 0 || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil, errors.New("invalid IRRd GraphQL response")
	}
	return raw, nil
}

func (s *Service) irr(ctx context.Context, target Target) (Metric, error) {
	const query = `query($prefix: IP!, $limit: Int!, $sources: [String!]) {
 rpslObjects(ipAny: $prefix, recordLimit: $limit, sources: $sources, objectClass: ["route", "route6"], rpkiStatus: [valid, invalid, not_found], scopeFilterStatus: [in_scope, out_scope_as, out_scope_prefix], routePreferenceStatus: [visible, suppressed]) {
 objectClass source rpslPk
 ... on RPSLRoute { prefix origin }
 ... on RPSLRoute6 { prefix origin }
 }
 }`
	sources := slices.Sorted(maps.Keys(irrRegistryURLs))
	routes, err := s.irrd(ctx, query, map[string]any{"prefix": target.Value, "limit": irrObjectLimit + 1, "sources": sources})
	if err != nil {
		return Metric{}, err
	}
	metadata, metadataError := s.irrd(ctx, `query($sources: [String!]) { databaseStatus(sources: $sources) { source objectClassFilter rpslDataUpdated } }`, map[string]any{"sources": sources})
	detail, err := normalizeIRR(routes, metadata, target, time.Now())
	if err != nil {
		return Metric{}, err
	}
	if metadataError == nil {
		detail.MetadataObservedAt = observedNow()
	}
	b, _ := json.Marshal(detail)
	m := Metric{IRR: detail, Data: b, ObservedAt: observedNow(), SourceURL: "https://api.subregator.com/api/v1/network?checks=irr&resource=" + url.QueryEscape(target.Value)}
	var limited *sourceLimited
	if errors.As(metadataError, &limited) {
		m.RetryAt = &limited.Until
	}
	return m, nil
}

func normalizeIRR(routes, metadata json.RawMessage, target Target, now time.Time) (*IRRExplanation, error) {
	var response struct {
		Data *struct {
			Objects []struct {
				Class  string `json:"objectClass"`
				Prefix string `json:"prefix"`
				Origin string `json:"origin"`
				Source string `json:"source"`
				ID     string `json:"rpslPk"`
			} `json:"rpslObjects"`
		} `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(routes, &response) != nil || response.Data == nil || response.Data.Objects == nil || len(response.Errors) > 0 {
		return nil, errors.New("invalid IRRd route response")
	}
	requested, err := netip.ParsePrefix(target.Value)
	if err != nil {
		return nil, errors.New("unsupported IRR scope")
	}
	out := &IRRExplanation{Prefix: target.Value, Status: "bgp_unavailable", Completeness: "complete", ObjectLimit: irrObjectLimit, Objects: []IRRObject{}, Registries: []IRRRegistry{}, MissingOrigins: []uint32{}, MetadataURL: irrMetadataURL}
	for i, row := range response.Data.Objects {
		if i >= irrObjectLimit {
			out.Truncated = true
			out.Completeness = "partial"
			break
		}
		p, err := netip.ParsePrefix(row.Prefix)
		asn, asnError := strconv.ParseUint(strings.TrimPrefix(row.Origin, "AS"), 10, 32)
		class := "route"
		if p.Addr().Is6() {
			class = "route6"
		}
		if err != nil || p != p.Masked() || !p.Overlaps(requested) || row.Class != class || irrRegistryURLs[row.Source] == "" || !strings.HasPrefix(row.Origin, "AS") || asnError != nil || asn == 0 {
			out.Completeness = "partial"
			continue
		}
		id := ""
		if row.ID != "" {
			id = p.String() + "AS" + strconv.FormatUint(asn, 10)
			if !strings.EqualFold(row.ID, id) {
				out.Completeness = "partial"
				id = ""
			}
		}
		relation := "exact"
		if p.Bits() < requested.Bits() {
			relation = "covering"
		} else if p.Bits() > requested.Bits() {
			relation = "contained"
		}
		out.Objects = append(out.Objects, IRRObject{Class: class, Prefix: p.String(), Origin: uint32(asn), Registry: row.Source, ID: id, Relation: relation})
	}
	var meta struct {
		Data *struct {
			Registries []struct {
				Name    string   `json:"source"`
				Updated string   `json:"rpslDataUpdated"`
				Classes []string `json:"objectClassFilter"`
			} `json:"databaseStatus"`
		} `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	byName := map[string]IRRRegistry{}
	if json.Unmarshal(metadata, &meta) == nil && meta.Data != nil && meta.Data.Registries != nil && len(meta.Errors) == 0 {
		for _, row := range meta.Data.Registries {
			if irrRegistryURLs[row.Name] == "" {
				out.Completeness = "partial"
				continue
			}
			if _, found := byName[row.Name]; found {
				out.Completeness = "partial"
				continue
			}
			entry := IRRRegistry{Name: row.Name, URL: irrRegistryURLs[row.Name], TimestampKind: "mirror_data_updated", Freshness: "unknown"}
			if updated, err := time.Parse(time.RFC3339Nano, row.Updated); err == nil && !updated.After(now.Add(time.Minute)) {
				entry.UpdatedAt = &updated
				entry.Freshness = "fresh"
				if now.Sub(updated) > 24*time.Hour {
					entry.Freshness = "stale"
				}
			}
			if !slices.Contains(row.Classes, "route") || !slices.Contains(row.Classes, "route6") {
				out.Completeness = "partial"
			}
			byName[row.Name] = entry
		}
	}
	for _, name := range slices.Sorted(maps.Keys(irrRegistryURLs)) {
		entry, found := byName[name]
		if !found {
			entry = IRRRegistry{Name: name, URL: irrRegistryURLs[name], TimestampKind: "mirror_data_updated", Freshness: "unknown"}
		}
		if entry.Freshness == "unknown" {
			out.Completeness = "partial"
		}
		out.Registries = append(out.Registries, entry)
	}
	return out, nil
}

func decorateIRR(m Metric, target Target, now time.Time) Metric {
	m.IRR = nil
	if m.Name != "irr" || m.Source != "IRRd" || m.ObservedAt == nil || m.ObservedAt.After(now.Add(time.Minute)) || m.Status != "ok" && m.Status != "stale" {
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

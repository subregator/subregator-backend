package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

func (s *Service) originTopology(ctx context.Context, target Target, q Query, name string) (Metric, error) {
	if target.Kind == "prefix" && q.overview == nil {
		overview := s.metric(ctx, target, Query{Resource: target.Value}, "prefix_overview")
		q.overview = &overview
	}
	_, asns, err := s.origins(ctx, target, q)
	if err != nil {
		return Metric{}, err
	}
	results := []any{}
	originExpiry := time.Now().UTC().Add(time.Duration(definitions["prefix_overview"].TTLSeconds) * time.Second)
	result := Metric{ObservedAt: observedNow(), ExpiresAt: &originExpiry, SourceURL: "https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes"}
	if name == "asn_relationships" {
		result.SourceURL = "https://catalog.caida.org/dataset/as_rank"
	}
	for _, asn := range asns {
		t := Target{Value: asnTarget(asn), Kind: "asn", ASN: asn}
		m := s.metric(ctx, t, Query{Resource: t.Value}, name)
		if m.Status != "ok" || m.ObservedAt == nil || m.ExpiresAt == nil {
			if m.Status == "rate_limited" {
				return Metric{}, ErrBusy
			}
			if m.Status == "no_data" {
				return Metric{}, ErrNoData
			}
			return Metric{}, errors.New("origin topology unavailable")
		}
		if m.ObservedAt.Before(*result.ObservedAt) {
			result.ObservedAt = m.ObservedAt
		}
		if result.ExpiresAt == nil || m.ExpiresAt.Before(*result.ExpiresAt) {
			result.ExpiresAt = m.ExpiresAt
		}
		results = append(results, map[string]any{"asn": asn, "source_url": m.SourceURL, "data": m.Data})
	}
	if q.overview != nil {
		if q.overview.ExpiresAt != nil && q.overview.ExpiresAt.Before(*result.ExpiresAt) {
			result.ExpiresAt = q.overview.ExpiresAt
		}
		if q.overview.ObservedAt != nil && q.overview.ObservedAt.Before(*result.ObservedAt) {
			result.ObservedAt = q.overview.ObservedAt
		}
	}
	result.Data, _ = json.Marshal(map[string]any{"origins": results, "origin_limit": 4})
	return result, nil
}

type topologyASN struct {
	ASN  string `json:"asn"`
	Name string `json:"asnName"`
	Rank int    `json:"rank"`
}

func (s *Service) relationships(ctx context.Context, target Target) (Metric, error) {
	// shortcut: first 500 links with explicit truncation, paginate when full large-AS graphs are needed.
	query := fmt.Sprintf(`{asn(asn:"%d"){asn asnName rank asnLinks(first:500){totalCount pageInfo{hasNextPage} edges{node{relationship asn0{asn} asn1{asn asnName rank}}}}}}`, target.ASN)
	u := "https://api.asrank.caida.org/v2/graphql?" + url.Values{"query": {query}}.Encode()
	b, err := s.request(ctx, u, "")
	if err != nil {
		return Metric{}, err
	}
	var envelope struct {
		Errors []json.RawMessage `json:"errors"`
		Data   *struct {
			ASN *struct {
				topologyASN
				Links *struct {
					Total    *int `json:"totalCount"`
					PageInfo *struct {
						More bool `json:"hasNextPage"`
					} `json:"pageInfo"`
					Edges []struct {
						Node struct {
							Relationship string      `json:"relationship"`
							From         topologyASN `json:"asn0"`
							To           topologyASN `json:"asn1"`
						} `json:"node"`
					} `json:"edges"`
				} `json:"asnLinks"`
			} `json:"asn"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &envelope) != nil || len(envelope.Errors) != 0 || envelope.Data == nil {
		return Metric{}, errors.New("invalid ASRank response")
	}
	a := envelope.Data.ASN
	if a == nil {
		return Metric{}, ErrNoData
	}
	if originASN(json.RawMessage(a.ASN)) != target.ASN || a.Links == nil {
		return Metric{}, errors.New("invalid ASRank ASN")
	}
	links := a.Links
	if links.Total == nil || *links.Total < len(links.Edges) || links.PageInfo == nil || links.Edges == nil || len(links.Edges) > 500 || links.PageInfo.More != (*links.Total > len(links.Edges)) {
		return Metric{}, errors.New("invalid ASRank link coverage")
	}
	upstreams, downstreams, peers := []topologyASN{}, []topologyASN{}, []topologyASN{}
	seen := map[uint32]bool{}
	for _, edge := range links.Edges {
		n := edge.Node
		asn := originASN(json.RawMessage(n.To.ASN))
		if n.From.ASN != a.ASN || asn == 0 || asn == target.ASN || seen[asn] {
			return Metric{}, errors.New("invalid ASRank link")
		}
		seen[asn] = true
		switch n.Relationship {
		case "provider":
			upstreams = append(upstreams, n.To)
		case "customer":
			downstreams = append(downstreams, n.To)
		case "peer":
			peers = append(peers, n.To)
		default:
			return Metric{}, errors.New("unknown ASRank relationship")
		}
	}
	data, _ := json.Marshal(map[string]any{"asn": target.ASN, "name": a.Name, "rank": a.Rank, "upstreams": upstreams, "downstreams": downstreams, "peers": peers, "total_count": *links.Total, "returned_count": len(links.Edges), "truncated": links.PageInfo.More, "relationship_semantics": "inferred_by_caida", "attribution": "The CAIDA UCSD AS Rank - " + time.Now().UTC().Format("2006-01-02") + ", https://catalog.caida.org/dataset/as_rank"})
	return Metric{Data: data, ObservedAt: observedNow(), SourceURL: u}, nil
}

func (s *Service) announcedPrefixes(ctx context.Context, target Target) (Metric, error) {
	m, err := s.ripe(ctx, "announced-prefixes", url.Values{"resource": {target.Value}})
	if err != nil {
		return Metric{}, err
	}
	var data struct {
		Resource string            `json:"resource"`
		Prefixes []json.RawMessage `json:"prefixes"`
	}
	if json.Unmarshal(m.Data, &data) != nil || originASN(json.RawMessage(data.Resource)) != target.ASN || data.Prefixes == nil {
		return Metric{}, errors.New("invalid announced prefixes response")
	}
	return m, nil
}

package intelligence

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

func (s *Service) asRank(ctx context.Context, target Target, q Query) (Metric, error) {
	asns := []uint32{target.ASN}
	if target.Kind != "asn" {
		_, origins, e := s.origins(ctx, target, q)
		if e != nil {
			return Metric{}, e
		}
		asns = origins
	}
	results := []any{}
	for _, asn := range asns[:min(4, len(asns))] {
		u := "https://api.asrank.caida.org/v2/restful/asns/" + strings.TrimPrefix(asnTarget(asn), "AS")
		b, e := s.request(ctx, u, "")
		if e != nil {
			return Metric{}, e
		}
		var envelope struct {
			Data struct {
				ASN json.RawMessage `json:"asn"`
			} `json:"data"`
		}
		if e = json.Unmarshal(b, &envelope); e != nil || len(envelope.Data.ASN) == 0 || string(envelope.Data.ASN) == "null" {
			return Metric{}, ErrNoData
		}
		results = append(results, map[string]any{"asn": asn, "source_url": u, "data": envelope.Data.ASN})
	}
	b, _ := json.Marshal(map[string]any{"scope": "autonomous_system", "asns": results, "origin_limit": 4, "attribution": "The CAIDA UCSD AS Rank - " + time.Now().UTC().Format("2006-01-02") + ", https://catalog.caida.org/dataset/as_rank"})
	return Metric{Data: b, ObservedAt: observedNow(), SourceURL: "https://catalog.caida.org/dataset/as_rank"}, nil
}

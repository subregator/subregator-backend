package intelligence

import (
	"context"
	"encoding/json"
	"time"
)

// Cached returns observations only; public requests cannot trigger or refresh checks.
func (s *Service) Cached(ctx context.Context, q Query) (Report, error) {
	target, e := q.validate()
	if e != nil {
		return Report{}, e
	}
	report := Report{Resource: target, Metrics: []Metric{}, Semantics: "source_observations_not_ownership_or_reachability_guarantees"}
	for _, name := range q.Checks {
		d := definitions[name]
		m := Metric{Name: name, Status: "pending", Source: d.Source, Coverage: d.Coverage, Data: json.RawMessage("null")}
		key := metricKey(target, q, name)
		if s.cache != nil {
			b, expires, found, err := s.cache.CacheGet(ctx, key)
			var cached Metric
			if err == nil && found && json.Unmarshal(b, &cached) == nil {
				m = cached
				m.Cached = true
				if !time.Now().Before(expires) && m.ObservedAt != nil && (m.Status == "ok" || m.Status == "stale") {
					m.Status = "stale"
				}
			}
		}
		report.Metrics = append(report.Metrics, m)
		if m.Status != "ok" {
			report.Partial = true
		}
	}
	return report, nil
}
func metricKey(target Target, q Query, name string) string {
	b, _ := json.Marshal(struct {
		Resource string
		Name     string
		Start    string
		End      string
		Version  string
		ASN      uint32
	}{target.Value, name, q.StartTime, q.EndTime, q.Version, q.ASN})
	return string(b)
}

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
		m := s.initialMetric(target, name, q)
		key := metricKey(target, q, name)
		if s.cache != nil && m.Status == "pending" {
			b, expires, found, err := s.cache.CacheGet(ctx, key)
			if err != nil {
				s.persistenceFailed()
			}
			var cached Metric
			if err == nil && found && json.Unmarshal(b, &cached) == nil {
				m = cached
				m.Cached = true
				if !time.Now().Before(expires) && m.ObservedAt != nil && (m.Status == "ok" || m.Status == "stale") {
					m.Status = "stale"
				}
			}
		}
		if m.Status == "pending" && !s.network {
			m.Status = "disabled"
		}
		m = decorateRegistration(m, target)
		m = decorateRouting(m, target, q.ASN)
		m = decorateIRR(m, target, time.Now())
		m = decorateAbuse(m, target, time.Now())
		if m.IRR != nil {
			dependency, _ := s.Cached(ctx, Query{Resource: target.Value, Checks: []string{"prefix_overview"}})
			compareIRR(&m, dependency.Metrics[0], target, time.Now())
		}
		if m.RPKI != nil && m.RPKI.Basis == "observed_origins" && target.Kind == "prefix" {
			dependency, _ := s.Cached(ctx, Query{Resource: target.Value, Checks: []string{"prefix_overview"}})
			overview := dependency.Metrics[0]
			reconcileRPKI(&m, overview)
		}
		m.Observation = metricObservation(m, target, q, time.Now())
		report.Metrics = append(report.Metrics, m)
		if metricPartial(m) {
			report.Partial = true
		}
	}
	attachRoutingContext(&report)
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

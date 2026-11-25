package intelligence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

type ArchivedObservation struct {
	ID              int64           `json:"id"`
	Identity        string          `json:"identity"`
	Resource        string          `json:"resource"`
	Check           string          `json:"check"`
	Source          string          `json:"source"`
	SourceURL       string          `json:"source_url,omitempty"`
	ObservedAt      *time.Time      `json:"observed_at"`
	SourceUpdatedAt *time.Time      `json:"source_updated_at"`
	AttemptedAt     time.Time       `json:"attempted_at"`
	IngestedAt      time.Time       `json:"ingested_at"`
	ExpiresAt       *time.Time      `json:"expires_at"`
	Observation     Observation     `json:"observation"`
	Evidence        json.RawMessage `json:"evidence"`
	State           json.RawMessage `json:"-"`
	Event           string          `json:"event"`
	FirstSeen       *time.Time      `json:"first_seen"`
	LastSeen        *time.Time      `json:"last_seen"`
	PreviousSeen    *time.Time      `json:"previous_seen"`
	Gap             bool            `json:"gap"`
	Comparable      bool            `json:"-"`
}

type ObservationArchive interface {
	SaveObservation(context.Context, ArchivedObservation) error
}

func (s *Service) archiveMetric(ctx context.Context, target Target, q Query, m Metric) {
	if target.Kind != "prefix" || !slices.Contains(s.historyChecks, m.Name) || m.Cached || q.ASN != 0 || q.StartTime != "" || q.EndTime != "" || q.Version != "" {
		return
	}
	if m.Name != "prefix_overview" && m.Name != "rpki" && m.Name != "registration" && m.Name != "rdap" {
		return
	}
	m = decorateRegistration(m, target)
	m = decorateRouting(m, target, 0)
	o := metricObservation(m, target, q, time.Now())
	r := ArchivedObservation{Resource: target.Value, Check: m.Name, Source: m.Source, SourceURL: m.SourceURL, ObservedAt: m.ObservedAt, SourceUpdatedAt: m.SourceUpdatedAt, ExpiresAt: m.ExpiresAt, Observation: o, AttemptedAt: time.Now().UTC(), IngestedAt: time.Now().UTC()}
	var evidence any
	var state any
	switch {
	case m.BGP != nil:
		evidence = m.BGP
		origins := slices.Clone(m.BGP.Origins)
		slices.Sort(origins)
		state = struct {
			Origins []uint32 `json:"origins"`
		}{slices.Compact(origins)}
	case m.RPKI != nil:
		evidence = m.RPKI
		states := map[uint32]string{}
		for _, origin := range m.RPKI.Origins {
			states[origin.ASN] = origin.Status
		}
		state = states
	case m.Registration != nil:
		evidence = m.Registration
		records := slices.Clone(m.Registration.Records)
		for i := range records {
			r := &records[i]
			r.Statuses = orderedRegistryValues(r.Statuses)
			r.Entities = slices.Clone(r.Entities)
			for j := range r.Entities {
				r.Entities[j].Statuses = orderedRegistryValues(r.Entities[j].Statuses)
			}
			r.Entities = orderedRegistryValues(r.Entities)
			r.Events = orderedRegistryValues(r.Events)
		}
		state = orderedRegistryValues(records)
	}
	if m.BGP != nil && m.BGP.QueryTime != nil {
		r.SourceUpdatedAt = m.BGP.QueryTime
	}
	r.Evidence, _ = json.Marshal(evidence)
	r.State, _ = json.Marshal(state)
	r.Comparable = state != nil && o.CollectionStatus == "succeeded" && o.Completeness == "complete" && o.Freshness == "fresh" && o.Scope.Relation != "unknown" && o.Scope.Resource != ""
	s.saveObservation(ctx, r)
}

func (s *Service) archiveDROP(ctx context.Context, resource string, c Check) {
	if !slices.Contains(s.historyChecks, "spamhaus_drop") {
		return
	}
	o := checkObservation(c, resource, "spamhaus_drop", time.Now())
	r := ArchivedObservation{Resource: resource, Check: "spamhaus_drop", Source: c.Source, SourceURL: c.SourceURL, ObservedAt: c.ObservedAt, SourceUpdatedAt: c.SourceUpdatedAt, ExpiresAt: c.ExpiresAt, Observation: o, AttemptedAt: time.Now().UTC(), IngestedAt: time.Now().UTC()}
	r.Evidence, _ = json.Marshal(c)
	r.State, _ = json.Marshal(c.Status)
	r.Comparable = o.CollectionStatus == "succeeded" && o.Completeness == "complete" && o.Freshness == "fresh" && (c.Status == "listed" || c.Status == "not_listed")
	s.saveObservation(ctx, r)
}

func (s *Service) saveObservation(ctx context.Context, r ArchivedObservation) {
	if archive, ok := s.cache.(ObservationArchive); ok {
		persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if archive.SaveObservation(persistCtx, r) != nil {
			s.persistenceFailed()
		}
	}
}

// SetHistoryChecks runs before collection and serving start.
func (s *Service) SetHistoryChecks(raw string) error {
	checks := []string{}
	if raw != "" {
		for _, check := range strings.Split(raw, ",") {
			if !slices.Contains([]string{"prefix_overview", "rpki", "registration", "rdap", "spamhaus_drop"}, check) || slices.Contains(checks, check) {
				return errors.New("invalid or unapproved history check")
			}
			checks = append(checks, check)
		}
	}
	s.historyChecks = checks
	return nil
}
func (s *Service) HistoryChecks() []string { return slices.Clone(s.historyChecks) }

func orderedRegistryValues[T any](values []T) []T {
	values = slices.Clone(values)
	compare := func(a, b T) int {
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return bytes.Compare(left, right)
	}
	slices.SortFunc(values, compare)
	return slices.CompactFunc(values, func(a, b T) bool { return compare(a, b) == 0 })
}

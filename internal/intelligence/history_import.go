package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"
)

var historicalChecks = []string{"routing_history", "allocation_history", "transfer_history", "registration_history"}

type HistoricalRecord struct {
	Resource          string `json:"resource,omitempty"`
	Relation          string `json:"relation"`
	Origin            uint32 `json:"origin,omitempty"`
	Version           int    `json:"version,omitempty"`
	Start             string `json:"start,omitempty"`
	End               string `json:"end,omitempty"`
	Status            string `json:"status,omitempty"`
	SourceRegistry    string `json:"source_registry,omitempty"`
	RecipientRegistry string `json:"recipient_registry,omitempty"`
}

type HistoricalSnapshot struct {
	Requested         string             `json:"requested"`
	WindowStart       string             `json:"window_start,omitempty"`
	WindowEnd         string             `json:"window_end,omitempty"`
	SourceWindowStart string             `json:"source_window_start,omitempty"`
	SourceWindowEnd   string             `json:"source_window_end,omitempty"`
	Records           []HistoricalRecord `json:"records"`
	Truncated         bool               `json:"truncated"`
	RecordLimit       int                `json:"record_limit"`
	Completeness      string             `json:"completeness"`
	DroppedRecords    int                `json:"dropped_records"`
	Coverage          string             `json:"coverage"`
}

func (s *Service) SetHistoricalChecks(raw string) error {
	checks := []string{}
	if raw != "" {
		for _, name := range strings.Split(raw, ",") {
			if !slices.Contains(historicalChecks, name) || slices.Contains(checks, name) {
				return errors.New("invalid historical collection check")
			}
			checks = append(checks, name)
		}
	}
	s.historicalChecks = checks
	return nil
}

func historicalQuery(resource string, now time.Time) Query {
	end := now.UTC().Truncate(24 * time.Hour)
	return Query{Resource: resource, StartTime: end.Add(-7 * 24 * time.Hour).Format(time.RFC3339), EndTime: end.Format(time.RFC3339)}
}

func historyDate(raw string) string {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC().Format(time.RFC3339Nano)
		}
	}
	return ""
}
func historyRelation(requested, resource string) string {
	a, e := netip.ParsePrefix(requested)
	b, f := netip.ParsePrefix(resource)
	if e != nil || f != nil || a.Addr().BitLen() != b.Addr().BitLen() {
		return "unknown"
	}
	if a == b {
		return "exact"
	}
	if b.Bits() < a.Bits() && b.Contains(a.Addr()) {
		return "covering"
	}
	if a.Bits() < b.Bits() && a.Contains(b.Addr()) {
		return "contained"
	}
	return "unknown"
}

func normalizeHistorical(name string, raw json.RawMessage, target Target, q Query) (HistoricalSnapshot, error) {
	out := HistoricalSnapshot{Requested: target.Value, WindowStart: q.StartTime, WindowEnd: q.EndTime, Records: []HistoricalRecord{}, RecordLimit: 300, Completeness: "partial", Coverage: definitions[name].Coverage}
	var data struct {
		Parameters struct {
			Earliest string `json:"earliest_time"`
			Latest   string `json:"latest_time"`
		} `json:"parameters"`
		QueryStart string `json:"query_starttime"`
		QueryEnd   string `json:"query_endtime"`
		ByOrigin   []struct {
			Origin   json.RawMessage `json:"origin"`
			Prefixes []struct {
				Prefix    string `json:"prefix"`
				Timelines []struct {
					Start string `json:"starttime"`
					End   string `json:"endtime"`
				} `json:"timelines"`
			} `json:"prefixes"`
		} `json:"by_origin"`
		Results   json.RawMessage `json:"results"`
		Transfers []struct {
			Recipient         string `json:"recipientResource"`
			Time              string `json:"transferTime"`
			SourceRegistry    string `json:"sourceRegistry"`
			RecipientRegistry string `json:"recipientRegistry"`
		} `json:"transfers"`
		Resource    string `json:"resource"`
		Database    string `json:"database"`
		NumVersions int    `json:"num_versions"`
		Versions    []struct {
			Version   int    `json:"version"`
			ID        int    `json:"id"`
			Date      string `json:"date"`
			Timestamp string `json:"timestamp"`
		} `json:"versions"`
	}
	if json.Unmarshal(raw, &data) != nil {
		return out, errors.New("invalid historical snapshot")
	}
	out.SourceWindowStart = historyDate(data.QueryStart)
	out.SourceWindowEnd = historyDate(data.QueryEnd)
	if name == "transfer_history" {
		out.SourceWindowStart = historyDate(data.Parameters.Earliest)
		out.SourceWindowEnd = historyDate(data.Parameters.Latest)
	}
	add := func(r HistoricalRecord) {
		if r.Resource == "" {
			out.DroppedRecords++
			return
		}
		if r.Start != "" && r.End != "" {
			start, _ := time.Parse(time.RFC3339Nano, r.Start)
			end, _ := time.Parse(time.RFC3339Nano, r.End)
			if end.Before(start) {
				out.DroppedRecords++
				return
			}
		}
		if len(out.Records) >= out.RecordLimit {
			out.Truncated = true
			return
		}
		if r.Resource != "" {
			p, err := netip.ParsePrefix(r.Resource)
			if err != nil {
				return
			}
			r.Resource = p.Masked().String()
			r.Relation = historyRelation(target.Value, r.Resource)
			if r.Relation == "unknown" {
				return
			}
		}
		out.Records = append(out.Records, r)
	}
	switch name {
	case "routing_history":
		if data.ByOrigin == nil {
			return out, errors.New("missing routing history")
		}
		for _, origin := range data.ByOrigin {
			asn := originASN(origin.Origin)
			if asn == 0 {
				continue
			}
			for _, prefix := range origin.Prefixes {
				for _, period := range prefix.Timelines {
					start, end := historyDate(period.Start), historyDate(period.End)
					if start == "" || end == "" {
						continue
					}
					add(HistoricalRecord{Resource: prefix.Prefix, Origin: asn, Start: start, End: end})
				}
			}
		}
	case "allocation_history":
		type allocation struct {
			Resource  string `json:"resource"`
			Status    string `json:"status"`
			Timelines []struct {
				Start string `json:"starttime"`
				End   string `json:"endtime"`
			} `json:"timelines"`
		}
		var records []allocation
		if json.Unmarshal(data.Results, &records) != nil {
			var groups map[string][]allocation
			if json.Unmarshal(data.Results, &groups) != nil {
				return out, errors.New("invalid allocation history")
			}
			keys := make([]string, 0, len(groups))
			for k := range groups {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				records = append(records, groups[k]...)
			}
		}
		if records == nil {
			return out, errors.New("missing allocation history")
		}
		for _, r := range records {
			for _, period := range r.Timelines {
				start, end := historyDate(period.Start), historyDate(period.End)
				if start == "" || end == "" {
					continue
				}
				status := ""
				if slices.Contains([]string{"allocated", "assigned", "reserved", "available", "legacy"}, r.Status) {
					status = r.Status
				}
				add(HistoricalRecord{Resource: r.Resource, Status: status, Start: start, End: end})
			}
		}
	case "transfer_history":
		if data.Transfers == nil {
			return out, errors.New("missing transfer history")
		}
		registry := func(raw string) string {
			if slices.Contains([]string{"RIPE", "RIPE NCC", "ARIN", "APNIC", "LACNIC", "AFRINIC", "IANA"}, raw) {
				return raw
			}
			return ""
		}
		for _, r := range data.Transfers {
			at := historyDate(r.Time)
			if at == "" {
				continue
			}
			add(HistoricalRecord{Resource: r.Recipient, Start: at, SourceRegistry: registry(r.SourceRegistry), RecipientRegistry: registry(r.RecipientRegistry)})
		}
	case "registration_history":
		if data.Database != "RIPE" || data.Versions == nil {
			return out, errors.New("RIPE version metadata unavailable")
		}
		if data.NumVersions > len(data.Versions) {
			out.Truncated = true
		}
		for _, r := range data.Versions {
			version := max(r.Version, r.ID)
			at := historyDate(r.Date)
			if at == "" {
				at = historyDate(r.Timestamp)
			}
			if version <= 0 || at == "" {
				continue
			}
			add(HistoricalRecord{Resource: data.Resource, Version: version, Start: at})
		}
	default:
		return out, errors.New("unsupported historical check")
	}
	slices.SortFunc(out.Records, func(a, b HistoricalRecord) int {
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return strings.Compare(string(left), string(right))
	})
	out.Records = slices.Compact(out.Records)
	return out, nil
}

func (s *Service) archiveHistorical(ctx context.Context, target Target, q Query, m Metric) {
	if !slices.Contains(s.historicalChecks, m.Name) || m.Cached || ctx.Value(automaticBudgetKey{}) != true {
		return
	}
	o := metricObservation(m, target, q, time.Now())
	o.Completeness = "unknown"
	o.Scope.Relation = "source_records"
	o.Scope.Resource = ""
	if m.Name == "transfer_history" || m.Name == "registration_history" {
		q.StartTime = ""
		q.EndTime = ""
		o.Scope.StartTime = ""
		o.Scope.EndTime = ""
	}
	r := ArchivedObservation{Resource: target.Value, Check: m.Name, Source: m.Source, SourceURL: m.SourceURL, ObservedAt: m.ObservedAt, SourceUpdatedAt: m.SourceUpdatedAt, AttemptedAt: time.Now().UTC(), IngestedAt: time.Now().UTC(), ExpiresAt: m.ExpiresAt, Observation: o, Evidence: json.RawMessage("null"), State: json.RawMessage("null"), Origin: "imported_history"}
	if m.Status == "ok" {
		snapshot, err := normalizeHistorical(m.Name, m.Data, target, q)
		if err != nil {
			r.Observation.CollectionStatus = "failed"
			r.Observation.FailureReason = "Historical payload could not be normalized"
		} else {
			r.Evidence, _ = json.Marshal(snapshot)
			for len(r.Evidence) > 60<<10 && len(snapshot.Records) > 0 {
				snapshot.Truncated = true
				snapshot.Records = snapshot.Records[:len(snapshot.Records)-1]
				r.Evidence, _ = json.Marshal(snapshot)
			}
			r.Observation.Completeness = snapshot.Completeness
		}
	}
	s.saveObservation(ctx, r)
}

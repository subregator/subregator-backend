package api

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/subregator/subregator-backend/internal/history"
	"github.com/subregator/subregator-backend/internal/intelligence"
)

const reportSectionBytes = 512 << 10

type ReportSection[T any] struct {
	Status    string   `json:"status"`
	Data      *T       `json:"data"`
	Gaps      []string `json:"gaps"`
	Truncated bool     `json:"truncated"`
	URL       string   `json:"url"`
	Next      string   `json:"next,omitempty"`
}

type ReportNetwork struct {
	Current intelligence.Report `json:"current"`
	Drop    *intelligence.Check `json:"drop"`
}

type SubnetReport struct {
	Resource       string                                `json:"resource"`
	GeneratedAt    time.Time                             `json:"generated_at"`
	Market         ReportSection[MarketCurrent]          `json:"market"`
	Network        ReportSection[ReportNetwork]          `json:"network"`
	Timeline       ReportSection[history.TimelineResult] `json:"timeline"`
	NetworkHistory string                                `json:"network_history"`
	MaxBytes       int                                   `json:"max_bytes"`
	Semantics      string                                `json:"semantics"`
}

func (s *service) subnetReport(ctx context.Context, v url.Values) (SubnetReport, error) {
	out := SubnetReport{GeneratedAt: time.Now().UTC(), MaxBytes: 2 << 20, Semantics: "local_cached_reads_only; generated_at_is_not_source_freshness; exact_prefix_provider_offers_not_ownership_or_completed_sales; no_aggregate_safety_score"}
	if err := parseFilters(v, "resource limit offset snapshot cursor"); err != nil {
		return out, err
	}
	target, err := intelligence.ParseTarget(v.Get("resource"))
	if err != nil || target.Kind != "prefix" {
		return out, badQuery("A public CIDR resource is required")
	}
	limit := 20
	if raw := v.Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 50 {
			return out, badQuery("report limit must be between 1 and 50")
		}
	}
	marketQuery := url.Values{"resource": {target.Value}, "limit": {strconv.Itoa(limit)}}
	for _, key := range []string{"offset", "snapshot"} {
		if raw := v.Get(key); raw != "" {
			marketQuery.Set(key, raw)
		}
	}
	market, err := s.marketData(ctx, marketQuery, false)
	if err != nil {
		return out, err
	}
	if market.Current.Total == 0 {
		providers, err := s.allowed("", true)
		if err != nil {
			return out, err
		}
		known := false
		if s.extras.History != nil {
			known, err = s.extras.History.PublicObservationResource(ctx, target.Value, providers)
			if err != nil {
				return out, &apiError{503, "resource_unavailable", "Could not establish a permitted public resource"}
			}
		}
		if !known {
			return out, &apiError{404, "not_found", "Public resource not found"}
		}
	}
	out.Resource = target.Value
	out.Market = ReportSection[MarketCurrent]{Status: "available", Data: &market.Current, Gaps: []string{"published_offers_only; unlisted_sellers_and_unreported_fees_unknown"}, URL: "/api/v1/market?" + marketQuery.Encode()}
	if market.Current.Total == 0 {
		out.Market.Status = "empty"
		out.Market.Gaps = append(out.Market.Gaps, "no_current_published_offers")
	}
	if market.Current.NextOffset != nil {
		next := url.Values{"resource": {target.Value}, "limit": {strconv.Itoa(limit)}}
		next.Set("offset", strconv.Itoa(*market.Current.NextOffset))
		next.Set("snapshot", market.Current.Snapshot)
		out.Market.Truncated = true
		out.Market.Next = "/api/v1/report?" + next.Encode()
	}

	checks := []string{"prefix_overview", "routing_status", "rpki", "registration", "rdap", "irr", "abuse", "spamhaus_zen", "asn_relationships", "announced_prefixes"}
	networkQuery := url.Values{"resource": {target.Value}, "checks": {strings.Join(checks, ",")}}
	out.Network = ReportSection[ReportNetwork]{Status: "disabled", Gaps: []string{"checks_disabled"}, URL: "/api/v1/network?" + networkQuery.Encode()}
	if s.extras.Intelligence != nil {
		current, err := s.inspect(ctx, intelligence.Query{Resource: target.Value, Checks: checks})
		out.Network.Gaps = []string{}
		if err != nil {
			out.Network.Status = "error"
			out.Network.Gaps = append(out.Network.Gaps, "cached_checks_failed")
		} else {
			data := ReportNetwork{Current: current}
			out.Network.Status = "available"
			for _, metric := range current.Metrics {
				if metric.Status != "ok" || metric.Observation.Freshness != "fresh" || metric.Observation.Completeness != "complete" {
					out.Network.Status = "partial"
					out.Network.Gaps = append(out.Network.Gaps, metric.Name+":"+metric.Status+":"+metric.Observation.Freshness+":"+metric.Observation.Completeness)
				}
			}
			if s.extras.Automatic != nil {
				drop := s.extras.Automatic.Get(target.Value).Blocklist
				data.Drop = &drop
				if drop.Freshness != "fresh" || drop.Observation.Completeness != "complete" {
					out.Network.Status = "partial"
					out.Network.Gaps = append(out.Network.Gaps, "spamhaus_drop:"+drop.Status+":"+drop.Freshness)
				}
			} else {
				out.Network.Status = "partial"
				out.Network.Gaps = append(out.Network.Gaps, "spamhaus_drop:collector_disabled")
			}
			out.Network.Data = &data
		}
	}

	out.NetworkHistory = "disabled"
	if s.extras.Intelligence != nil && len(s.extras.Intelligence.HistoryChecks()) > 0 {
		out.NetworkHistory = "enabled"
	}
	timelineQuery := url.Values{"resource": {target.Value}, "limit": {strconv.Itoa(limit)}}
	if raw := v.Get("cursor"); raw != "" {
		timelineQuery.Set("cursor", raw)
	}
	out.Timeline = ReportSection[history.TimelineResult]{Status: "available", Gaps: []string{}, URL: "/api/v1/timeline?" + timelineQuery.Encode()}
	if out.NetworkHistory == "disabled" {
		out.Timeline.Gaps = append(out.Timeline.Gaps, "network_history_disabled")
	}
	timeline, err := s.timeline(ctx, timelineQuery)
	if err != nil {
		if typed, ok := err.(*apiError); ok && typed.status == 400 {
			return SubnetReport{}, err
		}
		out.Timeline.Status = "error"
		out.Timeline.Gaps = append(out.Timeline.Gaps, "history_failed")
		if s.extras.History == nil {
			out.Timeline.Status = "disabled"
			out.Timeline.Gaps = []string{"history_disabled"}
		}
	} else {
		out.Timeline.Data = &timeline
		if len(timeline.Items) == 0 {
			out.Timeline.Status = "empty"
			out.Timeline.Gaps = append(out.Timeline.Gaps, "no_permitted_events")
		}
		for _, check := range timeline.Unavailable {
			out.Timeline.Gaps = append(out.Timeline.Gaps, check+":history_unavailable")
		}
		if out.NetworkHistory == "enabled" && timeline.ArchiveStartedAt == nil {
			out.Timeline.Gaps = append(out.Timeline.Gaps, "no_archived_network_observations")
		}
		if timeline.NextCursor != "" {
			timelineQuery.Set("cursor", timeline.NextCursor)
			out.Timeline.Truncated = true
			out.Timeline.Next = "/api/v1/timeline?" + timelineQuery.Encode()
		}
	}
	boundReportSection(&out.Market)
	boundReportSection(&out.Network)
	boundReportSection(&out.Timeline)
	return out, nil
}

func boundReportSection[T any](section *ReportSection[T]) {
	encoded, err := json.Marshal(section)
	if err != nil || len(encoded) > reportSectionBytes {
		section.Data = nil
		section.Status = "partial"
		section.Truncated = true
		section.Gaps = append(section.Gaps, "section_exceeds_report_byte_limit; read_section_url")
		section.Next = section.URL
	}
}

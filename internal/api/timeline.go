package api

import (
	"context"
	"net/url"

	"github.com/subregator/subregator-backend/internal/history"
	"github.com/subregator/subregator-backend/internal/intelligence"
)

func (s *service) timeline(ctx context.Context, v url.Values) (history.TimelineResult, error) {
	empty := history.TimelineResult{Items: []history.TimelineEntry{}}
	if err := parseFilters(v, "resource cursor limit"); err != nil {
		return empty, err
	}
	target, err := intelligence.ParseTarget(v.Get("resource"))
	if err != nil || target.Kind != "prefix" {
		return empty, badQuery("A public CIDR resource is required")
	}
	limit, err := pageLimit(v.Get("limit"))
	if err != nil {
		return empty, err
	}
	if s.extras.History == nil {
		return empty, &apiError{503, "history_disabled", "History storage is not configured"}
	}
	providers, err := s.allowed("", true)
	if err != nil {
		return empty, err
	}
	checks := []string{}
	if s.extras.Intelligence != nil {
		checks = s.extras.Intelligence.HistoryChecks()
	}
	result, err := s.extras.History.Timeline(ctx, target.Value, v.Get("cursor"), limit, providers, checks)
	if err != nil {
		if err.Error() == "invalid timeline cursor" {
			return empty, badQuery("Invalid timeline cursor")
		}
		return empty, &apiError{500, "history_failed", "Could not query resource timeline"}
	}
	for i := range result.Items {
		if e := result.Items[i].Listing; e != nil {
			e.Before = s.redact(e.Before)
			e.After = s.redact(e.After)
		}
	}
	return result, nil
}

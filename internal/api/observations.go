package api

import (
	"context"
	"net/url"
	"strconv"

	"github.com/subregator/subregator-backend/internal/history"
	"github.com/subregator/subregator-backend/internal/intelligence"
)

func (s *service) observations(ctx context.Context, v url.Values) (history.ObservationResult, error) {
	empty := history.ObservationResult{Items: []intelligence.ArchivedObservation{}}
	if err := parseFilters(v, "resource after_id limit"); err != nil {
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
	var after int64
	if raw := v.Get("after_id"); raw != "" {
		after, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || after < 0 {
			return empty, badQuery("Invalid observation cursor")
		}
	}
	if s.extras.History == nil {
		return empty, &apiError{503, "history_disabled", "History storage is not configured"}
	}
	if s.extras.Intelligence == nil || len(s.extras.Intelligence.HistoryChecks()) == 0 {
		return empty, nil
	}
	providers, err := s.allowed("", true)
	if err != nil {
		return empty, err
	}
	allowed, err := s.extras.History.PublicObservationResource(ctx, target.Value, providers)
	if err != nil {
		return empty, &apiError{500, "history_failed", "Could not query public resources"}
	}
	if !allowed {
		return empty, nil
	}
	result, err := s.extras.History.Observations(ctx, target.Value, after, limit, s.extras.Intelligence.HistoryChecks()...)
	if err != nil {
		return empty, &apiError{500, "history_failed", "Could not query observations"}
	}
	return result, nil
}

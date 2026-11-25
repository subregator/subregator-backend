package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/history"
	"github.com/subregator/subregator-backend/internal/intelligence"
)

type Services struct {
	Automatic    *intelligence.Automatic
	Limits       *RequestLimits
	History      *history.DB
	Intelligence *intelligence.Service
}
type service struct {
	store  *catalog.Store
	extras Services
}
type apiError struct {
	status       int
	code, detail string
}

func (e *apiError) Error() string  { return e.detail }
func badQuery(detail string) error { return &apiError{400, "invalid_query", detail} }
func (s *service) offers(filters url.Values) (Result, error) {
	q, e := ParseQuery(filters)
	if e != nil {
		return Result{}, badQuery(e.Error())
	}
	v := s.store.View()
	for id := range q.Provider {
		if _, ok := s.store.Provider(id); !ok {
			return Result{}, badQuery("Unknown provider")
		}
	}
	if q.Snapshot != "" && q.Snapshot != v.Generation {
		return Result{}, &apiError{409, "snapshot_changed", "Restart pagination using the current snapshot"}
	}
	result := Search(v, q, time.Now())
	for i := range result.Items {
		s.attachChecks(&result.Items[i])
	}
	return result, nil
}
func (s *service) offer(id string) (Item, error) {
	v := s.store.View()
	i, ok := v.ByID[id]
	if !ok {
		return Item{}, &apiError{404, "not_found", "Offer not found"}
	}
	o := v.Offers[i]
	ids := []string{}
	for _, q := range o.Quotes {
		ids = append(ids, q.ID)
	}
	item := Item{Offer: o, Freshness: v.OfferFreshness(o, time.Now()), MatchingQuoteIDs: ids}
	s.attachChecks(&item)
	return item, nil
}

type ProviderView struct {
	catalog.Provider
	Freshness string          `json:"freshness"`
	Source    *catalog.Source `json:"source"`
}
type ProvidersResult struct {
	Items    []ProviderView `json:"items"`
	Snapshot string         `json:"snapshot"`
}

func (s *service) providers() ProvidersResult {
	v := s.store.View()
	out := ProvidersResult{Items: []ProviderView{}, Snapshot: v.Generation}
	for _, p := range v.Providers {
		item := ProviderView{Provider: p, Freshness: v.Freshness(p.ID, time.Now())}
		for _, source := range v.Sources {
			if source.ProviderID == p.ID {
				x := source
				item.Source = &x
			}
		}
		out.Items = append(out.Items, item)
	}
	return out
}
func (s *service) allowed(provider string, fullOnly bool) ([]string, error) {
	if provider != "" {
		if _, ok := s.store.Provider(provider); !ok {
			return nil, badQuery("Unknown provider")
		}
	}
	out := []string{}
	for _, p := range s.store.View().Providers {
		if provider != "" && p.ID != provider {
			continue
		}
		if p.Policy.Publication == "pending" || fullOnly && p.Policy.PrefixVisibility != "full" {
			continue
		}
		out = append(out, p.ID)
	}
	return out, nil
}
func (s *service) redact(o *catalog.Offer) *catalog.Offer {
	if o == nil {
		return nil
	}
	p, ok := s.store.Provider(o.ProviderID)
	if !ok || p.Policy.Publication == "pending" {
		return nil
	}
	if p.Policy.PrefixVisibility == "full" {
		return o
	}
	id := o.ID
	n, e := catalog.Normalize(*o, p, time.Now())
	if e != nil {
		return nil
	}
	n.ID = id
	if o.Resource.Prefix == nil && strings.HasPrefix(o.ExternalID, p.ID+"_") && catalog.ValidToken(o.ExternalID) {
		n.ExternalID = o.ExternalID
	}
	return &n
}
func validHistoryResource(raw string) bool {
	if raw == "" {
		return true
	}
	if len(raw) > 100 {
		return false
	}
	if p, e := netip.ParsePrefix(raw); e == nil {
		return !p.Addr().Is4In6()
	}
	if ip, e := netip.ParseAddr(raw); e == nil {
		return ip.Zone() == ""
	}
	return false
}
func parseFilters(v url.Values, allowed string) error {
	keys := map[string]bool{}
	for _, k := range strings.Fields(allowed) {
		keys[k] = true
	}
	for k, x := range v {
		if !keys[k] || len(x) != 1 || len(x[0]) > 1000 {
			return badQuery("Unknown, repeated or oversized parameter")
		}
	}
	return nil
}
func pageLimit(raw string) (int, error) {
	if raw == "" {
		return 50, nil
	}
	n, e := strconv.Atoi(raw)
	if e != nil || n < 1 || n > 200 {
		return 0, badQuery("limit must be between 1 and 200")
	}
	return n, nil
}
func (s *service) events(ctx context.Context, v url.Values) (history.EventResult, error) {
	if s.extras.History == nil {
		return history.EventResult{}, &apiError{503, "history_disabled", "History storage is not configured"}
	}
	if e := parseFilters(v, "provider listing_id resource resource_id type since until after_id limit"); e != nil {
		return history.EventResult{}, e
	}
	q := history.Query{ListingID: v.Get("listing_id"), Resource: v.Get("resource"), ResourceID: v.Get("resource_id"), Type: v.Get("type")}
	if !validHistoryResource(q.Resource) || q.ListingID != "" && !catalog.ValidToken(q.ListingID) || q.ResourceID != "" && !catalog.ValidToken(q.ResourceID) {
		return history.EventResult{}, badQuery("Invalid resource or listing identifier")
	}
	if q.Type != "" && !oneOf(q.Type, "baseline", "listed", "changed", "removed", "relisted", "resource_changed") {
		return history.EventResult{}, badQuery("Invalid event type")
	}
	var e error
	q.Limit, e = pageLimit(v.Get("limit"))
	if e != nil {
		return history.EventResult{}, e
	}
	if value := v.Get("after_id"); value != "" {
		q.AfterID, e = strconv.ParseInt(value, 10, 64)
		if e != nil || q.AfterID < 0 {
			return history.EventResult{}, badQuery("Invalid event cursor")
		}
	}
	for key, field := range map[string]**time.Time{"since": &q.Since, "until": &q.Until} {
		if value := v.Get(key); value != "" {
			t, e := time.Parse(time.RFC3339, value)
			if e != nil {
				return history.EventResult{}, badQuery("Invalid event timestamp")
			}
			*field = &t
		}
	}
	if q.Since != nil && q.Until != nil && q.Until.Before(*q.Since) {
		return history.EventResult{}, badQuery("Invalid event time range")
	}
	q.Providers, e = s.allowed(v.Get("provider"), q.Resource != "" || strings.HasPrefix(q.ResourceID, "net_"))
	if e != nil {
		return history.EventResult{}, e
	}
	result, e := s.extras.History.Events(ctx, q)
	if e != nil {
		return result, &apiError{500, "history_failed", "Could not query listing history"}
	}
	for i := range result.Items {
		event := &result.Items[i]
		event.Before = s.redact(event.Before)
		event.After = s.redact(event.After)
		p, _ := s.store.Provider(event.ProviderID)
		if p.Policy.PrefixVisibility != "full" {
			event.ResourceID = catalog.StableID("masked", event.ListingID)
			event.NextResourceID = event.ResourceID
		}
	}
	return result, nil
}
func (s *service) listing(ctx context.Context, id string) (history.Listing, error) {
	if s.extras.History == nil {
		return history.Listing{}, &apiError{503, "history_disabled", "History storage is not configured"}
	}
	if !catalog.ValidToken(id) {
		return history.Listing{}, badQuery("Invalid listing identifier")
	}
	result, e := s.extras.History.Listing(ctx, id)
	if errors.Is(e, sql.ErrNoRows) {
		return result, &apiError{404, "not_found", "Listing not found"}
	}
	if e != nil {
		return result, &apiError{500, "history_failed", "Could not query listing"}
	}
	p, ok := s.store.Provider(result.ProviderID)
	if !ok || p.Policy.Publication == "pending" {
		return history.Listing{}, &apiError{404, "not_found", "Listing not found"}
	}
	o := s.redact(&result.Offer)
	if o == nil {
		return history.Listing{}, &apiError{404, "not_found", "Listing cannot be published under its current policy"}
	}
	result.Offer = *o
	if p.Policy.PrefixVisibility != "full" {
		result.ResourceID = catalog.StableID("masked", result.ID)
	}
	return result, nil
}
func (s *service) resources(ctx context.Context, v url.Values) (history.ResourceResult, error) {
	if s.extras.History == nil {
		return history.ResourceResult{}, &apiError{503, "history_disabled", "History storage is not configured"}
	}
	if e := parseFilters(v, "provider resource after_id limit"); e != nil {
		return history.ResourceResult{}, e
	}
	if !validHistoryResource(v.Get("resource")) {
		return history.ResourceResult{}, badQuery("Invalid IP or CIDR")
	}
	after := v.Get("after_id")
	if after != "" && !catalog.ValidToken(after) {
		return history.ResourceResult{}, badQuery("Invalid resource cursor")
	}
	limit, e := pageLimit(v.Get("limit"))
	if e != nil {
		return history.ResourceResult{}, e
	}
	providers, e := s.allowed(v.Get("provider"), true)
	if e != nil {
		return history.ResourceResult{}, e
	}
	result, e := s.extras.History.Resources(ctx, history.ResourceQuery{Providers: providers, Resource: v.Get("resource"), AfterID: after, Limit: limit})
	if e != nil {
		return result, &apiError{500, "history_failed", "Could not query known resources"}
	}
	allowedProviders := make(map[string]bool, len(providers))
	for _, id := range providers {
		allowedProviders[id] = true
	}
	active := map[string]int{}
	for _, o := range s.store.View().Offers {
		if allowedProviders[o.ProviderID] && o.Resource.Prefix != nil {
			active[history.ResourceID(o)]++
		}
	}
	for i := range result.Items {
		result.Items[i].ActiveOffers = active[result.Items[i].ID]
	}
	return result, nil
}
func (s *service) inspect(ctx context.Context, q intelligence.Query) (intelligence.Report, error) {
	if s.extras.Intelligence == nil {
		return intelligence.Report{}, &apiError{503, "checks_disabled", "Network checks are not configured"}
	}
	result, e := s.extras.Intelligence.Cached(ctx, q)
	if e != nil {
		if errors.Is(e, intelligence.ErrBusy) {
			return result, &apiError{429, "rate_limited", e.Error()}
		}
		return result, badQuery(e.Error())
	}
	return result, nil
}
func parseInspection(v url.Values) (intelligence.Query, error) {
	if e := parseFilters(v, "resource checks start_time end_time version asn"); e != nil {
		return intelligence.Query{}, e
	}
	q := intelligence.Query{Resource: v.Get("resource"), StartTime: v.Get("start_time"), EndTime: v.Get("end_time"), Version: v.Get("version")}
	if raw := v.Get("checks"); raw != "" {
		q.Checks = strings.Split(raw, ",")
	}
	if raw := v.Get("asn"); raw != "" {
		n, e := strconv.ParseUint(raw, 10, 32)
		if e != nil {
			return q, badQuery("Invalid ASN")
		}
		q.ASN = uint32(n)
	}
	return q, nil
}
func schema() any { var out any; json.Unmarshal(openAPI, &out); return out }

func (s *service) collectionStatus() (intelligence.CollectionStatus, error) {
	if s.extras.Automatic == nil {
		return intelligence.CollectionStatus{}, &apiError{503, "checks_disabled", "Automatic collection is not configured"}
	}
	return s.extras.Automatic.Status(s.store), nil
}

func (s *service) attachChecks(item *Item) {
	if s.extras.Automatic != nil && item.Resource.Prefix != nil {
		r := s.extras.Automatic.Get(*item.Resource.Prefix)
		item.Checks = &r
	}
}

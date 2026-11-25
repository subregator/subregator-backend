package api

import (
	"context"
	"math/big"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/history"
)

type MarketOffer struct {
	Item
	Relation   string       `json:"relation"`
	PriceScope string       `json:"price_scope"`
	QuoteCosts []QuoteCosts `json:"quote_costs"`
}
type MarketCurrent struct {
	Snapshot   string        `json:"snapshot"`
	Total      int           `json:"total"`
	Items      []MarketOffer `json:"items"`
	NextOffset *int          `json:"next_offset"`
}
type MarketEvent struct {
	history.Event
	BeforePrices []QuoteCosts `json:"before_prices"`
	AfterPrices  []QuoteCosts `json:"after_prices"`
}
type MarketHistory struct {
	Items             []MarketEvent `json:"items"`
	NextAfterID       *int64        `json:"next_after_id"`
	TrackingStartedAt time.Time     `json:"tracking_started_at"`
}
type MarketResult struct {
	Resource            string                `json:"resource"`
	AddressCount        string                `json:"address_count"`
	Current             MarketCurrent         `json:"current"`
	HistoricalProviders []history.Association `json:"historical_providers"`
	History             MarketHistory         `json:"history"`
	Polls               history.PollResult    `json:"polls"`
	Semantics           string                `json:"semantics"`
}

func prefixRelation(requested, actual netip.Prefix) string {
	if !requested.Overlaps(actual) {
		return ""
	}
	if requested.Bits() == actual.Bits() {
		return "exact"
	}
	if actual.Bits() < requested.Bits() {
		return "parent"
	}
	return "child"
}

func (s *service) market(ctx context.Context, v url.Values) (MarketResult, error) {
	out := MarketResult{Semantics: "provider_offers_not_ownership_fraud_or_sales; history_and_polls_are_exact_prefix_only; totals_are_quoted_charges_not_unreported_cost_guarantees"}
	if err := parseFilters(v, "resource provider listing_id model currency billing_months limit offset snapshot after_id after_poll_id relation"); err != nil {
		return out, err
	}
	prefix, err := netip.ParsePrefix(v.Get("resource"))
	if err != nil || prefix.Addr().Is4In6() {
		return out, badQuery("An IPv4 or IPv6 CIDR resource is required")
	}
	prefix = prefix.Masked()
	relation := v.Get("relation")
	if relation == "" {
		relation = "exact"
	}
	if !oneOf(relation, "exact", "parent", "child", "overlap") {
		return out, badQuery("Invalid prefix relation")
	}
	out.Resource = prefix.String()
	out.AddressCount = new(big.Int).Lsh(big.NewInt(1), uint(prefix.Addr().BitLen()-prefix.Bits())).String()
	filters := url.Values{"availability": {"available,waitlist,upcoming,unavailable,unknown"}}
	for _, key := range []string{"provider", "model", "currency", "billing_months", "limit", "offset", "snapshot"} {
		if value := v.Get(key); value != "" {
			filters.Set(key, value)
		}
	}
	q, err := ParseQuery(filters)
	if err != nil {
		return out, badQuery(err.Error())
	}
	providers, err := s.allowed(v.Get("provider"), true)
	if err != nil {
		return out, err
	}
	listing := v.Get("listing_id")
	if listing != "" && !catalog.ValidToken(listing) {
		return out, badQuery("Invalid listing identifier")
	}
	var afterPoll int64
	if raw := v.Get("after_poll_id"); raw != "" {
		afterPoll, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || afterPoll < 0 {
			return out, badQuery("Invalid poll cursor")
		}
	}
	now := time.Now()
	view := s.store.View()
	snapshot := view.PublicGeneration(now)
	if q.Snapshot != "" && q.Snapshot != snapshot {
		return out, &apiError{409, "snapshot_changed", "Restart pagination using the current snapshot"}
	}
	currentAllowed := map[string]bool{}
	for _, p := range view.Providers {
		if p.Policy.Publication != "pending" && p.Policy.PrefixVisibility == "full" {
			currentAllowed[p.ID] = true
		}
	}
	subset := *view
	subset.Offers = []catalog.Offer{}
	for _, o := range view.Offers {
		if !currentAllowed[o.ProviderID] || o.Resource.Prefix == nil || listing != "" && listing != o.ID {
			continue
		}
		actual, e := netip.ParsePrefix(*o.Resource.Prefix)
		if e != nil {
			continue
		}
		r := prefixRelation(prefix, actual)
		if r != "" && (relation == "overlap" || r == relation) {
			subset.Offers = append(subset.Offers, o)
		}
	}
	found := Search(&subset, q, now)
	out.Current = MarketCurrent{Snapshot: snapshot, Total: found.Total, Items: []MarketOffer{}, NextOffset: found.NextOffset}
	prices := func(o *catalog.Offer, resource string) []QuoteCosts {
		result := []QuoteCosts{}
		if o == nil || o.Resource.Prefix == nil || *o.Resource.Prefix != resource || !matchSet(q.Model, o.Model) {
			return result
		}
		for _, quote := range o.Quotes {
			if q.Term != 0 && quote.BillingMonths != q.Term || q.Currency != "" && (quote.Price == nil || quote.Price.Currency != q.Currency) {
				continue
			}
			result = append(result, quoteCosts(quote, o.Model))
		}
		return result
	}
	for _, item := range found.Items {
		actual, _ := netip.ParsePrefix(*item.Resource.Prefix)
		costs := prices(&item.Offer, actual.String())
		out.Current.Items = append(out.Current.Items, MarketOffer{item, prefixRelation(prefix, actual), actual.String(), costs})
	}
	eventFilters := url.Values{"resource": {out.Resource}}
	for _, key := range []string{"provider", "listing_id", "after_id", "limit"} {
		if value := v.Get(key); value != "" {
			eventFilters.Set(key, value)
		}
	}
	events, err := s.events(ctx, eventFilters)
	if err != nil {
		return out, err
	}
	out.History = MarketHistory{Items: []MarketEvent{}, NextAfterID: events.NextAfterID, TrackingStartedAt: events.TrackingStartedAt}
	for _, e := range events.Items {
		out.History.Items = append(out.History.Items, MarketEvent{e, prices(e.Before, out.Resource), prices(e.After, out.Resource)})
	}
	out.HistoricalProviders, err = s.extras.History.Associations(ctx, out.Resource, providers)
	if err != nil {
		return out, &apiError{500, "history_failed", "Could not query provider associations"}
	}
	out.Polls, err = s.extras.History.MarketPolls(ctx, out.Resource, providers, afterPoll, q.Limit)
	if err != nil {
		return out, &apiError{500, "history_failed", "Could not query collection coverage"}
	}
	return out, nil
}

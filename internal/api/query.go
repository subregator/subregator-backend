package api

import (
	"errors"
	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/intelligence"
	"math/bits"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Query struct {
	Provider, Country, RIR, Model, Availability map[string]bool
	Family, MinPrefix, MaxPrefix, Term          int
	Currency, Basis, Text, Sort, Snapshot       string
	MinPrice, MaxPrice                          *int64
	Network                                     *netip.Prefix
	FreshOnly                                   bool
	Limit, Offset                               int
}

func ParseQuery(v url.Values) (Query, error) {
	q := Query{MinPrefix: 0, MaxPrefix: 128, Limit: 50, Sort: "id"}
	allowed := map[string]bool{}
	for _, k := range strings.Fields("provider country rir model availability family min_prefix max_prefix billing_months currency geography_basis q sort snapshot min_price_minor max_price_minor within fresh_only limit offset") {
		allowed[k] = true
	}
	for k, x := range v {
		if !allowed[k] || len(x) != 1 || len(x[0]) > 1000 {
			return q, errors.New("unknown, repeated or oversized query parameter")
		}
	}
	var e error
	set := func(key string, upper bool) map[string]bool {
		m := map[string]bool{}
		if v.Get(key) != "" {
			for _, s := range strings.Split(v.Get(key), ",") {
				if upper {
					s = strings.ToUpper(s)
				}
				m[s] = true
			}
		}
		return m
	}
	q.Provider = set("provider", false)
	q.Country = set("country", true)
	q.RIR = set("rir", true)
	q.Model = set("model", false)
	q.Availability = set("availability", false)
	if len(q.Availability) == 0 {
		q.Availability["available"] = true
	}
	for s := range q.Provider {
		if !catalog.ValidToken(s) {
			return q, errors.New("invalid provider")
		}
	}
	for s := range q.Country {
		if len(s) != 2 || s[0] < 'A' || s[0] > 'Z' || s[1] < 'A' || s[1] > 'Z' {
			return q, errors.New("invalid country")
		}
	}
	for s := range q.RIR {
		if !oneOf(s, "RIPE NCC", "ARIN", "APNIC", "LACNIC", "AFRINIC") {
			return q, errors.New("invalid RIR")
		}
	}
	for s := range q.Model {
		if !oneOf(s, "purchase", "lease") {
			return q, errors.New("invalid model")
		}
	}
	for s := range q.Availability {
		if !oneOf(s, "available", "upcoming", "waitlist", "unavailable", "unknown") {
			return q, errors.New("invalid availability")
		}
	}
	number := func(key string, d, min, max int) int {
		if v.Get(key) == "" {
			return d
		}
		n, err := strconv.Atoi(v.Get(key))
		if err != nil || n < min || n > max {
			e = errors.New("invalid numeric filter: " + key)
			return d
		}
		return n
	}
	q.Family = number("family", 0, 4, 6)
	if q.Family == 5 {
		return q, errors.New("invalid family")
	}
	q.MinPrefix = number("min_prefix", 0, 0, 128)
	q.MaxPrefix = number("max_prefix", 128, 0, 128)
	q.Term = number("billing_months", 0, 1, 1200)
	q.Limit = number("limit", 50, 1, 200)
	q.Offset = number("offset", 0, 0, 100000)
	if e != nil {
		return q, e
	}
	if q.MinPrefix > q.MaxPrefix {
		return q, errors.New("invalid prefix range")
	}
	q.Currency = strings.ToUpper(v.Get("currency"))
	if q.Currency != "" && (len(q.Currency) != 3 || strings.IndexFunc(q.Currency, func(r rune) bool { return r < 'A' || r > 'Z' }) >= 0) {
		return q, errors.New("invalid currency")
	}
	q.Basis = v.Get("geography_basis")
	if q.Basis != "" && !oneOf(q.Basis, "provider_geolocation", "seller_country", "registry", "unknown") {
		return q, errors.New("invalid geography basis")
	}
	q.Text = strings.ToLower(v.Get("q"))
	if len(q.Text) > 200 {
		return q, errors.New("search text too long")
	}
	if s := v.Get("sort"); s != "" {
		q.Sort = s
	}
	if !oneOf(q.Sort, "id", "price_asc", "price_desc", "prefix_asc", "prefix_desc", "updated_desc") {
		return q, errors.New("invalid sort")
	}
	q.Snapshot = v.Get("snapshot")
	if s := v.Get("fresh_only"); s != "" {
		if s != "true" && s != "false" {
			return q, errors.New("invalid fresh_only")
		}
		q.FreshOnly = s == "true"
	}
	for key, dest := range map[string]**int64{"min_price_minor": &q.MinPrice, "max_price_minor": &q.MaxPrice} {
		if s := v.Get(key); s != "" {
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil || n < 0 || n > 1_000_000_000_000 {
				return q, errors.New("invalid price")
			}
			*dest = &n
		}
	}
	if (q.MinPrice != nil || q.MaxPrice != nil || strings.HasPrefix(q.Sort, "price_")) && q.Currency == "" {
		return q, errors.New("price filtering and sorting require currency")
	}
	if q.MinPrice != nil && q.MaxPrice != nil && *q.MinPrice > *q.MaxPrice {
		return q, errors.New("invalid price range")
	}
	if s := v.Get("within"); s != "" {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return q, errors.New("invalid within CIDR")
		}
		p = p.Masked()
		q.Network = &p
	}
	return q, nil
}
func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func matchSet(set map[string]bool, s string) bool { return len(set) == 0 || set[s] }

type priceRatio struct{ amount, denominator uint64 }

func (p priceRatio) compare(other priceRatio) int {
	ah, al := bits.Mul64(p.amount, other.denominator)
	bh, bl := bits.Mul64(other.amount, p.denominator)
	if ah < bh || ah == bh && al < bl {
		return -1
	}
	if ah > bh || ah == bh && al > bl {
		return 1
	}
	return 0
}
func quotePrice(q catalog.Quote) priceRatio {
	if q.Price == nil {
		return priceRatio{}
	}
	den := uint64(1)
	for i := 0; i < q.Price.MinorUnit; i++ {
		den *= 10
	}
	if q.BillingMonths > 0 {
		den *= uint64(q.BillingMonths)
	}
	return priceRatio{uint64(q.Price.AmountMinor), den}
}
func matchesQuotes(o catalog.Offer, q Query, includeIDs bool) (bool, []string, priceRatio) {
	var ids []string
	var best priceRatio
	matched := false
	for _, quote := range o.Quotes {
		if q.Term != 0 && quote.BillingMonths != q.Term {
			continue
		}
		if q.Currency != "" && (quote.Price == nil || quote.Price.Currency != q.Currency) {
			continue
		}
		price := quotePrice(quote)
		if q.MinPrice != nil && (price.denominator == 0 || price.compare(priceRatio{uint64(*q.MinPrice), 100}) < 0) {
			continue
		}
		if q.MaxPrice != nil && (price.denominator == 0 || price.compare(priceRatio{uint64(*q.MaxPrice), 100}) > 0) {
			continue
		}
		matched = true
		if includeIDs {
			ids = append(ids, quote.ID)
		}
		if price.denominator != 0 && (best.denominator == 0 || price.compare(best) < 0) {
			best = price
		}
	}
	return matched, ids, best
}

type Item struct {
	Checks *intelligence.OfferChecks `json:"checks,omitempty"`
	catalog.Offer
	Freshness        string   `json:"freshness"`
	MatchingQuoteIDs []string `json:"matching_quote_ids"`
}
type Facets struct {
	Providers  map[string]int `json:"providers"`
	Countries  map[string]int `json:"countries"`
	RIRs       map[string]int `json:"rirs"`
	Families   map[int]int    `json:"families"`
	Models     map[string]int `json:"models"`
	Currencies map[string]int `json:"currencies"`
}
type Result struct {
	SchemaVersion int    `json:"schema_version"`
	Snapshot      string `json:"snapshot"`
	Total         int    `json:"total"`
	Limit         int    `json:"limit"`
	Offset        int    `json:"offset"`
	NextOffset    *int   `json:"next_offset"`
	Items         []Item `json:"items"`
	Facets        Facets `json:"facets"`
}

func Search(v *catalog.View, q Query, now time.Time) Result {
	type candidate struct {
		index     int
		price     priceRatio
		freshness string
	}
	found := make([]candidate, 0, len(v.Offers))
	fresh := map[string]string{}
	maxAge := map[string]time.Duration{}
	for _, p := range v.Providers {
		fresh[p.ID] = v.Freshness(p.ID, now)
		maxAge[p.ID] = time.Duration(p.Policy.MinRefreshSeconds) * 2 * time.Second
	}
	facets := Facets{Providers: map[string]int{}, Countries: map[string]int{}, RIRs: map[string]int{}, Families: map[int]int{}, Models: map[string]int{}, Currencies: map[string]int{}}
	for i, o := range v.Offers {
		if !o.Publishable(now) {
			continue
		}
		freshness := fresh[o.ProviderID]
		if freshness == "fresh" && now.Sub(o.ObservedAt) > maxAge[o.ProviderID] {
			freshness = "stale"
		}
		if !matchSet(q.Provider, o.ProviderID) || !matchSet(q.RIR, o.Resource.RIR) || !matchSet(q.Model, o.Model) || !matchSet(q.Availability, o.Availability) || q.Family != 0 && q.Family != o.Resource.Family || o.Resource.PrefixLength < q.MinPrefix || o.Resource.PrefixLength > q.MaxPrefix || q.Basis != "" && o.Geography.Basis != q.Basis || q.FreshOnly && freshness != "fresh" {
			continue
		}
		if !matchSet(q.Country, o.Geography.Country) {
			continue
		}
		if len(q.Country) > 0 && q.Basis == "" && o.Geography.Basis == "seller_country" {
			continue
		}
		if q.Network != nil {
			if o.Resource.Prefix == nil {
				continue
			}
			p, e := netip.ParsePrefix(*o.Resource.Prefix)
			if e != nil || !q.Network.Contains(p.Addr()) || p.Bits() < q.Network.Bits() {
				continue
			}
		}
		if q.Text != "" {
			text := o.ProviderID + " " + o.Resource.RIR + " " + o.Geography.Country + " " + o.Geography.City + " " + o.Terms.Summary
			if o.Resource.Prefix != nil {
				text += " " + *o.Resource.Prefix
			}
			if !strings.Contains(strings.ToLower(text), q.Text) {
				continue
			}
		}
		matched, _, price := matchesQuotes(o, q, false)
		if !matched && (q.Currency != "" || q.Term != 0 || q.MinPrice != nil || q.MaxPrice != nil) {
			continue
		}
		found = append(found, candidate{i, price, freshness})
		facets.Providers[o.ProviderID]++
		if o.Geography.Country != "" && o.Geography.Basis != "seller_country" {
			facets.Countries[o.Geography.Country]++
		}
		if o.Resource.RIR != "" {
			facets.RIRs[o.Resource.RIR]++
		}
		facets.Families[o.Resource.Family]++
		facets.Models[o.Model]++
		currencies := map[string]bool{}
		for _, quote := range o.Quotes {
			if quote.Price != nil {
				currencies[quote.Price.Currency] = true
			}
		}
		for c := range currencies {
			facets.Currencies[c]++
		}
	}
	if q.Sort != "id" {
		sort.Slice(found, func(i, j int) bool {
			a, b := found[i], found[j]
			x, y := v.Offers[a.index], v.Offers[b.index]
			switch q.Sort {
			case "price_asc", "price_desc":
				if a.price.denominator == 0 && b.price.denominator != 0 {
					return false
				}
				if a.price.denominator != 0 && b.price.denominator == 0 {
					return true
				}
				if a.price.denominator != 0 && b.price.denominator != 0 {
					c := a.price.compare(b.price)
					if c != 0 {
						if q.Sort == "price_desc" {
							return c > 0
						}
						return c < 0
					}
				}
			case "prefix_asc", "prefix_desc":
				if x.Resource.PrefixLength != y.Resource.PrefixLength {
					if q.Sort == "prefix_desc" {
						return x.Resource.PrefixLength > y.Resource.PrefixLength
					}
					return x.Resource.PrefixLength < y.Resource.PrefixLength
				}
			case "updated_desc":
				if !x.ObservedAt.Equal(y.ObservedAt) {
					return x.ObservedAt.After(y.ObservedAt)
				}
			}
			return x.ID < y.ID
		})
	}
	result := Result{SchemaVersion: 1, Snapshot: v.PublicGeneration(now), Total: len(found), Limit: q.Limit, Offset: q.Offset, Items: []Item{}, Facets: facets}
	end := min(len(found), q.Offset+q.Limit)
	for i := q.Offset; i < end; i++ {
		c := found[i]
		_, ids, _ := matchesQuotes(v.Offers[c.index], q, true)
		if ids == nil {
			ids = []string{}
		}
		result.Items = append(result.Items, Item{Offer: v.Offers[c.index], Freshness: c.freshness, MatchingQuoteIDs: ids})
	}
	if end < len(found) {
		result.NextOffset = &end
	}
	return result
}

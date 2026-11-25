package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/history"
	"github.com/subregator/subregator-backend/internal/testdb"
)

func marketFixture(t *testing.T) (*service, *history.DB, string) {
	t.Helper()
	dsn := testdb.URL(t)
	d, err := history.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	providers := []catalog.Provider{}
	for _, id := range []string{"a", "b", "hidden", "peaktera", "pending"} {
		p := catalog.Provider{ID: id, Name: id, URL: "https://example.com", Policy: catalog.Policy{Publication: "approved", PrefixVisibility: "full", MinRefreshSeconds: 60}}
		if id == "hidden" {
			p.Policy.PrefixVisibility = "hidden"
		}
		if id == "pending" {
			p.Policy.Publication = "pending"
		}
		if id == "peaktera" {
			p.Policy.MinRefreshSeconds = 900
		}
		providers = append(providers, p)
	}
	store, err := catalog.NewPersistentStore(d, "", providers)
	if err != nil {
		t.Fatal(err)
	}
	return &service{store: store, extras: Services{History: d}}, d, dsn
}
func marketOffer(provider, id, prefix string, at time.Time) catalog.Offer {
	parsed := netip.MustParsePrefix(prefix)
	family := 6
	if parsed.Addr().Is4() {
		family = 4
	}
	bits := parsed.Bits()
	return catalog.Offer{ProviderID: provider, ExternalID: id, Model: "lease", Availability: "available", Resource: catalog.Resource{Family: family, Prefix: &prefix, PrefixLength: bits}, Geography: catalog.Geography{Basis: "unknown"}, URL: "https://example.com/offer", ObservedAt: at, Quotes: []catalog.Quote{{ID: "monthly", Price: &catalog.Money{Currency: "USD", AmountMinor: 1000, MinorUnit: 2}, BillingMonths: 1, Taxes: "included", Fees: []catalog.Fee{}}}}
}
func TestMarketExactHistoryGapsAndRestart(t *testing.T) {
	s, _, dsn := marketFixture(t)
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	prefix := "1.1.1.0/24"
	a := marketOffer("a", "old", prefix, at)
	b := marketOffer("b", "second", prefix, at)
	apply := func(p string, offers []catalog.Offer, err error, offset time.Duration) {
		t.Helper()
		e := s.store.Apply(p, offers, err, at.Add(offset))
		if (e != nil) != (err != nil) {
			t.Fatal(e)
		}
	}
	apply("a", []catalog.Offer{a}, nil, 0)
	apply("b", []catalog.Offer{b}, nil, 0)
	q := url.Values{"resource": {prefix}}
	out, err := s.market(context.Background(), q)
	if err != nil || out.Current.Total != 2 || len(out.HistoricalProviders) != 2 || len(out.History.Items) != 2 {
		t.Fatal(err, out)
	}
	if out.History.TrackingStartedAt.IsZero() || len(out.Polls.Items) != 2 {
		t.Fatal("missing tracking/polls", out)
	}
	a.Quotes[0].Price = &catalog.Money{Currency: "USD", AmountMinor: 1500, MinorUnit: 2}
	a.ObservedAt = at.Add(time.Second)
	apply("a", []catalog.Offer{a}, nil, time.Second)
	apply("a", nil, errors.New("synthetic source failure"), 2*time.Second)
	out, err = s.market(context.Background(), q)
	if err != nil || out.Current.Total != 2 {
		t.Fatal("failure removed offer", err, out)
	}
	var stale bool
	for _, o := range out.Current.Items {
		if o.ProviderID == "a" {
			stale = o.Freshness == "stale"
		}
	}
	if !stale || out.Polls.Items[len(out.Polls.Items)-1].Complete {
		t.Fatal("failure hidden", out)
	}
	apply("a", nil, nil, 3*time.Second)
	a.ExternalID = "replacement"
	apply("a", []catalog.Offer{a}, nil, 4*time.Second)
	moved := a
	other := "1.1.2.0/24"
	moved.Resource.Prefix = &other
	apply("a", []catalog.Offer{moved}, nil, 5*time.Second)
	out, err = s.market(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if out.Current.Total != 1 || len(out.HistoricalProviders) != 2 {
		t.Fatal("current and historical mixed", out)
	}
	var changed, removed, reappeared, movedAway bool
	for _, e := range out.History.Items {
		if e.Type == "changed" && len(e.BeforePrices) == 1 && len(e.AfterPrices) == 1 {
			changed = e.BeforePrices[0].Quote.Price.AmountMinor == 1000 && e.AfterPrices[0].Quote.Price.AmountMinor == 1500
		}
		if e.Type == "removed" {
			removed = len(e.BeforePrices) == 1 && len(e.AfterPrices) == 0
		}
		reappeared = reappeared || e.ResourceReappeared
		if e.Type == "resource_changed" {
			movedAway = len(e.BeforePrices) == 1 && len(e.AfterPrices) == 0
		}
	}
	if !changed || !removed || !reappeared || !movedAway {
		t.Fatal("lost traceability", changed, removed, reappeared, movedAway, out)
	}
	q.Set("limit", "1")
	page, err := s.market(context.Background(), q)
	if err != nil || page.History.NextAfterID == nil || page.Polls.NextAfterID == nil {
		t.Fatal(err, page)
	}
	q.Set("after_id", jsonNumber(*page.History.NextAfterID))
	q.Set("after_poll_id", jsonNumber(*page.Polls.NextAfterID))
	next, err := s.market(context.Background(), q)
	if err != nil || next.History.Items[0].ID <= page.History.Items[0].ID || next.Polls.Items[0].ID <= page.Polls.Items[0].ID {
		t.Fatal(err, next)
	}
	reopened, err := history.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, err := catalog.NewPersistentStore(reopened, "", s.store.View().Providers)
	if err != nil {
		t.Fatal(err)
	}
	s.store = restored
	s.extras.History = reopened
	q.Del("limit")
	q.Del("after_id")
	q.Del("after_poll_id")
	after, err := s.market(context.Background(), q)
	if err != nil || len(after.History.Items) != len(out.History.Items) || len(after.Polls.Items) != len(out.Polls.Items) {
		t.Fatal("restart lost history", err, after)
	}
}
func jsonNumber(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestMarketRelationsPoliciesAndMCP(t *testing.T) {
	s, _, _ := marketFixture(t)
	at := time.Now().UTC()
	child := "1.1.0.0/24"
	parent := "1.1.0.0/22"
	v6 := "2001:4860::/48"
	a := marketOffer("a", "child", child, at)
	p := marketOffer("a", "parent", parent, at)
	p.Resource.PrefixLength = 22
	six := marketOffer("a", "v6", v6, at)
	for provider, offers := range map[string][]catalog.Offer{"a": {a, p, six}, "hidden": {marketOffer("hidden", "secret", child, at)}} {
		if err := s.store.Apply(provider, offers, nil, at); err != nil {
			t.Fatal(err)
		}
	}
	for relation, want := range map[string]int{"exact": 1, "parent": 1, "child": 0, "overlap": 2} {
		out, err := s.market(context.Background(), url.Values{"resource": {child}, "relation": {relation}})
		if err != nil || out.Current.Total != want {
			t.Fatal(relation, err, out)
		}
		for _, item := range out.Current.Items {
			if item.Resource.Prefix == nil || item.ProviderID == "hidden" || item.PriceScope != *item.Resource.Prefix {
				t.Fatal("scope/disclosure lost", item)
			}
		}
		if len(out.HistoricalProviders) != 1 || len(out.History.Items) != 1 {
			t.Fatal("related histories merged", out)
		}
	}
	sixOut, err := s.market(context.Background(), url.Values{"resource": {v6}})
	if err != nil || sixOut.AddressCount != "1208925819614629174706176" {
		t.Fatal(err, sixOut)
	}
	wide, err := s.market(context.Background(), url.Values{"resource": {"::/0"}, "relation": {"child"}})
	if err != nil || wide.AddressCount != "340282366920938463463374607431768211456" || wide.Current.Total != 1 {
		t.Fatal(err, wide)
	}
	for _, values := range []url.Values{{}, {"resource": {"bad"}}, {"resource": {child}, "limit": {"201"}}, {"resource": {child}, "relation": {"owner"}}, {"resource": {child}, "after_poll_id": {"-1"}}, {"resource": {child}, "after_id": {"-1"}}, {"resource": {child}, "listing_id": {"bad/id"}}} {
		if _, err := s.market(context.Background(), values); err == nil {
			t.Fatal("invalid market query accepted", values)
		}
	}
	h := Handler(s.store, "", s.extras)
	server := httptest.NewServer(h)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "market-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	response, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "subnet_market", Arguments: map[string]any{"filters": map[string]string{"resource": child}}})
	if err != nil || response.IsError {
		t.Fatal(err, response)
	}
	data, _ := json.Marshal(response.StructuredContent)
	var actual MarketResult
	if err = json.Unmarshal(data, &actual); err != nil || actual.Current.Total != 1 {
		t.Fatal(err, string(data))
	}
	rest := httptest.NewRecorder()
	h.ServeHTTP(rest, httptest.NewRequest("GET", "/api/v1/market?resource="+child, nil))
	if rest.Code != 200 {
		t.Fatal(rest.Code, rest.Body.String())
	}
	var fromREST MarketResult
	json.Unmarshal(rest.Body.Bytes(), &fromREST)
	if fromREST.Current.Snapshot != actual.Current.Snapshot || len(fromREST.History.Items) != len(actual.History.Items) {
		t.Fatal("REST/MCP differ")
	}
	providers := slices.Clone(s.store.View().Providers)
	for i := range providers {
		if providers[i].ID == "a" {
			providers[i].Policy.PrefixVisibility = "hidden"
		}
	}
	current, err := catalog.NewStore("", providers)
	if err != nil {
		t.Fatal(err)
	}
	s.store = current
	hidden, err := s.market(context.Background(), url.Values{"resource": {child}, "relation": {"overlap"}})
	if err != nil || hidden.Current.Total != 0 || len(hidden.HistoricalProviders) != 0 || len(hidden.Polls.Items) != 0 || len(hidden.History.Items) != 0 {
		t.Fatal("policy change leaked history/counts", err, hidden)
	}
}

func TestMarketQuoteFiltersAndPeakteraBoundaries(t *testing.T) {
	s, _, _ := marketFixture(t)
	at := time.Now().UTC()
	prefix := "1.1.1.0/24"
	a := marketOffer("a", "multi", prefix, at)
	minimum := 24
	refundable := true
	a.Quotes = append(a.Quotes, catalog.Quote{ID: "annual", Price: &catalog.Money{Currency: "EUR", AmountMinor: 9000, MinorUnit: 2}, BillingMonths: 12, MinimumMonths: &minimum, Taxes: "excluded", Fees: []catalog.Fee{{Kind: "deposit", Frequency: "once", Amount: nil, Refundable: &refundable, Condition: "subject to contract"}}})
	purchase := marketOffer("b", "purchase", prefix, at)
	purchase.Model = "purchase"
	purchase.Quotes[0].BillingMonths = 0
	pk := marketOffer("peaktera", "approved", prefix, at)
	pk.Quotes[0].OrderURL = "https://www.peaktera.com/order"
	for p, offers := range map[string][]catalog.Offer{"a": {a}, "b": {purchase}, "peaktera": {pk}} {
		if err := s.store.Apply(p, offers, nil, at); err != nil {
			t.Fatal(err)
		}
	}
	q := url.Values{"resource": {prefix}, "currency": {"EUR"}, "model": {"lease"}, "billing_months": {"12"}}
	out, err := s.market(context.Background(), q)
	if err != nil || out.Current.Total != 1 || len(out.Current.Items[0].QuoteCosts) != 1 {
		t.Fatal(err, out)
	}
	quote := out.Current.Items[0].QuoteCosts[0]
	if quote.FirstPeriodTotal != nil || quote.Quote.MinimumMonths == nil || *quote.Quote.MinimumMonths != 24 || quote.Quote.Fees[0].Amount != nil || quote.Quote.Fees[0].Refundable == nil || !*quote.Quote.Fees[0].Refundable {
		t.Fatal("quote terms lost", quote)
	}
	for _, e := range out.History.Items {
		for _, cost := range e.AfterPrices {
			if cost.Quote.Price.Currency != "EUR" || cost.Quote.BillingMonths != 12 {
				t.Fatal("incomparable price series", e)
			}
		}
		if e.ProviderID == "peaktera" {
			t.Fatal("Peaktera history public")
		}
	}
	all, err := s.market(context.Background(), url.Values{"resource": {prefix}})
	if err != nil || all.Current.Total != 3 || len(all.HistoricalProviders) != 2 {
		t.Fatal(err, all)
	}
	for _, p := range all.Polls.Items {
		if p.ProviderID == "peaktera" {
			t.Fatal("Peaktera historical polling disclosed")
		}
	}
	q = url.Values{"resource": {prefix}, "provider": {"a"}, "listing_id": {catalog.StableID("a", "multi")}}
	selected, err := s.market(context.Background(), q)
	if err != nil || selected.Current.Total != 1 || len(selected.HistoricalProviders) != 1 {
		t.Fatal(err, selected)
	}
	q.Set("snapshot", "outdated")
	if _, err := s.market(context.Background(), q); err == nil {
		t.Fatal("accepted stale current snapshot")
	}
	pk.ObservedAt = at.Add(-2 * time.Hour)
	if err := s.store.Apply("peaktera", []catalog.Offer{pk}, nil, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	expired, err := s.market(context.Background(), url.Values{"resource": {prefix}, "relation": {"overlap"}})
	if err != nil || expired.Current.Total != 2 {
		t.Fatal("expired current Peaktera exposed", err, expired)
	}
	for _, publication := range []string{"pending", "approved"} {
		providers := slices.Clone(s.store.View().Providers)
		for i := range providers {
			if providers[i].ID == "a" {
				providers[i].Policy.Publication = publication
				providers[i].Policy.PrefixVisibility = "hidden"
			}
		}
		current, e := catalog.NewStore("", providers)
		if e != nil {
			t.Fatal(e)
		}
		private := service{store: current, extras: s.extras}
		hidden, e := private.market(context.Background(), url.Values{"resource": {prefix}, "provider": {"a"}})
		if e != nil || hidden.Current.Total != 0 || len(hidden.HistoricalProviders) != 0 || len(hidden.History.Items) != 0 || len(hidden.Polls.Items) != 0 {
			t.Fatal("policy revealed counts/history", e, hidden)
		}
	}
}

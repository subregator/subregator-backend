package api

import (
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

func TestPeakteraExpiry(t *testing.T) {
	at := time.Now().UTC()
	p := catalog.Provider{ID: "peaktera", Name: "Peaktera", URL: "https://www.peaktera.com", Policy: catalog.Policy{Publication: "approved", PrefixVisibility: "full", MinRefreshSeconds: 900}}
	s, e := catalog.NewStore("", []catalog.Provider{p})
	if e != nil {
		t.Fatal(e)
	}
	prefix := "192.0.2.0/24"
	o := catalog.Offer{ProviderID: p.ID, ExternalID: prefix, Model: "lease", Availability: "available", Resource: catalog.Resource{Family: 4, Prefix: &prefix, PrefixLength: 24}, Geography: catalog.Geography{Basis: "unknown"}, URL: p.URL, ObservedAt: at, Quotes: []catalog.Quote{{ID: "monthly", BillingMonths: 1, Taxes: "unknown"}}}
	o.Quotes[0] = quoteWithOrderURL(t, o.Quotes[0])
	if e = s.Apply(p.ID, []catalog.Offer{o}, nil, at); e != nil {
		t.Fatal(e)
	}
	q, e := ParseQuery(url.Values{})
	if e != nil {
		t.Fatal(e)
	}
	if r := Search(s.View(), q, at.Add(time.Hour)); r.Total != 1 {
		t.Fatal("expired before one hour")
	}
	if r := Search(s.View(), q, at.Add(time.Hour+time.Nanosecond)); r.Total != 0 {
		t.Fatal("published expired Peaktera offer")
	}
	if e = s.Apply(p.ID, nil, errors.New("offline"), at.Add(time.Hour+time.Second)); e == nil {
		t.Fatal("missing fetch failure")
	}
	if r := Search(s.View(), q, at.Add(time.Hour+time.Minute)); r.Total != 0 {
		t.Fatal("failed refresh extended lifetime")
	}
	old := o
	old.ObservedAt = at.Add(-2 * time.Hour)
	if e = s.Apply(p.ID, []catalog.Offer{old}, nil, at); e != nil {
		t.Fatal(e)
	}
	svc := service{store: s}
	if _, e = svc.offer(s.View().Offers[0].ID); e == nil {
		t.Fatal("expired detail published")
	}
	if _, e = svc.offers(url.Values{}); e != nil {
		t.Fatal(e)
	}
	if ids, e := svc.allowed("", false); e != nil || len(ids) != 0 {
		t.Fatal("Peaktera history remains public", ids, e)
	}
	if svc.redact(&o) != nil {
		t.Fatal("Peaktera history payload remains public")
	}
}

func quoteWithOrderURL(t *testing.T, q catalog.Quote) catalog.Quote {
	t.Helper()
	b, _ := json.Marshal(q)
	var v map[string]any
	json.Unmarshal(b, &v)
	v["order_url"] = "https://www.peaktera.com/portal/checkout?range=1&prefix=192.0.2.0%2F24&term=monthly"
	b, _ = json.Marshal(v)
	if e := json.Unmarshal(b, &q); e != nil {
		t.Fatal(e)
	}
	return q
}

func TestPeakteraExpiryChangesSnapshot(t *testing.T) {
	now := time.Now().UTC()
	v := &catalog.View{Generation: "same", Offers: []catalog.Offer{{ID: "peaktera_one", ProviderID: "peaktera", ObservedAt: now, Availability: "available", Quotes: []catalog.Quote{quoteWithOrderURL(t, catalog.Quote{ID: "monthly"})}}}}
	q := query(t, "")
	first := Search(v, q, now)
	next := Search(v, q, now.Add(time.Hour+time.Second))
	if first.Snapshot == next.Snapshot {
		t.Fatal("expiry changed pagination without changing snapshot")
	}
}

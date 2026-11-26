package api

import (
	"errors"
	"testing"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

func TestElistekaCurrentAndHistoricalSearch(t *testing.T) {
	var p catalog.Provider
	for _, candidate := range catalog.Providers() {
		if candidate.ID == "elisteka" {
			p = candidate
		}
	}
	s, err := catalog.NewStore("", []catalog.Provider{p})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 26, 4, 5, 0, 0, time.UTC)
	offer := catalog.Offer{ExternalID: "ipv6-32", ProviderID: p.ID, Model: "lease", Availability: "available", Resource: catalog.Resource{Family: 6, PrefixLength: 32}, Geography: catalog.Geography{Basis: "unknown"}, URL: p.URL, ObservedAt: at}
	waitlist := offer
	waitlist.ExternalID, waitlist.Availability = "ipv4-24", "waitlist"
	waitlist.Resource = catalog.Resource{Family: 4, PrefixLength: 24}
	if err = s.Apply(p.ID, []catalog.Offer{offer, waitlist}, nil, at); err != nil {
		t.Fatal(err)
	}
	for _, age := range []time.Duration{0, 36 * time.Hour, 36*time.Hour + time.Nanosecond} {
		now := at.Add(age)
		want := 1
		freshness := "fresh"
		if age > 36*time.Hour {
			want, freshness = 0, "stale"
		}
		for _, raw := range []string{"provider=elisteka", "provider=elisteka&availability=waitlist", "provider=elisteka&fresh_only=true"} {
			result := Search(s.View(), query(t, raw), now)
			if result.Total != want || result.Facets.Providers[p.ID] != want {
				t.Fatalf("age=%s query=%s total=%d", age, raw, result.Total)
			}
		}
		history := Search(s.View(), query(t, "provider=elisteka&fresh_only=false&availability=available,waitlist"), now)
		if history.Total != 2 {
			t.Fatal("historical offers lost")
		}
		for _, item := range history.Items {
			if item.Freshness != freshness || s.View().OfferFreshness(item.Offer, now) != freshness {
				t.Fatal("search/detail freshness inconsistent")
			}
		}
	}
	if err := s.Apply(p.ID, nil, errors.New("upstream failed"), at.Add(24*time.Hour)); err == nil {
		t.Fatal("expected refresh error")
	}
	if got := Search(s.View(), query(t, "provider=elisteka"), at.Add(25*time.Hour)); got.Total != 0 {
		t.Fatal("failed source remains current")
	}
	if got := Search(s.View(), query(t, "provider=elisteka&fresh_only=false"), at.Add(37*time.Hour)); got.Total != 1 || got.Items[0].Freshness != "stale" {
		t.Fatal("failed source history missing")
	}
	// A successful poll cannot make an old provider observation current again.
	if err := s.Apply(p.ID, []catalog.Offer{offer}, nil, at.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := Search(s.View(), query(t, "provider=elisteka"), at.Add(48*time.Hour)); got.Total != 0 {
		t.Fatal("old observation renewed by fetch")
	}
}

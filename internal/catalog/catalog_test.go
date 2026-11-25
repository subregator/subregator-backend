package catalog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureProvider() Provider {
	return Provider{ID: "test", Name: "Test", URL: "https://example.com", Policy: Policy{Publication: "approved", PrefixVisibility: "full", MinRefreshSeconds: 60}}
}
func fixtureOffer() Offer {
	prefix := "192.0.2.0/24"
	return Offer{ExternalID: "resource-1", ProviderID: "test", Model: "lease", Availability: "available", Resource: Resource{Family: 4, Prefix: &prefix, PrefixLength: 24}, Geography: Geography{Basis: "unknown"}, Quotes: []Quote{{ID: "monthly", Price: &Money{Currency: "USD", AmountMinor: 1000, MinorUnit: 2}, BillingMonths: 1, Taxes: "unknown"}}, URL: "https://example.com/offers/1"}
}
func TestNormalize(t *testing.T) {
	p := fixtureProvider()
	now := time.Now()
	o, e := Normalize(fixtureOffer(), p, now)
	if e != nil {
		t.Fatal(e)
	}
	if o.Resource.AddressCount != "256" || o.ID == "" || o.ObservedAt.IsZero() {
		t.Fatal(o)
	}
	o.Resource.Family = 6
	o.Resource.Prefix = nil
	o.Resource.PrefixLength = 0
	o, e = Normalize(o, p, now)
	if e != nil || o.Resource.AddressCount != "340282366920938463463374607431768211456" {
		t.Fatalf("IPv6 /0: %v %s", e, o.Resource.AddressCount)
	}
	cases := []struct {
		name   string
		change func(*Offer)
	}{
		{"host bits", func(o *Offer) { v := "192.0.2.1/24"; o.Resource.Prefix = &v }},
		{"family", func(o *Offer) { o.Resource.Family = 6 }},
		{"price", func(o *Offer) { o.Quotes[0].Price.AmountMinor = -1 }},
		{"fraction scale", func(o *Offer) { o.Quotes[0].Price.MinorUnit = 7 }},
		{"currency", func(o *Offer) { o.Quotes[0].Price.Currency = "usd" }},
		{"term", func(o *Offer) { o.Quotes[0].BillingMonths = 0 }},
		{"purchase term", func(o *Offer) { o.Model = "purchase" }},
		{"country", func(o *Offer) { o.Geography.Country = "UKK" }},
		{"timestamp", func(o *Offer) { o.ObservedAt = now.Add(time.Hour) }},
		{"url", func(o *Offer) { o.URL = "javascript:alert(1)" }},
		{"identity", func(o *Offer) { o.ProviderID = "other" }},
		{"availability", func(o *Offer) { o.Availability = "maybe" }},
		{"size", func(o *Offer) { o.Routing.BGP = strings.Repeat("x", 33000) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := fixtureOffer()
			c.change(&o)
			if _, e := Normalize(o, p, now); e == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
	p.Policy.Publication = "pending"
	if _, e := Normalize(fixtureOffer(), p, now); e == nil {
		t.Fatal("pending publication accepted")
	}
}
func TestHiddenPolicy(t *testing.T) {
	p := fixtureProvider()
	p.Policy.PrefixVisibility = "hidden"
	o := fixtureOffer()
	o.ExternalID = "192.0.2.0/24"
	o.Terms.Summary = "192.0.2.0/24"
	o.Routing.BGP = "192.0.2.0/24"
	o.Geography.City = "192.0.2.0/24"
	o.URL += "?prefix=192.0.2.0/24"
	o.Quotes[0].Fees = []Fee{{Kind: "setup", Frequency: "once", Condition: "192.0.2.0/24"}}
	n, e := Normalize(o, p, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(n)
	if strings.Contains(string(b), "192.0.2") {
		t.Fatal("hidden prefix leaked")
	}
	if n.Resource.AddressCount != "256" || n.Resource.Prefix != nil {
		t.Fatal(n)
	}
	o.URL = "https://example.com/192.0.2.0/24"
	if _, e := Normalize(o, p, time.Now()); e == nil {
		t.Fatal("prefix URL accepted")
	}
}
func TestStoreAtomicRefreshAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	p := fixtureProvider()
	s, e := NewStore(path, []Provider{p})
	if e != nil {
		t.Fatal(e)
	}
	at := time.Now().UTC()
	o := fixtureOffer()
	if e = s.Apply(p.ID, []Offer{o}, nil, at); e != nil {
		t.Fatal(e)
	}
	id := s.View().Offers[0].ID
	if e = s.Apply(p.ID, nil, errors.New("secret upstream detail"), at.Add(time.Second)); e == nil {
		t.Fatal("missing refresh error")
	}
	if len(s.View().Offers) != 1 || s.View().Freshness(p.ID, at) != "stale" {
		t.Fatal("lost last good snapshot")
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "secret upstream detail") {
		t.Fatal("raw error leaked")
	}
	broken := fixtureOffer()
	broken.Resource.Family = 9
	if e = s.Apply(p.ID, []Offer{o, broken}, nil, at); e == nil || len(s.View().Offers) != 1 {
		t.Fatal("partial snapshot published")
	}
	if e = s.Apply(p.ID, []Offer{o, o}, nil, at); e == nil {
		t.Fatal("duplicate accepted")
	}
	reloaded, e := NewStore(path, []Provider{p})
	if e != nil || reloaded.View().Offers[0].ID != id {
		t.Fatal("reload", e)
	}
	if e = s.Apply(p.ID, []Offer{}, nil, at); e != nil || len(s.View().Offers) != 0 {
		t.Fatal("confirmed empty catalog did not replace old offers", e)
	}
	if s.View().Freshness(p.ID, at.Add(121*time.Second)) != "stale" {
		t.Fatal("age not reflected")
	}
}
func TestHiddenStableReload(t *testing.T) {
	p := fixtureProvider()
	p.Policy.PrefixVisibility = "hidden"
	path := filepath.Join(t.TempDir(), "state.json")
	s, _ := NewStore(path, []Provider{p})
	if e := s.Apply(p.ID, []Offer{fixtureOffer()}, nil, time.Now()); e != nil {
		t.Fatal(e)
	}
	id := s.View().Offers[0].ID
	r, e := NewStore(path, []Provider{p})
	if e != nil || r.View().Offers[0].ID != id {
		t.Fatal("hidden ID changed on reload", e)
	}
}
func TestPersistenceFailureDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, _ := NewStore(path, []Provider{fixtureProvider()})
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	if e := s.Apply("test", []Offer{fixtureOffer()}, nil, time.Now()); e == nil || len(s.View().Offers) != 0 {
		t.Fatal("published undurable update")
	}
}
func TestCorruptSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(path, []byte("invalid"), 0600)
	if _, e := NewStore(path, []Provider{fixtureProvider()}); e == nil {
		t.Fatal("corrupt snapshot ignored")
	}
}

func TestRegistryCannotRelaxProviderRestrictions(t *testing.T) {
	for _, p := range Providers() {
		if p.ID == "prefix-broker" {
			p.Policy.MinRefreshSeconds = 60
			if _, e := NewStore("", []Provider{p}); e == nil {
				t.Fatal("provider refresh limit relaxed")
			}
			p.Policy.MinRefreshSeconds = 86400
			p.Policy.PrefixVisibility = "full"
			if _, e := NewStore("", []Provider{p}); e == nil {
				t.Fatal("provider prefix policy relaxed")
			}
		}
	}
}

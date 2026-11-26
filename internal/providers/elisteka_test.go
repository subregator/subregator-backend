package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

func elistekaProvider(t *testing.T) catalog.Provider {
	t.Helper()
	for _, p := range catalog.Providers() {
		if p.ID == "elisteka" {
			return p
		}
	}
	t.Fatal("missing ELISTEKA provider")
	return catalog.Provider{}
}

// Synthetic v1 products exercise the agreed mix, without claiming live prices.
func elistekaSample(at time.Time) Feed {
	f := Feed{SchemaVersion: 1, ProviderID: "elisteka", Complete: true, Offers: []catalog.Offer{}}
	for i, bits := range []int{24, 23, 22, 32, 29} {
		family, availability := 4, "waitlist"
		if i >= 3 {
			family, availability = 6, "available"
		}
		f.Offers = append(f.Offers, catalog.Offer{
			ExternalID: strings.Repeat("x", i+1), ProviderID: "elisteka", Model: "lease", Availability: availability,
			Resource:  catalog.Resource{Family: family, PrefixLength: bits, RIR: "RIPE NCC"},
			Geography: catalog.Geography{Basis: "unknown"},
			Quotes:    []catalog.Quote{{ID: "monthly", Price: &catalog.Money{Currency: "EUR", AmountMinor: 12345, MinorUnit: 2}, BillingMonths: 1, Taxes: "excluded"}},
			URL:       "https://elisteka.com/", ObservedAt: at,
		})
	}
	return f
}

func TestElistekaHTTPFeedAndFailureRetention(t *testing.T) {
	at := time.Now().UTC().Add(-72 * time.Hour)
	f := elistekaSample(at)
	status := http.StatusOK
	client := Client()
	client.Transport = elistekaTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("User-Agent") == "" {
			t.Error("unexpected feed request")
		}
		if r.URL.String() != ElistekaFeedURL {
			t.Error("unexpected feed URL")
		}
		b, err := json.Marshal(f)
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}, err
	})
	path := filepath.Join(t.TempDir(), "catalog.json")
	p := elistekaProvider(t)
	s, err := catalog.NewStore(path, []catalog.Provider{p})
	if err != nil {
		t.Fatal(err)
	}
	offers, err := LoadElisteka(context.Background(), client, ElistekaFeedURL)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Apply(p.ID, offers, nil, at); err != nil {
		t.Fatal(err)
	}
	if len(s.View().Offers) != 5 {
		t.Fatal("expected five products")
	}
	for _, o := range s.View().Offers {
		if o.Resource.Prefix != nil || o.Quotes[0].Price.AmountMinor != 12345 || o.Quotes[0].Price.Currency != "EUR" || o.Quotes[0].Taxes != "excluded" {
			t.Fatal("product or price changed", o)
		}
		if o.Resource.Family == 4 && o.Availability != "waitlist" || o.Resource.Family == 6 && o.Availability != "available" {
			t.Fatal("availability changed")
		}
	}
	status = http.StatusServiceUnavailable
	offers, err = LoadElisteka(context.Background(), client, ElistekaFeedURL)
	if err == nil || s.Apply(p.ID, offers, err, at.Add(24*time.Hour)) == nil {
		t.Fatal("failure accepted")
	}
	s, err = catalog.NewStore(path, []catalog.Provider{p})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.View().Offers) != 5 || !s.View().Sources[0].LastSuccess.Equal(at) || s.View().Freshness(p.ID, at.Add(37*time.Hour)) != "stale" {
		t.Fatal("failed poll lost or renewed snapshot")
	}
	if refreshDue(p, s.View().Sources, at.Add(25*time.Hour)) {
		t.Fatal("restart bypassed persisted failed-attempt interval")
	}
	f.Complete = false
	status = http.StatusOK
	if _, err = LoadElisteka(context.Background(), client, ElistekaFeedURL); err == nil {
		t.Fatal("incomplete remote snapshot accepted")
	}
}

type elistekaTransport func(*http.Request) (*http.Response, error)

func (f elistekaTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestElistekaFeedValidation(t *testing.T) {
	f := elistekaSample(time.Now())
	b, _ := json.Marshal(f)
	for name, change := range map[string]func() []byte{
		"wrong envelope provider": func() []byte {
			return []byte(strings.Replace(string(b), `"provider_id":"elisteka"`, `"provider_id":"other"`, 1))
		},
		"wrong offer provider": func() []byte {
			f := elistekaSample(time.Now())
			f.Offers[0].ProviderID = "other"
			out, _ := json.Marshal(f)
			return out
		},
		"missing observation": func() []byte {
			f := elistekaSample(time.Now())
			f.Offers[0].ObservedAt = time.Time{}
			out, _ := json.Marshal(f)
			return out
		},
		"unknown field": func() []byte { return append([]byte(`{"extra":true,`), b[1:]...) },
		"trailing JSON": func() []byte { return append(append([]byte{}, b...), []byte(` {}`)...) },
		"oversize":      func() []byte { return []byte(strings.Repeat(" ", maxBody+1)) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseFeed(change(), "elisteka"); err == nil {
				t.Fatal("invalid feed accepted")
			}
		})
	}
}

func TestElistekaRefreshSchedule(t *testing.T) {
	p := elistekaProvider(t)
	day := time.Date(2026, 11, 26, 4, 5, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		now  time.Time
		last *time.Time
		due  bool
	}{
		{"first start before slot", day.Add(-time.Second), nil, false},
		{"first start at slot", day, nil, true},
		{"first start late", day.Add(12 * time.Hour), nil, true},
		{"already attempted", day.Add(time.Hour), &day, false},
		{"next day before slot", day.Add(24*time.Hour - time.Second), &day, false},
		{"next day", day.Add(24 * time.Hour), &day, true},
		{"timezone independent", day.In(time.FixedZone("UTC+7", 7*3600)), nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sources := []catalog.Source{{ProviderID: p.ID, LastAttempt: tc.last, Error: "failed attempt"}}
			if got := refreshDue(p, sources, tc.now); got != tc.due {
				t.Fatalf("got due=%v want %v", got, tc.due)
			}
		})
	}
	late := day.Add(12 * time.Hour)
	if refreshDue(p, []catalog.Source{{ProviderID: p.ID, LastAttempt: &late}}, day.Add(24*time.Hour)) {
		t.Fatal("polled twice within 24 hours")
	}
}

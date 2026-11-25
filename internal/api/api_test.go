package api

import (
	"encoding/json"
	"fmt"
	"github.com/subregator/subregator-backend/internal/catalog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

func store(t testing.TB, n int) *catalog.Store {
	t.Helper()
	p := catalog.Provider{ID: "test", Name: "Test", URL: "https://example.com", Policy: catalog.Policy{Publication: "approved", PrefixVisibility: "full", MinRefreshSeconds: 60}}
	s, e := catalog.NewStore("", []catalog.Provider{p})
	if e != nil {
		t.Fatal(e)
	}
	offers := make([]catalog.Offer, 0, n)
	for i := 0; i < n; i++ {
		prefix := fmt.Sprintf("10.%d.%d.0/24", (i/256)%256, i%256)
		offers = append(offers, catalog.Offer{ExternalID: strconv.Itoa(i), ProviderID: "test", Model: "lease", Availability: "available", Resource: catalog.Resource{Family: 4, Prefix: &prefix, PrefixLength: 24, RIR: "RIPE NCC"}, Geography: catalog.Geography{Country: "DE", Basis: "provider_geolocation"}, Quotes: []catalog.Quote{{ID: "monthly", Price: &catalog.Money{Currency: "USD", AmountMinor: int64(i + 100), MinorUnit: 2}, BillingMonths: 1, Taxes: "unknown"}, {ID: "annual", Price: &catalog.Money{Currency: "USD", AmountMinor: int64(i+100) * 10, MinorUnit: 2}, BillingMonths: 12, Taxes: "unknown"}}, URL: "https://example.com/offers/" + strconv.Itoa(i)})
	}
	if e = s.Apply("test", offers, nil, time.Now()); e != nil {
		t.Fatal(e)
	}
	return s
}
func query(t testing.TB, raw string) Query {
	t.Helper()
	v, e := url.ParseQuery(raw)
	if e != nil {
		t.Fatal(e)
	}
	q, e := ParseQuery(v)
	if e != nil {
		t.Fatal(e)
	}
	return q
}
func TestQueryValidation(t *testing.T) {
	for _, raw := range []string{"unknown=1", "limit=0", "limit=201", "family=5", "limit=1&limit=2", "max_price_minor=1", "currency=USD&max_price_minor=-1", "sort=price_asc", "within=bad", "fresh_only=yes", "country=DEU", "min_prefix=25&max_prefix=24", "billing_months=0", "model=other", "availability=maybe", "rir=ASIA"} {
		v, _ := url.ParseQuery(raw)
		if _, e := ParseQuery(v); e == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
func TestSearchPricesAndPagination(t *testing.T) {
	s := store(t, 20)
	r := Search(s.View(), query(t, "currency=USD&sort=price_asc&limit=3"), time.Now())
	if r.Total != 20 || len(r.Items) != 3 || r.NextOffset == nil || *r.NextOffset != 3 {
		t.Fatal(r)
	}
	if r.Items[0].ExternalID != "0" {
		t.Fatal("wrong price order")
	}
	r = Search(s.View(), query(t, "currency=USD&billing_months=1&max_price_minor=101"), time.Now())
	if r.Total != 2 {
		t.Fatal("price limit", r.Total)
	}
	r = Search(s.View(), query(t, "currency=EUR"), time.Now())
	if r.Total != 0 {
		t.Fatal("mixed currencies")
	}
	r = Search(s.View(), query(t, "within=10.0.0.0/23"), time.Now())
	if r.Total != 2 {
		t.Fatal("CIDR containment", r.Total)
	}
	r = Search(s.View(), query(t, "offset=100"), time.Now())
	if len(r.Items) != 0 || r.NextOffset != nil {
		t.Fatal("out of range page")
	}
	first := Search(s.View(), query(t, "sort=price_desc&currency=USD&limit=5"), time.Now())
	second := Search(s.View(), query(t, "sort=price_desc&currency=USD&limit=5&offset=5"), time.Now())
	seen := map[string]bool{}
	for _, x := range append(first.Items, second.Items...) {
		if seen[x.ID] {
			t.Fatal("duplicate page item")
		}
		seen[x.ID] = true
	}
}
func TestMonthlyPrecisionAndSellerCountry(t *testing.T) {
	s := store(t, 1)
	o := s.View().Offers[0]
	o.Quotes = []catalog.Quote{{ID: "quarter", Price: &catalog.Money{Currency: "USD", AmountMinor: 100, MinorUnit: 2}, BillingMonths: 3, Taxes: "unknown"}}
	o.Geography.Basis = "seller_country"
	if e := s.Apply("test", []catalog.Offer{o}, nil, time.Now()); e != nil {
		t.Fatal(e)
	}
	if r := Search(s.View(), query(t, "country=DE"), time.Now()); r.Total != 0 {
		t.Fatal("seller location confused with geolocation")
	}
	if r := Search(s.View(), query(t, "country=DE&geography_basis=seller_country"), time.Now()); r.Total != 1 {
		t.Fatal("explicit seller country missing")
	}
	if r := Search(s.View(), query(t, "currency=USD&max_price_minor=33"), time.Now()); r.Total != 0 {
		t.Fatal("monthly price rounded down")
	}
	if r := Search(s.View(), query(t, "currency=USD&max_price_minor=34"), time.Now()); r.Total != 1 {
		t.Fatal("exact rational price missing")
	}
}
func TestHTTPContract(t *testing.T) {
	s := store(t, 3)
	h := Handler(s, "https://frontend.example.com")
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	for _, path := range []string{"/", "/healthz", "/readyz", "/api/v1/providers", "/openapi.json", "/api/v1/offers"} {
		if w := get(path); w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	for path, status := range map[string]int{"/missing": 404, "/api/v1/offers/bad": 404, "/api/v1/offers?provider=missing": 400, "/api/v1/offers?snapshot=old": 409, "/api/v1/offers?sort=price_asc": 400} {
		if w := get(path); w.Code != status {
			t.Fatal(path, w.Code)
		}
	}
	list := get("/api/v1/offers")
	var r Result
	if e := json.Unmarshal(list.Body.Bytes(), &r); e != nil {
		t.Fatal(e)
	}
	if w := get("/api/v1/offers/" + r.Items[0].ID); w.Code != 200 {
		t.Fatal(w.Code)
	}
	request := httptest.NewRequest("GET", "/api/v1/offers", nil)
	request.Header.Set("If-None-Match", list.Header().Get("ETag"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code != 304 || w.Body.Len() != 0 {
		t.Fatal("ETag", w.Code)
	}
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, "/api/v1/offers", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatal("write route exposed", method, w.Code)
		}
	}
	request = httptest.NewRequest("GET", "/api/v1/providers", nil)
	request.Header.Set("Origin", "https://frontend.example.com")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Header().Get("Access-Control-Allow-Origin") != "https://frontend.example.com" {
		t.Fatal("CORS missing")
	}
	request.Header.Set("Origin", "https://other.example.com")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS too broad")
	}
}
func TestConcurrentRefreshAndSearch(t *testing.T) {
	s := store(t, 100)
	offers := append([]catalog.Offer{}, s.View().Offers...)
	q := query(t, "currency=USD&sort=price_asc")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 25; i++ {
			if e := s.Apply("test", offers, nil, time.Now()); e != nil {
				t.Error(e)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if r := Search(s.View(), q, time.Now()); r.Total != 100 {
				t.Error("partial snapshot observed")
			}
		}
	}()
	wg.Wait()
}
func BenchmarkSearch10000(b *testing.B) {
	s := store(b, 10000)
	q := query(b, "country=DE&currency=USD&sort=price_asc&limit=50")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Search(s.View(), q, time.Now())
	}
}
func BenchmarkHTTP10000(b *testing.B) {
	s := store(b, 10000)
	h := Handler(s, "")
	r := httptest.NewRequest("GET", "/api/v1/offers?country=DE&currency=USD&sort=price_asc&limit=50", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
}

func TestLargePriceComparison(t *testing.T) {
	s := store(t, 2)
	offers := append([]catalog.Offer{}, s.View().Offers...)
	offers[0].ExternalID = "expensive"
	offers[1].ExternalID = "cheaper"
	offers[0].Quotes = []catalog.Quote{{ID: "long", Price: &catalog.Money{Currency: "USD", AmountMinor: 1_000_000_000_000, MinorUnit: 6}, BillingMonths: 1200, Taxes: "unknown"}}
	offers[1].Quotes = []catalog.Quote{{ID: "long", Price: &catalog.Money{Currency: "USD", AmountMinor: 999_999_999_999, MinorUnit: 6}, BillingMonths: 1200, Taxes: "unknown"}}
	if e := s.Apply("test", offers, nil, time.Now()); e != nil {
		t.Fatal(e)
	}
	r := Search(s.View(), query(t, "currency=USD&sort=price_asc"), time.Now())
	if r.Items[0].ExternalID != "cheaper" {
		t.Fatal("overflow or precision loss in price ordering")
	}
}
func TestResponseSchemaCoversPublicFields(t *testing.T) {
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if e := json.Unmarshal(openAPI, &doc); e != nil {
		t.Fatal(e)
	}
	r := Search(store(t, 1).View(), query(t, ""), time.Now())
	b, _ := json.Marshal(r.Items[0])
	var fields map[string]any
	json.Unmarshal(b, &fields)
	for key := range fields {
		if _, ok := doc.Components.Schemas["Item"].Properties[key]; !ok {
			t.Errorf("public response property %q missing from Item schema", key)
		}
	}
}

func TestOldFeedCannotBecomeFreshByReloading(t *testing.T) {
	s := store(t, 1)
	o := s.View().Offers[0]
	o.ObservedAt = time.Now().Add(-time.Hour)
	if e := s.Apply("test", []catalog.Offer{o}, nil, time.Now()); e != nil {
		t.Fatal(e)
	}
	r := Search(s.View(), query(t, ""), time.Now())
	if r.Items[0].Freshness != "stale" {
		t.Fatal("old observation advertised as fresh")
	}
	if r := Search(s.View(), query(t, "fresh_only=true"), time.Now()); r.Total != 0 {
		t.Fatal("stale observation matched fresh filter")
	}
	h := Handler(s, "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/offers/"+s.View().Offers[0].ID, nil))
	var item Item
	json.Unmarshal(w.Body.Bytes(), &item)
	if item.Freshness != "stale" {
		t.Fatal("detail freshness differs from search")
	}
}

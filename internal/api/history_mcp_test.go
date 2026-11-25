package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/subregator/subregator-backend/internal/testdb"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/history"
	"github.com/subregator/subregator-backend/internal/intelligence"
)

func historicalHandler(t *testing.T) (http.Handler, *catalog.Store, *history.DB) {
	t.Helper()
	s := store(t, 2)
	d, e := history.Open(testdb.URL(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.Close() })
	v := s.View()
	if e = d.Save(catalog.State{Version: 1, Offers: v.Offers, Sources: v.Sources}, "", time.Now(), true); e != nil {
		t.Fatal(e)
	}
	return Handler(s, "", Services{History: d, Intelligence: intelligence.New(d, false, "", 120)}), s, d
}
func TestHistoryRESTFiltersAndLifecycle(t *testing.T) {
	h, s, d := historicalHandler(t)
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	for _, path := range []string{"/api/v1/history?limit=1", "/api/v1/resources", "/api/v1/listings/" + s.View().Offers[0].ID, "/api/v1/network/checks", "/api/v1/network?resource=1.1.1.1&checks=registration"} {
		if w := get(path); w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/api/v1/history?resource=bad", "/api/v1/history?limit=201", "/api/v1/history?type=owner_changed", "/api/v1/history?after_id=-1", "/api/v1/resources?resource=bad", "/api/v1/history?unknown=1", "/api/v1/network?resource=127.0.0.1", "/api/v1/network?resource=1.1.1.1&checks=paid_score", "/api/v1/network?resource=1.1.1.1&asn=bad"} {
		if w := get(path); w.Code != 400 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	id := s.View().Offers[0].ID
	if e := d.Save(catalog.State{Version: 1, Offers: []catalog.Offer{}, Sources: []catalog.Source{}}, "test", time.Now(), true); e != nil {
		t.Fatal(e)
	}
	w := get("/api/v1/listings/" + id)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"active":false`) {
		t.Fatal("removed listing unavailable", w.Body.String())
	}
}
func TestCurrentPolicyProtectsHistoricalPrefixes(t *testing.T) {
	_, old, d := historicalHandler(t)
	p := old.View().Providers[0]
	p.Policy.PrefixVisibility = "hidden"
	current, e := catalog.NewStore("", []catalog.Provider{p})
	if e != nil {
		t.Fatal(e)
	}
	h := Handler(current, "", Services{History: d})
	for _, path := range []string{"/api/v1/history", "/api/v1/listings/" + old.View().Offers[0].ID} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "10.0.") {
			t.Fatal("historical prefix disclosed under new policy")
		}
	}
	for _, path := range []string{"/api/v1/history?resource=10.0.0.0/24", "/api/v1/resources"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		var result struct {
			Items []any `json:"items"`
		}
		json.Unmarshal(w.Body.Bytes(), &result)
		if len(result.Items) != 0 {
			t.Fatal("hidden provider correlation leaked", w.Body.String())
		}
	}
}
func TestMCPStreamableHTTPParity(t *testing.T) {
	handler, s, _ := historicalHandler(t)
	server := httptest.NewServer(handler)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "integration-client", Version: "1.0.0"}, nil)
	session, e := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	tools, e := session.ListTools(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	names := map[string]bool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = true
	}
	for _, name := range []string{"search_offers", "get_offer", "list_providers", "get_listing", "listing_history", "known_resources", "inspect_network", "network_checks", "get_api_schema"} {
		if !names[name] {
			t.Fatal("tool missing", name)
		}
	}
	filters := map[string]string{"currency": "USD", "sort": "price_asc", "limit": "1"}
	result, e := session.CallTool(ctx, &mcp.CallToolParams{Name: "search_offers", Arguments: map[string]any{"filters": filters}})
	if e != nil || result.IsError {
		t.Fatal(e, result)
	}
	encoded, e := json.Marshal(result.StructuredContent)
	if e != nil {
		t.Fatal(e)
	}
	var actual Result
	if e = json.Unmarshal(encoded, &actual); e != nil {
		t.Fatal(e)
	}
	v := url.Values{}
	for k, x := range filters {
		v.Set(k, x)
	}
	q, e := ParseQuery(v)
	if e != nil {
		t.Fatal(e)
	}
	expected := Search(s.View(), q, time.Now())
	if actual.Total != expected.Total || len(actual.Items) != 1 || actual.Items[0].ID != expected.Items[0].ID {
		t.Fatal("MCP/REST search differ")
	}
	for _, call := range []mcp.CallToolParams{{Name: "listing_history", Arguments: map[string]any{}}, {Name: "known_resources", Arguments: map[string]any{}}, {Name: "get_listing", Arguments: map[string]any{"id": s.View().Offers[0].ID}}, {Name: "inspect_network", Arguments: map[string]any{"resource": "1.1.1.1", "checks": []string{"registration"}}}} {
		r, e := session.CallTool(ctx, &call)
		if e != nil || r.IsError {
			t.Fatal(call.Name, e, r)
		}
	}
	bad, e := session.CallTool(ctx, &mcp.CallToolParams{Name: "search_offers", Arguments: map[string]any{"filters": map[string]string{"limit": "10000"}}})
	if e != nil || !bad.IsError {
		t.Fatal("invalid MCP filter accepted", e)
	}
}
func TestMCPOriginAndBodyBounds(t *testing.T) {
	handler, _, _ := historicalHandler(t)
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{}`))
	r.Header.Set("Origin", "https://untrusted.example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("untrusted MCP origin accepted", w.Code)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	r, _ = http.NewRequest("POST", server.URL+"/mcp", strings.NewReader(strings.Repeat("x", (1<<20)+1)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	response, e := server.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 413 {
		t.Fatal("MCP body limit ignored", response.StatusCode)
	}
}

func TestResourceCountsRespectProviderFilterAndListingPresence(t *testing.T) {
	source := store(t, 1)
	a := source.View().Providers[0]
	b := a
	b.ID = "other"
	b.Name = "Other"
	database, e := history.Open(testdb.URL(t))
	if e != nil {
		t.Fatal(e)
	}
	defer database.Close()
	current, e := catalog.NewPersistentStore(database, "", []catalog.Provider{a, b})
	if e != nil {
		t.Fatal(e)
	}
	offerA := source.View().Offers[0]
	offerB := offerA
	offerB.ProviderID = "other"
	at := time.Now().UTC()
	for id, offer := range map[string]catalog.Offer{a.ID: offerA, b.ID: offerB} {
		if e = current.Apply(id, []catalog.Offer{offer}, nil, at); e != nil {
			t.Fatal(e)
		}
	}
	handler := Handler(current, "", Services{History: database})
	count := func() int {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/resources?provider="+a.ID, nil))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var result history.ResourceResult
		if e = json.Unmarshal(w.Body.Bytes(), &result); e != nil {
			t.Fatal(e)
		}
		if len(result.Items) != 1 || len(result.Items[0].ProviderIDs) != 1 || result.Items[0].ProviderIDs[0] != a.ID {
			t.Fatal("provider scope differs", result)
		}
		return result.Items[0].ActiveOffers
	}
	if e = current.Apply(a.ID, nil, nil, at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if n := count(); n != 0 {
		t.Errorf("other provider's active offer leaked into filtered count: %d", n)
	}
	offerA.Availability = "waitlist"
	if e = current.Apply(a.ID, []catalog.Offer{offerA}, nil, at.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	if e = current.Apply(b.ID, nil, nil, at.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	if n := count(); n != 1 {
		t.Errorf("current waitlisted listing excluded from active count: %d", n)
	}
}

func TestMCPRejectsLegacyBatches(t *testing.T) {
	h, _, _ := historicalHandler(t)
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(" \n["+`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"batch-test","version":"1"}}}`+"]"))
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("MCP-Protocol-Version", "2025-03-26")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("legacy batch bypasses one-request admission: status=%d body=%s", w.Code, w.Body.String())
	}
}

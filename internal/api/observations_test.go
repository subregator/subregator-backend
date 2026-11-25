package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/history"
	"github.com/subregator/subregator-backend/internal/intelligence"
)

func TestNetworkHistoryRESTMCPAndPublication(t *testing.T) {
	_, store, d := historicalHandler(t)
	prefix := "1.1.1.0/24"
	offer := store.View().Offers[0]
	offer.Resource.Prefix = &prefix
	if err := d.Save(catalog.State{Version: 1, Offers: []catalog.Offer{offer}}, "", time.Now(), true); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Minute)
	expires := at.Add(time.Hour)
	record := intelligence.ArchivedObservation{Resource: prefix, Check: "prefix_overview", Source: "fixture", ObservedAt: &at, IngestedAt: time.Now().UTC(), ExpiresAt: &expires, Observation: intelligence.Observation{CollectionStatus: "succeeded", Freshness: "fresh", Completeness: "complete", Scope: intelligence.ObservationScope{Resource: prefix, Requested: prefix, Kind: "prefix", Relation: "exact"}}, Evidence: json.RawMessage(`{"origins":[13335]}`), State: json.RawMessage(`{"origins":[13335]}`), Comparable: true}
	if err := d.SaveObservation(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	checks := intelligence.New(d, false, "", 120)
	if err := checks.SetHistoryChecks("prefix_overview"); err != nil {
		t.Fatal(err)
	}
	other := record
	other.Check = "rdap"
	if err := d.SaveObservation(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	h := Handler(store, "", Services{History: d, Intelligence: checks})
	request := func(h http.Handler, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	w := request(h, "/api/v1/network/history?resource="+prefix)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var expected history.ObservationResult
	if err := json.Unmarshal(w.Body.Bytes(), &expected); err != nil || len(expected.Items) != 1 {
		t.Fatal(err, w.Body.String())
	}
	server := httptest.NewServer(h)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "history-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "network_history", Arguments: map[string]any{"filters": map[string]string{"resource": prefix}}})
	if err != nil || result.IsError {
		t.Fatal(err, result)
	}
	encoded, _ := json.Marshal(result.StructuredContent)
	var actual history.ObservationResult
	if err = json.Unmarshal(encoded, &actual); err != nil || len(actual.Items) != 1 || actual.Items[0].Identity != expected.Items[0].Identity {
		t.Fatal(err, string(encoded))
	}
	for _, query := range []string{"", "?resource=127.0.0.0/24", "?resource=" + prefix + "&after_id=-1", "?resource=" + prefix + "&limit=201", "?resource=" + prefix + "&resource=" + prefix, "?resource=" + prefix + "&check=abuse"} {
		if w := request(h, "/api/v1/network/history"+query); w.Code != 400 {
			t.Fatal(query, w.Code, w.Body.String())
		}
	}
	if err := checks.SetHistoryChecks(""); err != nil {
		t.Fatal(err)
	}
	if w := request(h, "/api/v1/network/history?resource="+prefix); w.Code != 200 || strings.Contains(w.Body.String(), "13335") {
		t.Fatal("disabled archive published", w.Body.String())
	}
	if err := checks.SetHistoryChecks("prefix_overview"); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []string{"hidden", "pending", "peaktera"} {
		provider := store.View().Providers[0]
		switch policy {
		case "hidden":
			provider.Policy.PrefixVisibility = "hidden"
		case "pending":
			provider.Policy.Publication = "pending"
		case "peaktera":
			provider.ID = "peaktera"
			provider.Policy.MinRefreshSeconds = 900
		}
		current, err := catalog.NewStore("", []catalog.Provider{provider})
		if err != nil {
			t.Fatal(err)
		}
		private := Handler(current, "", Services{History: d, Intelligence: checks})
		w := request(private, "/api/v1/network/history?resource="+prefix)
		if w.Code != 200 || strings.Contains(w.Body.String(), "13335") || strings.Contains(w.Body.String(), prefix) {
			t.Fatal("history disclosed", policy, w.Code, w.Body.String())
		}
	}
	if w := request(h, "/api/v1/network/history?resource=8.8.8.0/24"); w.Code != 200 || strings.Contains(w.Body.String(), "13335") {
		t.Fatal(w.Code, w.Body.String())
	}
}

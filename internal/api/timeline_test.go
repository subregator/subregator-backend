package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/history"
	"github.com/subregator/subregator-backend/internal/intelligence"
	"strings"
)

func TestResourceTimelineRESTMCPAndValidation(t *testing.T) {
	h, s, d := historicalHandler(t)
	prefix := "1.1.1.0/24"
	offer := s.View().Offers[0]
	offer.Resource.Prefix = &prefix
	if err := d.Save(catalog.State{Version: 1, Offers: []catalog.Offer{offer}}, "", time.Now(), true); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/timeline?resource=" + prefix
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var expected history.TimelineResult
	if err := json.Unmarshal(w.Body.Bytes(), &expected); err != nil || len(expected.Items) == 0 {
		t.Fatal(err, w.Body.String())
	}
	validateOpenAPI(t, "TimelineResult", expected)
	for _, policy := range []string{"hidden", "pending", "peaktera"} {
		provider := s.View().Providers[0]
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
		private := Handler(current, "", Services{History: d})
		w := httptest.NewRecorder()
		private.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || strings.Contains(w.Body.String(), prefix) || strings.Contains(w.Body.String(), offer.ID) {
			t.Fatal(policy, w.Code, w.Body.String())
		}
	}
	server := httptest.NewServer(h)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "timeline-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "resource_timeline", Arguments: map[string]any{"filters": map[string]string{"resource": prefix}}})
	if err != nil || result.IsError {
		t.Fatal(err, result)
	}
	encoded, _ := json.Marshal(result.StructuredContent)
	var actual history.TimelineResult
	if err = json.Unmarshal(encoded, &actual); err != nil || len(actual.Items) != len(expected.Items) || actual.Items[0].ID != expected.Items[0].ID {
		t.Fatal(err, string(encoded))
	}
	for _, query := range []string{"", "?resource=127.0.0.0/24", "?resource=" + prefix + "&limit=201", "?resource=" + prefix + "&cursor=bad", "?resource=" + prefix + "&resource=" + prefix} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/timeline"+query, nil))
		if w.Code != 400 {
			t.Fatal(query, w.Code, w.Body.String())
		}
	}
}

func TestImportedHistorySchema(t *testing.T) {
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	r := intelligence.ArchivedObservation{ID: 1, Identity: "fixture", Resource: "1.1.1.0/24", Check: "routing_history", Source: "RIPEstat", ObservedAt: &now, AttemptedAt: now, IngestedAt: now, ExpiresAt: &expires, Origin: "imported_history", Event: "historical_snapshot", Gap: true, Observation: intelligence.Observation{CollectionStatus: "succeeded", Freshness: "fresh", Completeness: "partial", Scope: intelligence.ObservationScope{Requested: "1.1.1.0/24", Kind: "prefix", Relation: "source_records"}}, Evidence: json.RawMessage(`{"requested":"1.1.1.0/24","records":[],"record_limit":300,"truncated":false,"completeness":"partial","dropped_records":0,"coverage":"RIS source coverage"}`)}
	validateOpenAPI(t, "ArchivedObservation", r)
	validateOpenAPI(t, "ObservationHistoryResult", history.ObservationResult{Items: []intelligence.ArchivedObservation{r}, Semantics: "source observations"})
}

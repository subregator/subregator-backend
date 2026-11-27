package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/subregator/subregator-backend/internal/intelligence"
)

type checkTransport func(*http.Request) (*http.Response, error)

func (f checkTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestPublicChecksNeverTriggerUpstreams(t *testing.T) {
	var calls atomic.Int32
	old := http.DefaultTransport
	http.DefaultTransport = checkTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":"ok","data":{}}`)), Header: make(http.Header)}, nil
	})
	defer func() { http.DefaultTransport = old }()
	s := &service{store: store(t, 1), extras: Services{Intelligence: intelligence.New(nil, true, "", 120)}}
	report, e := s.inspect(context.Background(), intelligence.Query{Resource: "1.1.1.0/24", Checks: []string{"asn_relationships", "announced_prefixes"}})
	if e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 0 {
		t.Fatalf("public lookup triggered %d upstream requests", calls.Load())
	}
	if len(report.Metrics) != 2 || report.Metrics[0].Status != "pending" {
		t.Fatalf("missing observation must remain pending: %+v", report)
	}
	h := Handler(s.store, "", s.extras)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/network?resource=1.1.1.0/24&checks=asn_relationships,announced_prefixes", nil))
	if rr.Code != 200 || calls.Load() != 0 {
		t.Fatalf("REST triggered upstream or failed: %d", rr.Code)
	}
	var body map[string]any
	if json.Unmarshal(rr.Body.Bytes(), &body) != nil {
		t.Fatal("invalid response")
	}
}

func TestOffersIncludePendingChecksWithoutUpstreamOrStorage(t *testing.T) {
	s := store(t, 2)
	h := Handler(s, "", Services{Automatic: intelligence.NewAutomatic(intelligence.New(nil, true, "", 120))})
	for _, path := range []string{"/api/v1/offers", "/api/v1/offers/" + s.View().Offers[0].ID} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"status":"pending"`) || !strings.Contains(rr.Body.String(), `"checks":`) {
			t.Fatalf("missing explicit pending checks: %d %s", rr.Code, rr.Body.String())
		}
	}
}

func TestNetworkMetricSchemaIncludesPending(t *testing.T) {
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Enum []json.RawMessage `json:"enum"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openAPI, &doc); err != nil {
		t.Fatal(err)
	}
	for _, status := range doc.Components.Schemas["NetworkMetric"].Properties["status"].Enum {
		if string(status) == `"pending"` {
			return
		}
	}
	t.Fatal("public pending metric is missing from OpenAPI")
}

func TestNetworkCollectionStatusColdStart(t *testing.T) {
	s := store(t, 1)
	offers := s.View().Offers
	prefix := "1.1.1.0/24"
	offers[0].Resource.Prefix = &prefix
	if err := s.Apply("test", offers, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	h := Handler(s, "", Services{Automatic: intelligence.NewAutomatic(intelligence.New(nil, true, "", 120))})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/network/status", nil))
	if w.Code != 200 {
		t.Fatalf("collection status unavailable: %d %s", w.Code, w.Body.String())
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result["checks"] == nil || result["upstreams"] == nil || result["work"] == nil {
		t.Fatalf("missing bounded coverage and upstream counters: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "10.0.") {
		t.Fatal("status disclosed per-prefix identifiers")
	}
	var status intelligence.CollectionStatus
	json.Unmarshal(w.Body.Bytes(), &status)
	if status.EligiblePrefixes != 1 || status.Checks[0].Collection["pending"] != 1 || len(status.Upstreams) != 0 {
		t.Fatalf("wrong cold coverage: %+v", status)
	}
	missing := httptest.NewRecorder()
	Handler(s, "").ServeHTTP(missing, httptest.NewRequest("GET", "/api/v1/network/status", nil))
	if missing.Code != 503 {
		t.Fatalf("unconfigured collector should be unavailable: %d", missing.Code)
	}
}

func TestNetworkCollectionStatusMCP(t *testing.T) {
	s := store(t, 1)
	server := httptest.NewServer(Handler(s, "", Services{Automatic: intelligence.NewAutomatic(intelligence.New(nil, false, "", 120))}))
	defer server.Close()
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "network_status", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatal(err, result)
	}
	b, _ := json.Marshal(result.StructuredContent)
	var status intelligence.CollectionStatus
	if json.Unmarshal(b, &status) != nil || status.Work == nil || len(status.Checks) != 9 || status.Semantics != "process_local_collection_health_not_subnet_safety" {
		t.Fatalf("wrong MCP collection status: %s", b)
	}
}

func TestObservationAndCollectionOpenAPIContracts(t *testing.T) {
	s := intelligence.New(nil, false, "", 120)
	a := intelligence.NewAutomatic(s)
	report, err := s.Cached(context.Background(), intelligence.Query{Resource: "2001:4860:4860::/48", Checks: []string{"registration", "ipinfo_lite"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"NetworkReport", report},
		{"OfferChecks", a.Get("1.1.1.0/24")},
		{"CollectionStatus", a.Status(store(t, 1))},
		{"ChecksResult", map[string]any{"items": intelligence.Capabilities()}},
	} {
		validateOpenAPI(t, tc.name, tc.value)
	}
}

func validateOpenAPI(t *testing.T, name string, instance any) {
	t.Helper()
	var doc struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openAPI, &doc); err != nil {
		t.Fatal(err)
	}
	root, _ := json.Marshal(map[string]any{"$ref": "#/$defs/" + name, "$defs": doc.Components.Schemas})
	root = []byte(strings.ReplaceAll(string(root), "#/components/schemas/", "#/$defs/"))
	var schema jsonschema.Schema
	if err := json.Unmarshal(root, &schema); err != nil {
		t.Fatal(err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(instance)
	var value any
	json.Unmarshal(payload, &value)
	if err := resolved.Validate(value); err != nil {
		t.Fatalf("%s response violates OpenAPI: %v", name, err)
	}
}

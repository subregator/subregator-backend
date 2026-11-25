package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/subregator/subregator-backend/internal/history"
	"github.com/subregator/subregator-backend/internal/intelligence"
	"github.com/subregator/subregator-backend/internal/testdb"
)

func TestZENRESTMCPPostgresRestartAndGate(t *testing.T) {
	ctx := context.Background()
	dsn := testdb.URL(t)
	d, err := history.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	expires := now.Add(24 * time.Hour)
	detail := intelligence.BlocklistObservation{Requested: "1.1.1.0/24", Address: "1.1.1.0", Status: "listed", Completeness: "partial", ScopeRelation: "contained", Selection: "prefix_first_address", Semantics: "source_scoped_lists_not_safety_ownership_or_tenant_attribution", Findings: []intelligence.ListFinding{{List: "SBL", Status: "not_listed", Codes: []int{}, Reason: "SBL"}, {List: "XBL", Status: "listed", Codes: []int{1004}, Reason: "XBL"}, {List: "PBL", Status: "not_listed", Codes: []int{}, Reason: "Mail policy"}}}
	raw, _ := json.Marshal(detail)
	metric := intelligence.Metric{Name: "spamhaus_zen", Status: "ok", Source: "Spamhaus ZEN", SourceURL: "https://apibl.spamhaus.net/lookup/v1/ZEN/1.1.1.0", ObservedAt: &now, ExpiresAt: &expires, Data: raw}
	b, _ := json.Marshal(metric)
	key := `{"Resource":"1.1.1.0/24","Name":"spamhaus_zen","Start":"","End":"","Version":"","ASN":0}`
	if err := d.CachePut(ctx, key, b, expires); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = history.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	checks := intelligence.New(d, false, "", 120)
	checks.EnableSpamhaus("fixture-key")
	h := Handler(store(t, 1), "", Services{Intelligence: checks})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/network?resource=1.1.1.0%2F24&checks=spamhaus_zen", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rest intelligence.Report
	json.Unmarshal(w.Body.Bytes(), &rest)
	if !rest.Partial || rest.Metrics[0].Blocklists == nil || rest.Metrics[0].Blocklists.Findings[1].Status != "listed" || rest.Metrics[0].Observation.Completeness != "partial" {
		t.Fatal("restart lost source scope", rest)
	}

	validateOpenAPI(t, "NetworkReport", rest)
	saved := intelligence.NewAutomatic(checks).Get(detail.Requested)
	saved.ZEN = &intelligence.Check{Status: "listed", Freshness: "fresh", Source: "Spamhaus ZEN", ObservedAt: &now, ExpiresAt: &expires, Blocklists: rest.Metrics[0].Blocklists, Observation: rest.Metrics[0].Observation}

	payload, _ := json.Marshal(saved)
	if err := d.CachePut(ctx, "automatic:"+detail.Requested, payload, expires); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = history.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	persisted, _, found, err := d.CacheGet(ctx, "automatic:"+detail.Requested)
	var report intelligence.OfferChecks
	if err != nil || !found || json.Unmarshal(persisted, &report) != nil || report.ZEN == nil || report.ZEN.Blocklists.Findings[1].Status != "listed" {
		t.Fatal("normalized report lost", err)
	}
	validateOpenAPI(t, "OfferChecks", report)
	checks = intelligence.New(d, false, "", 120)
	checks.EnableSpamhaus("fixture-key")
	h = Handler(store(t, 1), "", Services{Intelligence: checks})
	server := httptest.NewServer(h)
	defer server.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "inspect_network", Arguments: map[string]any{"resource": detail.Requested, "checks": []string{"spamhaus_zen"}}})
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	actual, _ := json.Marshal(result.StructuredContent)
	var left, right any
	json.Unmarshal(actual, &left)
	json.Unmarshal(w.Body.Bytes(), &right)
	if !reflect.DeepEqual(left, right) {
		t.Fatal("REST/MCP observations differ")
	}
	closed := Handler(store(t, 1), "", Services{Intelligence: intelligence.New(d, true, "", 120)})
	w = httptest.NewRecorder()
	closed.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/network?resource=1.1.1.0%2F24&checks=spamhaus_zen", nil))
	var gated intelligence.Report
	json.Unmarshal(w.Body.Bytes(), &gated)
	if gated.Metrics[0].Status != "not_configured" || gated.Metrics[0].Blocklists != nil || string(gated.Metrics[0].Data) != "null" {
		t.Fatal("closed gate exposed cached data")
	}
	validateOpenAPI(t, "NetworkReport", gated)
}

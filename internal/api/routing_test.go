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

func TestCachedRoutingRESTMCPAndPostgresRestart(t *testing.T) {
	ctx := context.Background()
	dsn := testdb.URL(t)
	d, err := history.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	now, expires := time.Now().UTC(), time.Now().UTC().Add(time.Hour)
	for name, data := range map[string]string{
		"routing_status":  `{"resource":"1.1.1.0/24","query_time":"2026-01-01T00:00:00","visibility":{"v4":{"ris_peers_seeing":12,"total_ris_peers":20}}}`,
		"prefix_overview": `{"resource":"1.1.1.0/24","announced":true,"is_less_specific":false,"num_filtered_out":0,"asns":[{"asn":13335}]}`,
		"rpki":            `{"prefix":"1.1.1.0/24","origins":[{"asn":13335,"source_url":"https://stat.ripe.net/fixture","data":{"prefix":"1.1.1.0/24","resource":"13335","status":"invalid_length","validating_roas":[{"prefix":"1.1.0.0/16","origin":"13335","max_length":23}]}}]}`,
	} {
		m := intelligence.Metric{Name: name, Status: "ok", Source: "RIPEstat", ObservedAt: &now, ExpiresAt: &expires, Data: json.RawMessage(data)}
		b, _ := json.Marshal(m)
		key := `{"Resource":"1.1.1.0/24","Name":"` + name + `","Start":"","End":"","Version":"","ASN":0}`
		if err := d.CachePut(ctx, key, b, expires); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = history.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	h := Handler(store(t, 1), "", Services{Intelligence: intelligence.New(d, false, "", 120)})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/network?resource=1.1.1.0%2F24&checks=prefix_overview,rpki,routing_status", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rest intelligence.Report
	if err := json.Unmarshal(w.Body.Bytes(), &rest); err != nil {
		t.Fatal(err)
	}
	if rest.Partial || rest.Metrics[0].BGP == nil || rest.Metrics[0].BGP.Routing == nil || *rest.Metrics[0].BGP.Routing.PeersSeeing != 12 || rest.Metrics[1].RPKI == nil || rest.Metrics[1].RPKI.Origins[0].Status != "invalid_length" || rest.Metrics[1].RPKI.Origins[0].CoveringROAs[0].MaxLength != 23 {
		t.Fatalf("restart lost explanations: %+v", rest)
	}
	validateOpenAPI(t, "NetworkReport", rest)
	saved := intelligence.OfferChecks{Resource: rest.Resource.Value,
		BGP:       intelligence.Check{Status: "announced", Freshness: "fresh", ObservedAt: &now, ExpiresAt: &expires, Source: "RIPEstat", Observation: rest.Metrics[0].Observation, BGP: rest.Metrics[0].BGP},
		RPKI:      intelligence.Check{Status: "invalid", Freshness: "fresh", ObservedAt: &now, ExpiresAt: &expires, Source: "RIPEstat", Observation: rest.Metrics[1].Observation, RPKI: rest.Metrics[1].RPKI},
		Blocklist: intelligence.Check{Status: "pending", Freshness: "unknown", Observation: intelligence.Observation{CollectionStatus: "pending", Freshness: "unknown", Completeness: "unknown", Scope: intelligence.ObservationScope{Requested: rest.Resource.Value, Kind: "prefix", Relation: "unknown"}}}, Semantics: "source_scoped_observations_not_safety_or_reputation"}
	savedBytes, _ := json.Marshal(saved)
	if err := d.CachePut(ctx, "automatic:"+saved.Resource, savedBytes, expires); err != nil {
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
	persisted, _, found, err := d.CacheGet(ctx, "automatic:"+saved.Resource)
	var checks intelligence.OfferChecks
	if err != nil || !found || json.Unmarshal(persisted, &checks) != nil || checks.RPKI.RPKI.Origins[0].Status != "invalid_length" {
		t.Fatal("normalized report lost after restart", err)
	}
	validateOpenAPI(t, "OfferChecks", checks)
	h = Handler(store(t, 1), "", Services{Intelligence: intelligence.New(d, false, "", 120)})

	server := httptest.NewServer(h)
	defer server.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "inspect_network", Arguments: map[string]any{"resource": "1.1.1.0/24", "checks": []string{"prefix_overview", "rpki", "routing_status"}}})
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	b, _ := json.Marshal(result.StructuredContent)
	var actual intelligence.Report
	json.Unmarshal(b, &actual)
	var left, right any
	json.Unmarshal(w.Body.Bytes(), &left)
	json.Unmarshal(b, &right)
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("REST/MCP differ: %s", b)
	}
	validateOpenAPI(t, "NetworkReport", actual)
}

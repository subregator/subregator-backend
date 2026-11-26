package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/subregator/subregator-backend/internal/history"
	"github.com/subregator/subregator-backend/internal/intelligence"
	"github.com/subregator/subregator-backend/internal/testdb"
)

func TestIRRRESTMCPPostgresRestartAndGate(t *testing.T) {
	ctx := context.Background()
	dsn := testdb.URL(t)
	d, err := history.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	now, expires := time.Now().UTC(), time.Now().UTC().Add(time.Hour)
	snapshot := now.Add(-time.Hour)
	detail := intelligence.IRRExplanation{Prefix: "1.1.1.0/24", Status: "bgp_unavailable", Completeness: "complete", ObjectLimit: 200, Objects: []intelligence.IRRObject{{Class: "route", Prefix: "1.1.1.0/24", Origin: 13335, Registry: "APNIC", Relation: "exact", ID: "1.1.1.0/24AS13335"}}, Registries: []intelligence.IRRRegistry{{Name: "APNIC", UpdatedAt: &snapshot, Freshness: "fresh"}}, MissingOrigins: []uint32{}, MetadataURL: "https://github.com/subregator/subregator-backend/blob/main/docs/irr.md", MetadataObservedAt: &now}
	raw, _ := json.Marshal(detail)
	for name, data := range map[string]json.RawMessage{"irr": raw, "prefix_overview": json.RawMessage(`{"resource":"1.1.1.0/24","announced":true,"is_less_specific":false,"num_filtered_out":0,"asns":[{"asn":13335}]}`)} {
		metric := intelligence.Metric{Name: name, Status: "ok", Source: "fixture", ObservedAt: &now, ExpiresAt: &expires, Data: data}
		if name == "irr" {
			metric.Source = "IRRd"
		}
		b, _ := json.Marshal(metric)
		key := `{"Resource":"1.1.1.0/24","Name":"` + name + `","Start":"","End":"","Version":"","ASN":0}`
		if name == "irr" {
			key = strings.Replace(key, `"Version":""`, `"Version":"irrd-v1"`, 1)
		}
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
	checks := intelligence.New(d, false, "", 120)
	if err := checks.EnableIRR(intelligence.DefaultIRRdURL); err != nil {
		t.Fatal(err)
	}
	h := Handler(store(t, 1), "", Services{Intelligence: checks})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/network?resource=1.1.1.0%2F24&checks=irr", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rest intelligence.Report
	if err := json.Unmarshal(w.Body.Bytes(), &rest); err != nil {
		t.Fatal(err)
	}
	if rest.Partial || rest.Metrics[0].IRR == nil || rest.Metrics[0].IRR.Status != "consistent" || rest.Metrics[0].Observation.Scope.Relation != "overlap" {
		t.Fatalf("lost cached IRR comparison: %+v", rest)
	}
	validateOpenAPI(t, "NetworkReport", rest)
	saved := intelligence.NewAutomatic(checks).Get(rest.Resource.Value)
	saved.IRR = &intelligence.Check{Status: "consistent", Freshness: "fresh", Source: "IRRd", ObservedAt: &now, ExpiresAt: &expires, Observation: rest.Metrics[0].Observation, IRR: rest.Metrics[0].IRR}
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
	cached, _, found, err := d.CacheGet(ctx, "automatic:"+saved.Resource)
	var restored intelligence.OfferChecks
	if err != nil || !found || json.Unmarshal(cached, &restored) != nil || restored.IRR == nil || restored.IRR.IRR.Objects[0].Origin != 13335 {
		t.Fatal("normalized IRR report lost after restart", err)
	}
	validateOpenAPI(t, "OfferChecks", restored)
	checks = intelligence.New(d, false, "", 120)
	if err := checks.EnableIRR(intelligence.DefaultIRRdURL); err != nil {
		t.Fatal(err)
	}
	h = Handler(store(t, 1), "", Services{Intelligence: checks})

	server := httptest.NewServer(h)
	defer server.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "inspect_network", Arguments: map[string]any{"resource": "1.1.1.0/24", "checks": []string{"irr"}}})
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	actual, _ := json.Marshal(result.StructuredContent)
	var a, b any
	json.Unmarshal(actual, &a)
	json.Unmarshal(w.Body.Bytes(), &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("REST/MCP IRR differ")
	}
	var report intelligence.Report
	json.Unmarshal(actual, &report)
	validateOpenAPI(t, "NetworkReport", report)
	closedGate := Handler(store(t, 1), "", Services{Intelligence: intelligence.New(d, true, "", 120)})
	w = httptest.NewRecorder()
	closedGate.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/network?resource=1.1.1.0%2F24&checks=irr", nil))
	report = intelligence.Report{}
	json.Unmarshal(w.Body.Bytes(), &report)
	if report.Metrics[0].Status != "not_configured" || report.Metrics[0].IRR != nil || string(report.Metrics[0].Data) != "null" {
		t.Fatal("closed gate exposed stored IRR")
	}
	validateOpenAPI(t, "NetworkReport", report)
}

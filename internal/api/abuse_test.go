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

func TestAbuseRESTMCPPostgresRestartAndGate(t *testing.T) {
	ctx := context.Background()
	dsn := testdb.URL(t)
	d, err := history.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	expires := now.Add(24 * time.Hour)
	reported := now.Add(-time.Hour)
	detail := intelligence.AbuseObservation{Prefix: "1.1.1.0/24", Status: "reports_observed", Completeness: "complete", ScopeRelation: "exact", RangeStart: "1.1.1.0", RangeEnd: "1.1.1.255", PossibleHosts: 256, WindowDays: 30, WindowStart: now.Add(-30 * 24 * time.Hour), WindowEnd: now, WindowBasis: "local_request_bounds", IngestedAt: now, ReportedIPCount: 1, ReportCount: 3, LatestReportAt: &reported, AddressLimit: 256, Addresses: []intelligence.ReportedAddress{{Address: "1.1.1.2", Reports: 3, LatestReportAt: &reported}}, DetailsCoverage: "not_collected", Semantics: "source_reports_not_cleanliness_tenant_attribution_or_resolution"}
	raw, _ := json.Marshal(detail)
	metric := intelligence.Metric{Name: "abuse", Status: "ok", Source: "AbuseIPDB", SourceURL: "https://api.abuseipdb.com/api/v2/check-block?maxAgeInDays=30&network=1.1.1.0%2F24", ObservedAt: &now, ExpiresAt: &expires, Data: raw}
	b, _ := json.Marshal(metric)
	key := `{"Resource":"1.1.1.0/24","Name":"abuse","Start":"","End":"","Version":"","ASN":0}`
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
	checks.EnableAbuseIPDB("fixture-key")
	h := Handler(store(t, 1), "", Services{Intelligence: checks})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/network?resource=1.1.1.0%2F24&checks=abuse", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rest intelligence.Report
	json.Unmarshal(w.Body.Bytes(), &rest)
	if rest.Partial || rest.Metrics[0].Abuse == nil || rest.Metrics[0].Abuse.ReportCount != 3 || !rest.Metrics[0].Abuse.IngestedAt.Equal(now) {
		t.Fatal("restart lost abuse observation")
	}
	validateOpenAPI(t, "NetworkReport", rest)
	saved := intelligence.NewAutomatic(checks).Get(detail.Prefix)
	saved.Abuse = &intelligence.Check{Status: "reports_observed", Freshness: "fresh", Source: "AbuseIPDB", ObservedAt: &now, ExpiresAt: &expires, Abuse: rest.Metrics[0].Abuse, Observation: rest.Metrics[0].Observation}
	payload, _ := json.Marshal(saved)
	if err := d.CachePut(ctx, "automatic:"+detail.Prefix, payload, expires); err != nil {
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
	persisted, _, found, err := d.CacheGet(ctx, "automatic:"+detail.Prefix)
	var report intelligence.OfferChecks
	if err != nil || !found || json.Unmarshal(persisted, &report) != nil || report.Abuse == nil || report.Abuse.Abuse.ReportedIPCount != 1 {
		t.Fatal("normalized report lost", err)
	}
	validateOpenAPI(t, "OfferChecks", report)
	checks = intelligence.New(d, false, "", 120)
	checks.EnableAbuseIPDB("fixture-key")
	h = Handler(store(t, 1), "", Services{Intelligence: checks})
	server := httptest.NewServer(h)
	defer server.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "inspect_network", Arguments: map[string]any{"resource": detail.Prefix, "checks": []string{"abuse"}}})
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
	closed.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/network?resource=1.1.1.0%2F24&checks=abuse", nil))
	var gated intelligence.Report
	json.Unmarshal(w.Body.Bytes(), &gated)
	if gated.Metrics[0].Status != "not_configured" || gated.Metrics[0].Abuse != nil || string(gated.Metrics[0].Data) != "null" {
		t.Fatal("closed gate exposed cached data")
	}
	validateOpenAPI(t, "NetworkReport", gated)
	validateOpenAPI(t, "NetworkMetric", intelligence.Metric{Name: "abuse", Status: "plan_limited", Data: json.RawMessage(`null`), Observation: intelligence.Observation{CollectionStatus: "plan_limited", Freshness: "unknown", Completeness: "unknown", Scope: intelligence.ObservationScope{Requested: detail.Prefix, Kind: "prefix", Relation: "unknown"}}})
}

func TestAbuseIPv6CachedRESTContract(t *testing.T) {
	d, err := history.Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	now := time.Now().UTC()
	expires := now.Add(24 * time.Hour)
	prefix := "2001:4860:4860::8888/127"
	detail := intelligence.AbuseObservation{Prefix: prefix, Status: "no_reports_in_window", Completeness: "complete", ScopeRelation: "exact", RangeStart: "2001:4860:4860::8888", RangeEnd: "2001:4860:4860::8889", PossibleHosts: 2, WindowDays: 30, WindowStart: now.Add(-30 * 24 * time.Hour), WindowEnd: now, WindowBasis: "local_request_bounds", IngestedAt: now, AddressLimit: 256, Addresses: []intelligence.ReportedAddress{}, DetailsCoverage: "not_collected", Semantics: "source_reports_not_cleanliness_tenant_attribution_or_resolution"}
	raw, _ := json.Marshal(detail)
	metric := intelligence.Metric{Name: "abuse", Status: "ok", Source: "AbuseIPDB", ObservedAt: &now, ExpiresAt: &expires, Data: raw}
	payload, _ := json.Marshal(metric)
	key := `{"Resource":"` + prefix + `","Name":"abuse","Start":"","End":"","Version":"","ASN":0}`
	if err := d.CachePut(context.Background(), key, payload, expires); err != nil {
		t.Fatal(err)
	}
	checks := intelligence.New(d, false, "", 120)
	checks.EnableAbuseIPDB("fixture-key")
	h := Handler(store(t, 1), "", Services{Intelligence: checks})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/network?resource=2001:4860:4860::8888%2F127&checks=abuse", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var report intelligence.Report
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Partial || report.Metrics[0].Abuse == nil || report.Metrics[0].Abuse.Status != "no_reports_in_window" || report.Metrics[0].Observation.Scope.Relation != "exact" {
		t.Fatal("IPv6 cached scope lost")
	}
	validateOpenAPI(t, "NetworkReport", report)
}

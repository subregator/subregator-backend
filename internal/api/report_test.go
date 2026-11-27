package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/intelligence"
)

type reportFailedCache struct{}

func (reportFailedCache) CacheGet(context.Context, string) (json.RawMessage, time.Time, bool, error) {
	return nil, time.Time{}, false, errors.New("private database failure")
}
func (reportFailedCache) CachePut(context.Context, string, json.RawMessage, time.Time) error {
	return nil
}

func TestReportCacheFailureIsNotPending(t *testing.T) {
	checks := intelligence.New(reportFailedCache{}, true, "", 120)
	result, err := checks.Cached(context.Background(), intelligence.Query{Resource: "1.1.1.0/24", Checks: []string{"prefix_overview"}})
	if err != nil || len(result.Metrics) != 1 || result.Metrics[0].Status != "error" || result.Metrics[0].Error != "Cached observation storage unavailable" {
		t.Fatalf("storage failure hidden as missing observation: %v %+v", err, result)
	}
}

func reportFixture(t *testing.T) (*service, string) {
	t.Helper()
	s, _, _ := marketFixture(t)
	prefix := "1.1.1.0/24"
	at := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	offers := []catalog.Offer{marketOffer("a", "first", prefix, at), marketOffer("a", "second", prefix, at)}
	offers[0].Quotes[0].Taxes = "unknown"
	offers[0].Quotes[0].Fees = []catalog.Fee{{Kind: "setup", Frequency: "once", Amount: &catalog.Money{Currency: "EUR", AmountMinor: 12, MinorUnit: 2}}}
	if err := s.store.Apply("a", offers, nil, at); err != nil {
		t.Fatal(err)
	}
	observed := at.Add(-time.Minute)
	expires := at.Add(time.Hour)
	metric := intelligence.Metric{Name: "prefix_overview", Status: "ok", Source: "RIPEstat", SourceURL: "https://stat.ripe.net/fixture", ObservedAt: &observed, ExpiresAt: &expires, Data: json.RawMessage(`{"resource":"1.1.1.0/24","announced":true,"is_less_specific":false,"num_filtered_out":0,"asns":[{"asn":13335}]}`)}
	encoded, _ := json.Marshal(metric)
	key := `{"Resource":"1.1.1.0/24","Name":"prefix_overview","Start":"","End":"","Version":"","ASN":0}`
	if err := s.extras.History.CachePut(context.Background(), key, encoded, expires); err != nil {
		t.Fatal(err)
	}
	s.extras.Intelligence = intelligence.New(s.extras.History, true, "", 120)
	s.extras.Automatic = intelligence.NewAutomatic(s.extras.Intelligence)
	return s, prefix
}

func TestSubnetReportRESTMCPCachedAndCosts(t *testing.T) {
	s, prefix := reportFixture(t)
	var calls atomic.Int32
	old := http.DefaultTransport
	http.DefaultTransport = checkTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"data":{}}`)), Header: make(http.Header)}, nil
	})
	defer func() { http.DefaultTransport = old }()
	out, err := s.subnetReport(context.Background(), url.Values{"resource": {prefix}, "limit": {"1"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Market.Data == nil || out.Market.Data.Total != 2 || len(out.Market.Data.Items) != 1 || !out.Market.Truncated || out.Market.Next == "" || out.Timeline.Data == nil || !out.Timeline.Truncated || out.NetworkHistory != "disabled" {
		t.Fatalf("incomplete report: %+v", out)
	}
	item := out.Market.Data.Items[0]
	if !reflect.DeepEqual(item.QuoteCosts[0], quoteCosts(item.Quotes[0], item.Model)) {
		t.Fatal("cost contract diverged")
	}
	if item.Quotes[0].Taxes == "unknown" && item.QuoteCosts[0].FirstPeriodTotal != nil {
		t.Fatal("invented total")
	}
	if out.GeneratedAt.IsZero() || out.Network.Data == nil || len(out.Network.Data.Current.Metrics) != 10 || out.Network.Data.Drop == nil || calls.Load() != 0 {
		t.Fatal("missing checks or collection triggered", calls.Load())
	}
	if first := out.Network.Data.Current.Metrics[0]; first.Status != "ok" || first.BGP == nil || first.SourceURL != "https://stat.ripe.net/fixture" || first.ObservedAt == nil || !first.ObservedAt.Before(out.GeneratedAt) {
		t.Fatal("lost dated cached observation", first)
	}
	if out.Timeline.Data.ArchiveStartedAt != nil || !slices.Contains(out.Timeline.Gaps, "network_history_disabled") {
		t.Fatal("disabled archive indistinguishable")
	}
	encoded, _ := json.Marshal(out)
	if len(encoded) > out.MaxBytes {
		t.Fatal("unbounded report")
	}
	validateOpenAPI(t, "SubnetReport", out)
	h := Handler(s.store, "", s.extras)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/report?resource="+prefix+"&limit=1", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rest SubnetReport
	if json.Unmarshal(w.Body.Bytes(), &rest) != nil || rest.Market.Data.Snapshot != out.Market.Data.Snapshot {
		t.Fatal(w.Body.String())
	}
	http.DefaultTransport = old
	server := httptest.NewServer(h)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "report-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "subnet_report", Arguments: map[string]any{"filters": map[string]string{"resource": prefix, "limit": "1"}}})
	if err != nil || result.IsError {
		t.Fatal(err, result)
	}
	data, _ := json.Marshal(result.StructuredContent)
	var actual SubnetReport
	if json.Unmarshal(data, &actual) != nil || !reflect.DeepEqual(actual.Market, rest.Market) || !reflect.DeepEqual(actual.Timeline, rest.Timeline) {
		t.Fatal("REST/MCP differ", string(data))
	}
	for _, path := range []string{out.Market.Next, out.Timeline.Next} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
}

func TestSubnetReportPoliciesValidationAndFailures(t *testing.T) {
	s, prefix := reportFixture(t)
	for _, query := range []url.Values{{}, {"resource": {"127.0.0.0/24"}}, {"resource": {prefix}, "limit": {"51"}}, {"resource": {prefix}, "limit": {"0"}}, {"resource": {prefix, prefix}}, {"resource": {prefix}, "offset": {"-1"}}, {"resource": {prefix}, "cursor": {"bad"}}, {"resource": {prefix}, "unknown": {"x"}}} {
		_, err := s.subnetReport(context.Background(), query)
		if typed, ok := err.(*apiError); !ok || typed.status != 400 {
			t.Fatal("accepted invalid query", query, err)
		}
	}
	if _, err := s.subnetReport(context.Background(), url.Values{"resource": {"8.8.8.0/24"}}); err == nil {
		t.Fatal("unknown prefix disclosed")
	}
	for _, policy := range []string{"hidden", "pending"} {
		providers := slices.Clone(s.store.View().Providers)
		for i := range providers {
			if providers[i].ID == "a" {
				if policy == "hidden" {
					providers[i].Policy.PrefixVisibility = "hidden"
				} else {
					providers[i].Policy.Publication = "pending"
				}
			}
		}
		private, err := catalog.NewStore("", providers)
		if err != nil {
			t.Fatal(err)
		}
		svc := service{store: private, extras: s.extras}
		h := Handler(private, "", svc.extras)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/report?resource="+prefix, nil))
		if w.Code != 404 || strings.Contains(w.Body.String(), prefix) {
			t.Fatal("private resource exposed", policy, w.Code, w.Body.String())
		}
	}
	if err := s.extras.Intelligence.SetHistoryChecks("prefix_overview"); err != nil {
		t.Fatal(err)
	}
	out, err := s.subnetReport(context.Background(), url.Values{"resource": {prefix}})
	if err != nil || out.NetworkHistory != "enabled" || !slices.Contains(out.Timeline.Gaps, "no_archived_network_observations") {
		t.Fatal(err, out)
	}
	s.extras.History.Close()
	s.extras.Intelligence = intelligence.New(reportFailedCache{}, true, "", 120)
	out, err = s.subnetReport(context.Background(), url.Values{"resource": {prefix}})
	if err != nil || out.Market.Data == nil || out.Market.Data.Total != 2 || out.Timeline.Status != "error" || out.Network.Data.Current.Metrics[0].Status != "error" {
		t.Fatal("failed section hid useful data", err, out)
	}
	s.extras.History = nil
	s.extras.Intelligence = nil
	out, err = s.subnetReport(context.Background(), url.Values{"resource": {prefix}})
	if err != nil || out.Timeline.Status != "disabled" || out.Network.Status != "disabled" || out.Market.Data.Total != 2 {
		t.Fatal(err, out)
	}
	page, err := s.subnetReport(context.Background(), url.Values{"resource": {prefix}, "limit": {"1"}})
	if err != nil || !page.Market.Truncated {
		t.Fatal(err, page)
	}
	h := Handler(s.store, "", s.extras)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", page.Market.Next, nil))
	var continued SubnetReport
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &continued) != nil || continued.Market.Data == nil || len(continued.Market.Data.Items) != 1 || continued.Market.Data.Items[0].ID == page.Market.Data.Items[0].ID {
		t.Fatal("market continuation lost without history", w.Code, w.Body.String())
	}
	out, err = s.subnetReport(context.Background(), url.Values{"resource": {prefix}, "cursor": {"bad"}})
	if err != nil || out.Timeline.Status != "disabled" || out.Market.Data == nil {
		t.Fatal("disabled timeline must not hide current data", err, out)
	}
}

func TestSubnetReportIPv6AndHistoricalKnown(t *testing.T) {
	s, prefix := reportFixture(t)
	at := time.Now().UTC()
	if err := s.store.Apply("a", nil, nil, at); err != nil {
		t.Fatal(err)
	}
	out, err := s.subnetReport(context.Background(), url.Values{"resource": {prefix}})
	if err != nil || out.Market.Status != "empty" || out.Timeline.Data == nil || len(out.Timeline.Data.Items) == 0 {
		t.Fatal("known removed prefix lost", err, out)
	}
	v6 := "2001:4860::/48"
	if err := s.store.Apply("a", []catalog.Offer{marketOffer("a", "v6", v6, at)}, nil, at); err != nil {
		t.Fatal(err)
	}
	out, err = s.subnetReport(context.Background(), url.Values{"resource": {v6}})
	if err != nil || out.Resource != v6 || out.Market.Data.Items[0].Resource.Family != 6 {
		t.Fatal(err, out)
	}
}

func TestReportSectionByteLimit(t *testing.T) {
	value := strings.Repeat("x", reportSectionBytes)
	section := ReportSection[string]{Status: "available", Data: &value, Gaps: []string{}, URL: "/api/v1/timeline?resource=1.1.1.0%2F24&limit=1"}
	boundReportSection(&section)
	if section.Data != nil || !section.Truncated || section.Next != section.URL || section.Status != "partial" {
		t.Fatal("oversize section escaped bound", section)
	}
	encoded, _ := json.Marshal(section)
	if len(encoded) > reportSectionBytes {
		t.Fatal("byte bound failed")
	}
}

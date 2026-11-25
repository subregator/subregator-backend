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
	report, e := s.inspect(context.Background(), intelligence.Query{Resource: "1.1.1.0/24", Checks: []string{"registration"}})
	if e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 0 {
		t.Fatalf("public lookup triggered %d upstream requests", calls.Load())
	}
	if len(report.Metrics) != 1 || report.Metrics[0].Status != "pending" {
		t.Fatalf("missing observation must remain pending: %+v", report)
	}
	h := Handler(s.store, "", s.extras)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/network?resource=1.1.1.0/24", nil))
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

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

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/subregator/subregator-backend/internal/intelligence"
)

func TestPublicLookupRESTAndMCPShareCache(t *testing.T) {
	_, store, db := historicalHandler(t)
	var calls atomic.Int32
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	http.DefaultTransport = checkTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Host != "stat.ripe.net" {
			t.Error("unexpected upstream")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":"ok","data":{"holder":"DinoTech, LLC"}}`)), Header: make(http.Header)}, nil
	})
	s := intelligence.New(db, true, "", 120)
	h := Handler(store, "", Services{Intelligence: s})
	for _, path := range []string{
		"/api/v1/network/lookup?resource=AS218036&checks=registration",
		"/api/v1/network/lookup?resource=AS218036&checks=registration",
		"/api/v1/network?resource=AS218036&checks=registration",
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		var r intelligence.Report
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &r) != nil || r.Partial || len(r.Metrics) != 1 || r.Metrics[0].Status != "ok" {
			t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
	}
	for _, path := range []string{"/api/v1/network/lookup?resource=127.0.0.1", "/api/v1/network/lookup?resource=AS218036&checks=bad", "/api/v1/network/lookup?resource=AS218036&unknown=1"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != 400 {
			t.Fatalf("invalid query: %d", rr.Code)
		}
	}
	http.DefaultTransport = old
	server := httptest.NewServer(h)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "lookup-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	r, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "lookup_network", Arguments: map[string]any{"resource": "AS218036", "checks": []string{"registration"}}})
	if err != nil || r.IsError {
		t.Fatal(err, r)
	}
	b, _ := json.Marshal(r.StructuredContent)
	if !strings.Contains(string(b), `"status":"ok"`) || calls.Load() != 1 {
		t.Fatalf("cache not shared: %d %s", calls.Load(), b)
	}
}

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/time/rate"
)

func TestRequestRateSharedAcrossRESTAndMCP(t *testing.T) {
	limits := NewRequestLimits(1, 1)
	h := Handler(store(t, 1), "https://subregator.com", Services{Limits: limits})
	request := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Origin", "https://subregator.com")
		r.Header.Set("X-Forwarded-For", path)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/v1/offers"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	limits.rate.SetLimit(0)
	for _, path := range []string{"/api/v1/offers", "/mcp", "/openapi.json"} {
		w := request("POST", path)
		if w.Code != 429 || w.Header().Get("Retry-After") != "1" || w.Header().Get("Access-Control-Allow-Origin") != "https://subregator.com" || !strings.Contains(w.Header().Get("Access-Control-Expose-Headers"), "Retry-After") {
			t.Fatal("rate/cors limit missing", w.Code, w.Header())
		}
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		if w := request("GET", path); w.Code != 200 {
			t.Fatal("probe blocked", path, w.Code)
		}
		if w := request("HEAD", path); w.Code != 200 {
			t.Fatal("HEAD probe blocked", path, w.Code)
		}
	}
	if w := request("OPTIONS", "/mcp"); w.Code != 204 {
		t.Fatal("preflight blocked", w.Code)
	}
	limits.rate.SetLimit(rate.Inf)
	if w := request("GET", "/api/v1/offers"); w.Code != 200 {
		t.Fatal("admission did not recover", w.Code)
	}
}

func TestRequestConcurrencyRejectsWithoutQueueAndRecovers(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	limits := NewRequestLimits(10000, 1)
	h := limits.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blocked" {
			close(entered)
			<-release
		}
		calls.Add(1)
		w.WriteHeader(200)
	}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/blocked", nil))
	}()
	<-entered
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/mcp", nil))
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" || calls.Load() != 0 {
		t.Error("overload queued or executed", w.Code, calls.Load())
	}
	probe := httptest.NewRecorder()
	h.ServeHTTP(probe, httptest.NewRequest("GET", "/healthz", nil))
	if probe.Code != 200 {
		t.Error("health probe unavailable", probe.Code)
	}
	close(release)
	<-done
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/recovered", nil))
	if w.Code != 200 || calls.Load() != 3 {
		t.Fatal("slot leaked", w.Code, calls.Load())
	}
}

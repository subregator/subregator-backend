package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthProbe(t *testing.T) {
	for _, status := range []int{200, 503, 302} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/healthz" {
					t.Error("wrong probe path")
				}
				if status == 302 {
					w.Header().Set("Location", "/healthz")
				}
				w.WriteHeader(status)
			}))
			defer server.Close()
			addr := strings.TrimPrefix(server.URL, "http://")
			e := probe(addr)
			if (e == nil) != (status == 200) {
				t.Fatal("incorrect probe result", e)
			}
			if status == 200 {
				_, port, _ := net.SplitHostPort(addr)
				if e = probe(net.JoinHostPort("0.0.0.0", port)); e != nil {
					t.Fatal("wildcard listener could not be probed", e)
				}
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(server.URL, "http://")
	server.Close()
	if e := probe(addr); e == nil {
		t.Fatal("closed server reported healthy")
	}
	if e := probe("invalid-address"); e == nil {
		t.Fatal("invalid probe address accepted")
	}
}

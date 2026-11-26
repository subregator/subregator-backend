package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/intelligence"
	"net/http"
	"strings"
)

func Handler(store *catalog.Store, origin string, extras ...Services) http.Handler {
	service := &service{store: store}
	if len(extras) > 0 {
		service.extras = extras[0]
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, r, 200, map[string]any{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		status := 503
		if len(store.View().Sources) > 0 {
			for _, s := range store.View().Sources {
				if s.LastSuccess != nil {
					status = 200
				}
			}
		}
		writeJSON(w, r, status, map[string]any{"ready": status == 200, "offers": len(store.View().Offers)})
	})
	mux.HandleFunc("GET /api/v1/offers", func(w http.ResponseWriter, r *http.Request) {
		result, e := service.offers(r.URL.Query())
		respond(w, r, result, e)
	})
	mux.HandleFunc("GET /api/v1/offers/{id}", func(w http.ResponseWriter, r *http.Request) {
		result, e := service.offer(r.PathValue("id"))
		respond(w, r, result, e)
	})
	mux.HandleFunc("GET /api/v1/providers", func(w http.ResponseWriter, r *http.Request) { respond(w, r, service.providers(), nil) })
	mux.HandleFunc("GET /api/v1/market", func(w http.ResponseWriter, r *http.Request) {
		result, e := service.market(r.Context(), r.URL.Query())
		respond(w, r, result, e)
	})
	mux.HandleFunc("GET /api/v1/history", func(w http.ResponseWriter, r *http.Request) {
		result, e := service.events(r.Context(), r.URL.Query())
		respond(w, r, result, e)
	})
	mux.HandleFunc("GET /api/v1/listings/{id}", func(w http.ResponseWriter, r *http.Request) {
		result, e := service.listing(r.Context(), r.PathValue("id"))
		respond(w, r, result, e)
	})
	mux.HandleFunc("GET /api/v1/resources", func(w http.ResponseWriter, r *http.Request) {
		result, e := service.resources(r.Context(), r.URL.Query())
		respond(w, r, result, e)
	})
	mux.HandleFunc("GET /api/v1/network/checks", func(w http.ResponseWriter, r *http.Request) {
		respond(w, r, map[string]any{"items": intelligence.Capabilities()}, nil)
	})
	mux.HandleFunc("GET /api/v1/network/status", func(w http.ResponseWriter, r *http.Request) {
		result, err := service.collectionStatus()
		respond(w, r, result, err)
	})
	mux.HandleFunc("GET /api/v1/network", func(w http.ResponseWriter, r *http.Request) {
		q, e := parseInspection(r.URL.Query())
		if e != nil {
			respond(w, r, nil, e)
			return
		}
		result, e := service.inspect(r.Context(), q)
		respond(w, r, result, e)
	})
	mux.HandleFunc("GET /api/v1/network/lookup", func(w http.ResponseWriter, r *http.Request) {
		q, e := parseInspection(r.URL.Query())
		if e != nil {
			respond(w, r, nil, e)
			return
		}
		result, e := service.lookup(r.Context(), q)
		respond(w, r, result, e)
	})
	mux.Handle("/mcp", service.mcpHandler())
	mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAPI)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			problem(w, r, 404, "not_found", "Route not found")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(indexHTML))
	})
	var handler http.Handler = mux
	if service.extras.Limits != nil {
		handler = service.extras.Limits.wrap(handler)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
		if origin != "" {
			w.Header().Set("Vary", "Origin")
			if r.Header.Get("Origin") == origin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				methods := "GET, HEAD, OPTIONS"
				if r.URL.Path == "/mcp" {
					methods = "POST, GET, HEAD, OPTIONS"
				}
				w.Header().Set("Access-Control-Allow-Methods", methods)
				w.Header().Set("Access-Control-Expose-Headers", "ETag, Retry-After")
				w.Header().Set("Access-Control-Allow-Headers", "If-None-Match, Content-Type, MCP-Protocol-Version, Mcp-Session-Id")
			}
		}
		if r.URL.Path == "/mcp" {
			if value := r.Header.Get("Origin"); value != "" && value != origin && value != "http://"+r.Host && value != "https://"+r.Host {
				problem(w, r, 403, "origin_denied", "Origin not allowed")
				return
			}
		}
		if len(r.URL.RawQuery) > 4096 {
			problem(w, r, 414, "query_too_long", "Query exceeds limit")
			return
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		handler.ServeHTTP(w, r)
	})
}
func respond(w http.ResponseWriter, r *http.Request, result any, e error) {
	if e != nil {
		if typed, ok := e.(*apiError); ok {
			if typed.status == 429 {
				w.Header().Set("Retry-After", "15")
			}
			problem(w, r, typed.status, typed.code, typed.detail)
		} else {
			problem(w, r, 500, "internal_error", "Request failed")
		}
		return
	}
	writeJSON(w, r, 200, result)
}
func problem(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	writeJSON(w, r, status, map[string]any{"error": map[string]string{"code": code, "detail": detail}})
}
func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	b, e := json.Marshal(v)
	if e != nil {
		http.Error(w, "Response serialization failed", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if status == 200 {
		sum := sha256.Sum256(b)
		tag := `"` + hex.EncodeToString(sum[:16]) + `"`
		w.Header().Set("ETag", tag)
		for _, t := range strings.Split(r.Header.Get("If-None-Match"), ",") {
			t = strings.TrimSpace(t)
			if t == "*" || strings.TrimPrefix(t, "W/") == tag {
				w.WriteHeader(304)
				return
			}
		}
	}
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		w.Write(b)
	}
}

const indexHTML = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Subregator API</title><style>body{font:18px system-ui;max-width:760px;margin:60px auto;padding:24px;background:#101820;color:#edf2f5}a{color:#83d7b6}li{margin:16px 0}code{color:#83d7b6}</style><h1>Subregator API</h1><p>Read-only IP resource comparison. Prices and availability are provider observations; complete transactions directly with the provider.</p><ul><li><a href="/api/v1/offers">Available offers</a></li><li><a href="/api/v1/offers?currency=USD&amp;sort=price_asc&amp;limit=10">Lowest monthly base prices in USD</a></li><li><a href="/api/v1/providers">Providers, permissions and source freshness</a></li><li><a href="/api/v1/network/checks">Available network checks</a></li><li><a href="/api/v1/network/lookup?resource=AS218036&amp;checks=asn_overview,asn_neighbours,asn_relationships,announced_prefixes">Look up AS218036</a></li><li><a href="/openapi.json">OpenAPI contract</a></li><li><a href="/readyz">Catalog readiness</a></li></ul><p>Price filters use hundredths of the currency per month for leases, or the full purchase price. Fees and taxes are separate. Seller country does not imply IP geolocation.</p></html>`

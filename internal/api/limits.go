package api

import (
	"net/http"

	"golang.org/x/time/rate"
)

type RequestLimits struct {
	rate  *rate.Limiter
	slots chan struct{}
}

func NewRequestLimits(rps, concurrent int) *RequestLimits {
	return &RequestLimits{rate: rate.NewLimiter(rate.Limit(rps), rps), slots: make(chan struct{}, concurrent)}
}

func (l *RequestLimits) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && (r.URL.Path == "/healthz" || r.URL.Path == "/readyz") {
			next.ServeHTTP(w, r)
			return
		}
		if !l.rate.Allow() {
			w.Header().Set("Retry-After", "1")
			problem(w, r, http.StatusTooManyRequests, "rate_limited", "Request rate exceeded; retry after one second")
			return
		}
		select {
		case l.slots <- struct{}{}:
			defer func() { <-l.slots }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", "1")
			problem(w, r, http.StatusServiceUnavailable, "server_busy", "Concurrent request limit reached; retry after one second")
		}
	})
}

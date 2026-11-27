package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

func validTestURL(raw string, target Target) bool {
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 2048 || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") || (u.Port() != "" && u.Port() != "80" && u.Port() != "443") {
		return false
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if e != nil || ip.Zone() != "" {
		return false
	}
	t, e := ParseTarget(ip.String())
	if e != nil {
		return false
	}
	if target.Kind == "ip" {
		return t.Value == target.Value
	}
	if target.Kind == "prefix" {
		p, _ := netip.ParsePrefix(target.Value)
		return p.Contains(ip)
	}
	return false
}

func (s *Service) throughput(ctx context.Context, target Target, q Query) (Metric, error) {
	if !validTestURL(q.TestURL, target) {
		return Metric{}, errors.New("matching public test URL required")
	}
	if e := s.checkSourceLimit(ctx, q.TestURL); e != nil {
		return Metric{}, e
	}
	release, e := s.acquireRequest(context.WithValue(ctx, sourceBudgetKey{}, q.TestURL))
	if e != nil {
		return Metric{}, e
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, q.TestURL, nil)
	req.Header.Set("User-Agent", "Subregator/0.2 (+https://github.com/subregator/subregator-backend)")
	req.Header.Set("Accept-Encoding", "identity")
	started := time.Now()
	status := 0
	var requestError error
	defer func() {
		s.recordHTTPRequest(ctx, q.TestURL, status, requestError, time.Since(started))
	}()
	response, e := s.client.Do(req)
	if response != nil {
		status = response.StatusCode
	}
	if e != nil {
		requestError = e
		return Metric{}, errors.New("test download unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		requestError = errors.New("test endpoint HTTP status")
	}
	if response.StatusCode == 429 {
		return Metric{}, &sourceLimited{Until: s.deferSource(ctx, q.TestURL, response.Header.Get("Retry-After"))}
	}
	if response.StatusCode != 200 {
		return Metric{}, errors.New("test endpoint did not return HTTP 200")
	}
	bodyStart := time.Now()
	const limit = 8 << 20
	count, readError := io.Copy(io.Discard, io.LimitReader(response.Body, limit))
	elapsed := time.Since(bodyStart).Seconds()
	requestError = readError
	if count == 0 || elapsed <= 0 {
		return Metric{}, ErrNoData
	}
	complete := "complete"
	if readError != nil || count < 65536 || target.Kind != "ip" {
		complete = "partial"
	}
	u, _ := url.Parse(q.TestURL)
	b, _ := json.Marshal(map[string]any{"requested": target.Value, "address": u.Hostname(), "completeness": complete, "bytes_read": count, "body_seconds": elapsed, "mbps": float64(count) * 8 / elapsed / 1e6, "byte_limit": limit, "limit_reached": count == limit, "vantage": "backend_runtime", "semantics": "bounded_HTTP_body_goodput_from_backend_to_supplied_test_endpoint; not_ASN_subnet_or_link_capacity"})
	return Metric{Data: b, ObservedAt: observedNow(), SourceURL: q.TestURL}, nil
}

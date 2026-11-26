package intelligence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

const globalpingURL = "https://api.globalping.io/v1/measurements"

type measurementJob struct {
	ID      string    `json:"id"`
	Probes  int       `json:"probesCount"`
	Created time.Time `json:"created"`
}

func measurementAddress(t Target, q Query) string {
	if q.Address != "" {
		return q.Address
	}
	if t.Kind == "ip" {
		return t.Value
	}
	p := netip.MustParsePrefix(t.Value)
	if p.Bits() < p.Addr().BitLen() {
		return p.Addr().Next().String()
	}
	return p.Addr().String()
}

func (s *Service) measurement(ctx context.Context, target Target, q Query, name string) (Metric, error) {
	select {
	case s.measurementSlots <- struct{}{}:
		defer func() { <-s.measurementSlots }()
	case <-ctx.Done():
		return Metric{}, ctx.Err()
	}
	address := measurementAddress(target, q)
	key := "globalping:" + name + ":" + address
	var job measurementJob
	now := time.Now().UTC()
	if s.cache == nil {
		return Metric{}, errors.New("measurement cache required")
	}
	raw, expires, found, err := s.cache.CacheGet(ctx, key)
	if err != nil {
		return Metric{}, err
	}
	if !found || !now.Before(expires) || json.Unmarshal(raw, &job) != nil || job.ID == "" || job.Created.IsZero() {
		body, _ := json.Marshal(map[string]any{"type": name, "target": address, "limit": 3, "locations": []map[string]string{{"continent": "EU"}, {"continent": "NA"}, {"continent": "AS"}}})
		if err = s.checkSourceLimit(ctx, globalpingURL); err != nil {
			return Metric{}, err
		}
		release, e := s.acquireRequest(context.WithValue(ctx, sourceBudgetKey{}, globalpingURL))
		if e != nil {
			return Metric{}, e
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, globalpingURL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		b, e := s.readRequest(ctx, req, "", 1<<20, true)
		release()
		if e != nil {
			return Metric{}, e
		}
		if json.Unmarshal(b, &job) != nil || job.ID == "" || len(job.ID) > 128 || job.Probes < 1 || job.Probes > 3 {
			return Metric{}, errors.New("invalid measurement creation")
		}
		job.Created = now
		expires = now.Add(5 * time.Minute)
		raw, _ = json.Marshal(job)
		if err = s.cache.CachePut(ctx, key, raw, expires); err != nil {
			return Metric{}, err
		}
	}
	u := globalpingURL + "/" + url.PathEscape(job.ID)
	if wait := time.Until(s.measurementPollAt.Add(500 * time.Millisecond)); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Metric{}, ctx.Err()
		case <-timer.C:
		}
	}
	b, err := s.request(ctx, u, "")
	s.measurementPollAt = time.Now()
	if err != nil {
		return Metric{}, err
	}
	var d struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Target  string `json:"target"`
		Status  string `json:"status"`
		Results []struct {
			Probe  json.RawMessage `json:"probe"`
			Result struct {
				Status  string `json:"status"`
				Address string `json:"resolvedAddress"`
			} `json:"result"`
		} `json:"results"`
	}
	actual, e := ParseTarget(address)
	if json.Unmarshal(b, &d) != nil || d.ID != job.ID || d.Type != name || d.Target != actual.Value || e != nil || len(d.Results) > 3 || (d.Status != "in-progress" && d.Status != "finished") {
		return Metric{}, errors.New("invalid measurement result")
	}
	complete := "complete"
	if d.Status != "finished" || len(d.Results) != job.Probes || target.Kind != "ip" {
		complete = "partial"
	}
	for _, r := range d.Results {
		if r.Result.Status != "finished" || len(r.Probe) == 0 {
			complete = "partial"
		}
		if r.Result.Address != "" && r.Result.Address != address {
			return Metric{}, errors.New("measurement target mismatch")
		}
	}
	data, _ := json.Marshal(map[string]any{"requested": target.Value, "address": address, "completeness": complete, "measurement_id": job.ID, "measurement_url": "https://globalping.io/?measurement=" + url.QueryEscape(job.ID), "data": json.RawMessage(b), "semantics": "delivery_latency_and_paths_from_returned_probes_only; no_reply_is_not_proof_of_outage; not_bandwidth_or_physical_location_verification"})
	m := Metric{Data: data, ObservedAt: observedNow(), ExpiresAt: &expires, SourceURL: u}
	if d.Status == "in-progress" {
		m.Status = "pending"
		m.ObservedAt = nil
	}
	return m, nil
}

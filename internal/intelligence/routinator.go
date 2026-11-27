package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const DefaultRoutinatorURL = "http://routinator:8323"
const routinatorSourceURL = "https://routinator.docs.nlnetlabs.nl/en/stable/validity-checker.html"
const routinatorMaxAge = time.Hour

func (s *Service) EnableRoutinator(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 2048 || strings.TrimSpace(endpoint) != endpoint || u.Opaque != "" || u.ForceQuery || strings.HasSuffix(u.Host, ":") || u.Scheme != "http" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return errors.New("invalid private Routinator endpoint")
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		if !ip.IsPrivate() && !ip.IsLoopback() {
			return errors.New("Routinator requires a private address")
		}
	} else if strings.Contains(host, ".") && host != "localhost" {
		return errors.New("Routinator requires a private address or single-label service name")
	}
	if u.Port() != "" {
		n, e := strconv.Atoi(u.Port())
		if e != nil || n < 1 || n > 65535 {
			return errors.New("invalid Routinator port")
		}
	}
	s.routinatorURL = strings.TrimSuffix(u.String(), "/")
	s.routinatorSlots = make(chan struct{}, 2)
	return nil
}

func (s *Service) rpkiSource() string {
	if s.routinatorURL != "" {
		return "Routinator"
	}
	return "RIPEstat"
}

func (s *Service) cacheKey(target Target, q Query, name string) string {
	if name == "rpki" && s.routinatorURL != "" {
		q.Version = "routinator-v1"
	}
	return metricKey(target, q, name)
}

func (s *Service) routinatorUsable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routinatorHealthy && time.Since(s.routinatorChecked) < 5*time.Minute
}

func (s *Service) routinatorRead(ctx context.Context, path string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	select {
	case s.routinatorSlots <- struct{}{}:
		defer func() { <-s.routinatorSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.readSource(ctx, s.routinatorURL+path, "", 1<<20, true)
}

func (s *Service) routinatorStatus(ctx context.Context) (done time.Time, err error) {
	defer func() {
		s.mu.Lock()
		s.routinatorChecked, s.routinatorHealthy = time.Now(), err == nil
		s.mu.Unlock()
	}()
	raw, err := s.routinatorRead(ctx, "/api/v1/status")
	if err != nil {
		return done, err
	}
	var status struct {
		Done time.Time `json:"lastUpdateDone"`
		TALs map[string]struct {
			VRPs int `json:"vrpsTotal"`
		} `json:"tals"`
	}
	if json.Unmarshal(raw, &status) != nil || status.Done.IsZero() || status.Done.After(time.Now().Add(time.Minute)) || time.Since(status.Done) > routinatorMaxAge {
		return done, errors.New("Routinator validation data unavailable or stale")
	}
	for _, name := range []string{"afrinic", "apnic", "arin", "lacnic", "ripe"} {
		if status.TALs[name].VRPs <= 0 {
			return done, errors.New("Routinator trust-anchor coverage incomplete")
		}
	}
	return status.Done, nil
}

func (s *Service) routinatorValidation(ctx context.Context, prefix string, asn uint32, updated time.Time) (Metric, error) {
	raw, err := s.routinatorRead(ctx, "/validity?"+url.Values{"asn": {strconv.FormatUint(uint64(asn), 10)}, "prefix": {prefix}}.Encode())
	if err != nil {
		s.mu.Lock()
		s.routinatorHealthy = false
		s.mu.Unlock()
		return Metric{}, err
	}
	data, generated, err := normalizeRoutinator(raw, prefix, asn)
	if err != nil {
		s.mu.Lock()
		s.routinatorHealthy = false
		s.mu.Unlock()
		return Metric{}, err
	}
	expires := minTime(updated.Add(routinatorMaxAge), generated.Add(routinatorMaxAge))
	return Metric{Data: data, ObservedAt: observedNow(), SourceUpdatedAt: &updated, ExpiresAt: &expires, SourceURL: routinatorSourceURL}, nil
}

func normalizeRoutinator(raw json.RawMessage, prefix string, asn uint32) (json.RawMessage, time.Time, error) {
	var d struct {
		Generated time.Time `json:"generatedTime"`
		Route     struct {
			Route struct {
				ASN    string `json:"origin_asn"`
				Prefix string `json:"prefix"`
			} `json:"route"`
			Validity struct {
				State  string `json:"state"`
				Reason string `json:"reason"`
				VRPs   struct {
					Matched []routinatorVRP `json:"matched"`
					ASN     []routinatorVRP `json:"unmatched_as"`
					Length  []routinatorVRP `json:"unmatched_length"`
				} `json:"VRPs"`
			} `json:"validity"`
		} `json:"validated_route"`
	}
	invalid := errors.New("invalid or stale Routinator validity response")
	p, err := netip.ParsePrefix(prefix)
	if err != nil || json.Unmarshal(raw, &d) != nil || d.Generated.IsZero() || d.Generated.After(time.Now().Add(time.Minute)) || time.Since(d.Generated) > routinatorMaxAge || !samePrefix(d.Route.Route.Prefix, p) || originASN(json.RawMessage(strconv.Quote(d.Route.Route.ASN))) != asn {
		return nil, time.Time{}, invalid
	}
	v := d.Route.Validity
	state := v.State
	switch state {
	case "valid":
		if len(v.VRPs.Matched) == 0 {
			return nil, time.Time{}, invalid
		}
	case "invalid":
		if len(v.VRPs.Matched) > 0 {
			return nil, time.Time{}, invalid
		}
		if v.Reason == "as" && len(v.VRPs.ASN) > 0 {
			state = "invalid_asn"
		} else if v.Reason == "length" && len(v.VRPs.Length) > 0 {
			state = "invalid_length"
		} else {
			return nil, time.Time{}, invalid
		}
	case "not-found":
		if len(v.VRPs.Matched)+len(v.VRPs.ASN)+len(v.VRPs.Length) > 0 {
			return nil, time.Time{}, invalid
		}
		state = "unknown"
	default:
		return nil, time.Time{}, invalid
	}
	roas := []ROA{}
	for category, group := range [][]routinatorVRP{v.VRPs.Matched, v.VRPs.ASN, v.VRPs.Length} {
		for _, vrp := range group {
			rp, e := netip.ParsePrefix(vrp.Prefix)
			n, ok := roaASN(json.RawMessage(strconv.Quote(vrp.ASN)))
			length, e2 := strconv.Atoi(vrp.MaxLength)
			if e != nil || e2 != nil || !ok || rp != rp.Masked() || rp.Bits() > p.Bits() || !rp.Contains(p.Addr()) || length < rp.Bits() || length > rp.Addr().BitLen() {
				return nil, time.Time{}, invalid
			}
			if category == 0 && (n != asn || length < p.Bits()) || category == 1 && (n == asn || length < p.Bits()) || category == 2 && length >= p.Bits() {
				return nil, time.Time{}, invalid
			}
			if len(roas) < 32 {
				roas = append(roas, ROA{Prefix: rp.String(), ASN: n, MaxLength: length})
			}
		}
	}
	b, _ := json.Marshal(map[string]any{"prefix": prefix, "resource": asn, "status": state, "validating_roas": roas, "roas_truncated": len(v.VRPs.Matched)+len(v.VRPs.ASN)+len(v.VRPs.Length) > 32})
	return b, d.Generated, nil
}

type routinatorVRP struct {
	ASN       string `json:"asn"`
	Prefix    string `json:"prefix"`
	MaxLength string `json:"max_length"`
}

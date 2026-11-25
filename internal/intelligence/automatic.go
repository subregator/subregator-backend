package intelligence

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

type Check struct {
	Status          string      `json:"status"`
	Freshness       string      `json:"freshness"`
	ObservedAt      *time.Time  `json:"observed_at"`
	ExpiresAt       *time.Time  `json:"expires_at"`
	Source          string      `json:"source"`
	SourceURL       string      `json:"source_url,omitempty"`
	Coverage        string      `json:"coverage"`
	Reason          string      `json:"reason"`
	Origins         []uint32    `json:"origins,omitempty"`
	Matches         []DropMatch `json:"matches,omitempty"`
	SourceUpdatedAt *time.Time  `json:"source_updated_at,omitempty"`
	Copyright       string      `json:"copyright,omitempty"`
}

type OfferChecks struct {
	Resource  string `json:"resource"`
	BGP       Check  `json:"bgp"`
	RPKI      Check  `json:"rpki"`
	Blocklist Check  `json:"blocklist"`
	Semantics string `json:"semantics"`
}

// Automatic is written only by Run; readers never schedule upstream work.
type Automatic struct {
	service *Service
	mu      sync.RWMutex
	reports map[string]OfferChecks
	due     map[string]time.Time
	drop    map[bool]*dropFeed
}

func NewAutomatic(s *Service) *Automatic {
	return &Automatic{service: s, reports: map[string]OfferChecks{}, due: map[string]time.Time{}, drop: map[bool]*dropFeed{true: {}, false: {}}}
}

func unknownCheck() Check {
	return Check{Status: "pending", Freshness: "unknown", Reason: "Awaiting automatic source checks"}
}
func pendingChecks(resource string) OfferChecks {
	return OfferChecks{Resource: resource, BGP: unknownCheck(), RPKI: unknownCheck(), Blocklist: unknownCheck(), Semantics: "source_scoped_observations_not_safety_or_reputation"}
}
func (a *Automatic) Get(resource string) OfferChecks {
	a.mu.RLock()
	r, ok := a.reports[resource]
	a.mu.RUnlock()
	if !ok {
		return pendingChecks(resource)
	}
	now := time.Now()
	for _, c := range []*Check{&r.BGP, &r.RPKI, &r.Blocklist} {
		if c.Freshness == "fresh" && (c.ExpiresAt == nil || !now.Before(*c.ExpiresAt)) {
			c.Freshness = "stale"
		}
	}
	return r
}

func (a *Automatic) Run(ctx context.Context, store *catalog.Store) {
	// Ten upstream calls per prefix leaves room for multi-origin RPKI and bootstrap requests.
	interval := max(100*time.Millisecond, time.Minute*10/time.Duration(a.service.rpm))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	cursor := ""
	for {
		view := store.View()
		active := map[string]bool{}
		for _, o := range view.Offers {
			if o.Resource.Prefix != nil {
				if t, e := ParseTarget(*o.Resource.Prefix); e == nil {
					active[t.Value] = true
				}
			}
		}
		keys := make([]string, 0, len(active))
		for key := range active {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		a.mu.Lock()
		for key := range a.reports {
			if !active[key] {
				delete(a.reports, key)
				delete(a.due, key)
			}
		}
		a.mu.Unlock()
		for _, key := range keys {
			if _, ok := a.due[key]; ok {
				continue
			}
			if a.service.cache != nil {
				b, _, found, e := a.service.cache.CacheGet(ctx, "automatic:"+key)
				var r OfferChecks
				if e == nil && found && json.Unmarshal(b, &r) == nil && r.Resource == key {
					a.mu.Lock()
					a.reports[key] = r
					a.mu.Unlock()
				}
			}
			a.due[key] = time.Time{}
		}
		start := sort.SearchStrings(keys, cursor)
		for i := 0; i < len(keys); i++ {
			key := keys[(start+i)%len(keys)]
			if time.Now().Before(a.due[key]) {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			prefix := netip.MustParsePrefix(key)
			blocklist := a.drop[prefix.Addr().Is4()].check(ctx, a.service, prefix, time.Now())
			r := Report{Resource: Target{Value: key, Kind: "prefix"}, Semantics: "source_observations_not_ownership_or_reachability_guarantees"}
			q := Query{Resource: key}
			workCtx := context.WithValue(ctx, automaticBudgetKey{}, true)
			a.publish(ctx, key, r, blocklist)
			for _, name := range []string{"prefix_overview", "rpki", "routing_status", "registration", "rdap"} {
				m := a.service.metric(workCtx, r.Resource, q, name)
				if ctx.Err() != nil {
					return
				}
				r.Metrics = append(r.Metrics, m)
				if name == "prefix_overview" {
					q.overview = &m
				}
				a.publish(ctx, key, r, blocklist)
			}
			cursor = key + "\x00"
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func sameOrigins(a, b []uint32) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

func retainCheck(previous, current Check) Check {
	if (current.Status == "unavailable" || current.Status == "pending") && previous.ObservedAt != nil && previous.Status != "unavailable" && previous.Status != "pending" {
		previous.Reason = "Retained source observation; refresh unavailable"
		return previous
	}
	return current
}

func (a *Automatic) publish(ctx context.Context, key string, r Report, blocklist Check) {
	bgp, rpki := summarize(r, time.Now())
	if len(r.Metrics) == 0 {
		bgp, rpki = unknownCheck(), unknownCheck()
	}
	if len(r.Metrics) == 1 && rpki.Status == "unavailable" {
		rpki = unknownCheck()
	}
	a.mu.RLock()
	previous := a.reports[key]
	a.mu.RUnlock()
	retainValidation := bgp.Status == "unavailable" || bgp.Status == "pending"
	if bgp.Status == "announced" {
		var overview struct {
			Filtered *int `json:"num_filtered_out"`
		}
		for _, m := range r.Metrics {
			if m.Name == "prefix_overview" && json.Unmarshal(m.Data, &overview) == nil && overview.Filtered != nil && *overview.Filtered == 0 {
				retainValidation = true
			}
		}
	}
	bgp = retainCheck(previous.BGP, bgp)
	if retainValidation && bgp.Status == previous.BGP.Status && sameOrigins(bgp.Origins, previous.BGP.Origins) {
		rpki = retainCheck(previous.RPKI, rpki)
		if bgp.ExpiresAt != nil && rpki.ExpiresAt != nil && bgp.ExpiresAt.Before(*rpki.ExpiresAt) {
			rpki.ExpiresAt = bgp.ExpiresAt
		}
		if bgp.Freshness != "fresh" {
			rpki.Freshness = bgp.Freshness
		}
	}
	report := OfferChecks{Resource: key, BGP: bgp, RPKI: rpki, Blocklist: blocklist, Semantics: "source_scoped_observations_not_safety_or_reputation"}
	due := time.Now().Add(5 * time.Minute)
	for _, m := range r.Metrics {
		if m.Status != "ok" || m.ExpiresAt == nil {
			due = time.Now().Add(time.Minute)
			break
		}
		if m.ExpiresAt.Before(due) {
			due = *m.ExpiresAt
		}
	}
	a.due[key] = due
	if a.service.cache != nil {
		b, _ := json.Marshal(report)
		if e := a.service.cache.CachePut(ctx, "automatic:"+key, b, due); e != nil {
			a.due[key] = time.Now().Add(time.Minute)
			slog.Warn("could not persist automatic checks", "resource", key)
		}
	}
	a.mu.Lock()
	a.reports[key] = report
	a.mu.Unlock()
}

func metricCheck(m Metric, now time.Time) Check {
	c := Check{Status: "unavailable", Freshness: "unknown", ObservedAt: m.ObservedAt, ExpiresAt: m.ExpiresAt, Source: m.Source, SourceURL: m.SourceURL, Coverage: m.Coverage, Reason: m.Error}
	if m.ObservedAt != nil {
		c.Freshness = "stale"
	}
	if (m.Status == "ok" || m.Status == "no_data") && m.ObservedAt != nil && m.ExpiresAt != nil && !m.ObservedAt.After(now.Add(time.Minute)) && !m.ObservedAt.After(*m.ExpiresAt) && now.Before(*m.ExpiresAt) {
		c.Freshness = "fresh"
	}
	return c
}
func samePrefix(raw string, p netip.Prefix) bool {
	q, e := netip.ParsePrefix(raw)
	return e == nil && q.Masked() == p
}
func summarize(r Report, now time.Time) (Check, Check) {
	var overview, validation Metric
	for _, m := range r.Metrics {
		if m.Name == "prefix_overview" {
			overview = m
		}
		if m.Name == "rpki" {
			validation = m
		}
	}
	bgp, rpki := metricCheck(overview, now), metricCheck(validation, now)
	if overview.Status == "no_data" && overview.ObservedAt != nil {
		bgp.Status = "no_data"
		rpki.Status = "not_applicable"
		return bgp, rpki
	}
	if validation.Status == "no_data" && validation.ObservedAt != nil {
		rpki.Status = "no_data"
	}
	p, e := netip.ParsePrefix(r.Resource.Value)
	if e != nil {
		return bgp, rpki
	}
	var d struct {
		Resource  string `json:"resource"`
		Less      *bool  `json:"is_less_specific"`
		Announced *bool  `json:"announced"`
		Filtered  *int   `json:"num_filtered_out"`
		ASNs      []struct {
			ASN uint32 `json:"asn"`
		} `json:"asns"`
	}
	if json.Unmarshal(overview.Data, &d) != nil {
		return bgp, rpki
	}
	if !samePrefix(d.Resource, p) || d.Less == nil || *d.Less {
		if d.Less != nil && *d.Less {
			bgp.Status = "covering_route"
		}
		bgp.Reason = "An exact-prefix observation is required"
		return bgp, rpki
	}
	origins := map[uint32]bool{}
	for _, v := range d.ASNs {
		if v.ASN == 0 {
			return bgp, rpki
		}
		origins[v.ASN] = true
		bgp.Origins = append(bgp.Origins, v.ASN)
	}
	if d.Announced != nil && !*d.Announced && d.ASNs != nil && len(origins) == 0 {
		bgp.Status = "not_announced"
		rpki.Status = "not_applicable"
		return bgp, rpki
	}
	if d.Announced == nil || !*d.Announced || len(origins) == 0 {
		return bgp, rpki
	}
	bgp.Status = "announced"
	bgp.Reason = "Exact prefix observed by RIS; not a reachability guarantee"
	var v struct {
		Prefix  string `json:"prefix"`
		Origins []struct {
			ASN  uint32 `json:"asn"`
			Data struct {
				Prefix   string          `json:"prefix"`
				Resource json.RawMessage `json:"resource"`
				Status   string          `json:"status"`
			} `json:"data"`
		} `json:"origins"`
	}
	if json.Unmarshal(validation.Data, &v) != nil || !samePrefix(v.Prefix, p) {
		return bgp, rpki
	}
	if bgp.ExpiresAt != nil && rpki.ExpiresAt != nil && bgp.ExpiresAt.Before(*rpki.ExpiresAt) {
		rpki.ExpiresAt = bgp.ExpiresAt
	}
	if bgp.Freshness != "fresh" {
		rpki.Freshness = bgp.Freshness
	}
	checked := map[uint32]bool{}
	invalid, valid, unknown := false, 0, 0
	for _, o := range v.Origins {
		if !origins[o.ASN] || checked[o.ASN] || !samePrefix(o.Data.Prefix, p) || originASN(o.Data.Resource) != o.ASN {
			continue
		}
		switch o.Data.Status {
		case "valid":
			valid++
		case "unknown":
			unknown++
		case "invalid_asn", "invalid_length":
			invalid = true
		default:
			continue
		}
		checked[o.ASN] = true
	}
	rpki.Reason = "Validation of observed prefix/origin pairs; not ownership or reputation"
	switch {
	case invalid:
		rpki.Status = "invalid"
	case len(checked) != len(origins) || len(v.Origins) != len(origins) || d.Filtered == nil || *d.Filtered != 0:
		rpki.Status = "partial"
	case valid == len(origins):
		rpki.Status = "valid"
	case unknown == len(origins):
		rpki.Status = "not_found"
	default:
		rpki.Status = "mixed"
	}
	return bgp, rpki
}

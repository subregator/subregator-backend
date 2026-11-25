package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

type Cache interface {
	CacheGet(context.Context, string) (json.RawMessage, time.Time, bool, error)
	CachePut(context.Context, string, json.RawMessage, time.Time) error
}
type Definition struct {
	Automatic     bool     `json:"automatic"`
	Name          string   `json:"name"`
	Source        string   `json:"source"`
	Description   string   `json:"description"`
	Coverage      string   `json:"coverage"`
	TTLSeconds    int      `json:"cache_ttl_seconds"`
	Kinds         []string `json:"resource_kinds"`
	TokenRequired bool     `json:"free_token_required"`
}

var definitions = map[string]Definition{
	"asn_rank":             {Name: "asn_rank", Source: "CAIDA ASRank", Description: "Free customer-cone topology ranking of origin ASNs", Coverage: "ASN topology rank, not subnet reputation, traffic or packet reachability", TTLSeconds: 300, Kinds: []string{"ip", "prefix", "asn"}},
	"prefix_overview":      {Name: "prefix_overview", Source: "RIPEstat", Description: "Announced prefix and origin ASNs", Coverage: "RIS collector observations; not a packet reachability test", TTLSeconds: 300, Kinds: []string{"ip", "prefix"}},
	"routing_status":       {Name: "routing_status", Source: "RIPEstat", Description: "Visibility, first/last routing observations and related routes", Coverage: "RIS collectors only", TTLSeconds: 300, Kinds: []string{"ip", "prefix", "asn"}},
	"looking_glass":        {Name: "looking_glass", Source: "RIPEstat", Description: "AS paths and BGP peers by collector", Coverage: "Near real-time RIS data; no active ping or traceroute", TTLSeconds: 60, Kinds: []string{"ip", "prefix"}},
	"routing_history":      {Name: "routing_history", Source: "RIPEstat", Description: "Historic origin announcements and visibility timelines", Coverage: "Requested window, up to 366 days per request; source may omit or truncate records", TTLSeconds: 3600, Kinds: []string{"ip", "prefix", "asn"}},
	"registration":         {Name: "registration", Source: "RIPEstat", Description: "Current public registry records", Coverage: "Registration is not proof of beneficial ownership", TTLSeconds: 21600, Kinds: []string{"ip", "prefix", "asn"}},
	"registration_history": {Name: "registration_history", Source: "RIPEstat", Description: "Versions of registry objects with optional version/time selection", Coverage: "RIPE Database only; other RIR histories are not covered", TTLSeconds: 3600, Kinds: []string{"ip", "prefix", "asn"}},
	"allocation_history":   {Name: "allocation_history", Source: "RIPEstat", Description: "Published RIR allocation history", Coverage: "Registry allocations, not every private commercial transfer", TTLSeconds: 86400, Kinds: []string{"ip", "prefix", "asn"}},
	"transfer_history":     {Name: "transfer_history", Source: "RIPEstat", Description: "Published registry transfer events", Coverage: "May cover larger containing blocks; not a complete ownership ledger", TTLSeconds: 86400, Kinds: []string{"ip", "prefix"}},
	"rpki":                 {Name: "rpki", Source: "RIPEstat", Description: "Validate prefix/origin pairs against ROAs", Coverage: "Current origin validation; not reputation or ownership", TTLSeconds: 300, Kinds: []string{"ip", "prefix"}},
	"asn_overview":         {Name: "asn_overview", Source: "RIPEstat", Description: "ASN name and announced address space", Coverage: "Current ASN data", TTLSeconds: 3600, Kinds: []string{"asn"}},
	"asn_neighbours":       {Name: "asn_neighbours", Source: "RIPEstat", Description: "Upstream/downstream or peer relationships of origin ASNs", Coverage: "Observed BGP adjacency does not prove packet connectivity", TTLSeconds: 300, Kinds: []string{"ip", "prefix", "asn"}},
	"rdap":                 {Name: "rdap", Source: "RIR RDAP", Description: "Authoritative registration range and organization metadata", Coverage: "Current covering registration block; public registry records only", TTLSeconds: 21600, Kinds: []string{"ip", "prefix", "asn"}},
	"ipinfo_lite":          {Name: "ipinfo_lite", Source: "IPinfo Lite", Description: "Free country and ASN data for one address", Coverage: "IP-level data; no subnet reputation score or paid privacy fields", TTLSeconds: 86400, Kinds: []string{"ip"}, TokenRequired: true},
}

func Capabilities() []Definition {
	out := make([]Definition, 0, len(definitions))
	for _, d := range definitions {
		d.Automatic = slices.Contains(automaticChecks, d.Name)
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type Metric struct {
	Registration    *Registration   `json:"registration,omitempty"`
	RetryAt         *time.Time      `json:"retry_at,omitempty"`
	SourceUpdatedAt *time.Time      `json:"source_updated_at,omitempty"`
	Observation     Observation     `json:"observation"`
	Name            string          `json:"name"`
	Status          string          `json:"status"`
	Source          string          `json:"source"`
	SourceURL       string          `json:"source_url,omitempty"`
	Coverage        string          `json:"coverage"`
	ObservedAt      *time.Time      `json:"observed_at"`
	ExpiresAt       *time.Time      `json:"expires_at"`
	Cached          bool            `json:"cached"`
	Error           string          `json:"error,omitempty"`
	Data            json.RawMessage `json:"data"`
}
type Report struct {
	Resource  Target   `json:"resource"`
	Metrics   []Metric `json:"metrics"`
	Partial   bool     `json:"partial"`
	Semantics string   `json:"semantics"`
}
type call struct {
	done   chan struct{}
	result Metric
}
type Service struct {
	cache               Cache
	client              *http.Client
	network             bool
	token               string
	rpm                 int
	mu                  sync.Mutex
	flights             map[string]*call
	window              time.Time
	used                int
	httpSlots           chan struct{}
	inspectSlots        chan struct{}
	stats               map[string]UpstreamStats
	startedAt           time.Time
	budgetDenials       uint64
	budgetWaits         uint64
	budgetWaitDuration  time.Duration
	persistenceFailures uint64
	limits              map[string]*sourceLimit
	budgetChanged       chan struct{}
	budgetQueue         []uint64
	budgetTicket        uint64
}

var ErrNoData = errors.New("no observation in source coverage")
var ErrBusy = errors.New("network inspection capacity reached; retry later")

func New(cache Cache, network bool, freeToken string, rpm int) *Service {
	if rpm < 1 {
		rpm = 120
	}
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("upstream redirect refused") }}
	return &Service{cache: cache, client: client, network: network, token: freeToken, rpm: rpm, flights: map[string]*call{}, httpSlots: make(chan struct{}, 4), inspectSlots: make(chan struct{}, 4), stats: map[string]UpstreamStats{}, startedAt: time.Now().UTC(), limits: map[string]*sourceLimit{}, budgetChanged: make(chan struct{})}
}
func (s *Service) Inspect(ctx context.Context, q Query) (Report, error) {
	target, e := q.validate()
	if e != nil {
		return Report{}, e
	}
	select {
	case s.inspectSlots <- struct{}{}:
		defer func() { <-s.inspectSlots }()
	default:
		return Report{}, ErrBusy
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	out := Report{Resource: target, Metrics: make([]Metric, len(q.Checks)), Semantics: "source_observations_not_ownership_or_reachability_guarantees"}
	var wg sync.WaitGroup
	for i, name := range q.Checks {
		wg.Add(1)
		go func(i int, name string) { defer wg.Done(); out.Metrics[i] = s.metric(ctx, target, q, name) }(i, name)
	}
	wg.Wait()
	for _, m := range out.Metrics {
		if m.Status != "ok" {
			out.Partial = true
		}
	}
	return out, nil
}
func (s *Service) metric(ctx context.Context, target Target, q Query, name string) (out Metric) {
	defer func() {
		out = decorateRegistration(out, target)
		out.Observation = metricObservation(out, target, q, time.Now())
	}()
	d := definitions[name]
	m := s.initialMetric(target, name)
	if m.Status != "pending" {
		return m
	}
	key := metricKey(target, q, name)
	var previous Metric
	cached := func() bool {
		if s.cache != nil {
			b, expires, found, e := s.cache.CacheGet(ctx, key)
			if e != nil {
				s.persistenceFailed()
			}
			if e == nil && found && json.Unmarshal(b, &previous) == nil && time.Now().Before(expires) {
				if name == "rdap" {
					if _, err := normalizeRDAP(previous.Data, previous.SourceURL, target); err != nil {
						previous = Metric{}
						return false
					}
				}
				previous.Cached = true
				return true
			}
		}
		return false
	}
	if cached() {
		return previous
	}

	if !s.network {
		if previous.Status != "" {
			previous.Status = "stale"
			previous.Cached = true
			previous.Error = "External lookups are disabled"
			return previous
		}
		m.Status = "disabled"
		return m
	}
	s.mu.Lock()
	if existing := s.flights[key]; existing != nil {
		s.mu.Unlock()
		select {
		case <-existing.done:
			r := existing.result
			r.Cached = true
			return r
		case <-ctx.Done():
			m.Status = "unavailable"
			m.Error = "Inspection canceled or timed out"
			return m
		}
	}
	pending := &call{done: make(chan struct{})}
	s.flights[key] = pending
	s.mu.Unlock()
	var result Metric
	// Another refresh may have finished after the first cache read.
	if cached() {
		result = previous
	} else {
		result = s.fetchMetric(ctx, target, q, m)
		ttl := time.Duration(d.TTLSeconds) * time.Second
		if result.Status != "ok" && result.Status != "no_data" {
			ttl = 15 * time.Second
			if result.Status != "no_data" && (previous.Status == "ok" || previous.Status == "stale") {
				retry := result.RetryAt
				result = previous
				result.RetryAt = retry
				result.Status = "stale"
				result.Cached = true
				result.Error = "Refresh failed; retained source observation"
			}
		}
		expires := time.Now().UTC().Add(ttl)
		if result.RetryAt != nil && result.RetryAt.After(expires) {
			expires = *result.RetryAt
		}
		result.ExpiresAt = &expires
		if s.cache != nil && ctx.Err() == nil {
			if b, e := json.Marshal(result); e == nil {
				if s.cache.CachePut(ctx, key, b, expires) != nil {
					s.persistenceFailed()
				}
			}
		}
	}

	s.mu.Lock()
	pending.result = result
	delete(s.flights, key)
	close(pending.done)
	s.mu.Unlock()
	return result
}

type automaticBudgetKey struct{}

func (s *Service) acquireRequest(ctx context.Context) (func(), error) {
	automatic := ctx.Value(automaticBudgetKey{}) == true
	var ticket uint64
	if automatic {
		s.mu.Lock()
		s.budgetTicket++
		ticket = s.budgetTicket
		s.budgetQueue = append(s.budgetQueue, ticket)
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			for i, queued := range s.budgetQueue {
				if queued == ticket {
					s.budgetQueue = append(s.budgetQueue[:i], s.budgetQueue[i+1:]...)
					break
				}
			}
			s.notifyBudget()
			s.mu.Unlock()
		}()
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		select {
		case s.httpSlots <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		s.mu.Lock()
		now := time.Now()
		if raw, ok := ctx.Value(sourceBudgetKey{}).(string); ok {
			if limit := s.limits[sourceLimitKey(raw)]; limit != nil {
				if deadline := limit.deadline.Load(); deadline != nil && deadline.After(now) {
					s.mu.Unlock()
					<-s.httpSlots
					return nil, &sourceLimited{Until: *deadline}
				}
			}
		}
		if s.window.IsZero() || now.Sub(s.window) >= time.Minute {
			s.window = now
			s.used = 0
		}
		turn := !automatic || len(s.budgetQueue) > 0 && s.budgetQueue[0] == ticket
		if s.used < s.rpm && turn {
			s.used++
			s.mu.Unlock()
			return func() { <-s.httpSlots }, nil
		}
		wait := time.Until(s.window.Add(time.Minute))
		if !turn && s.used < s.rpm {
			wait = time.Minute
		}
		changed := s.budgetChanged
		s.mu.Unlock()
		<-s.httpSlots
		if !automatic {
			s.mu.Lock()
			s.budgetDenials++
			s.mu.Unlock()
			return nil, ErrBusy
		}
		started := time.Now()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			s.recordBudgetWait(time.Since(started))
			return nil, ctx.Err()
		case <-timer.C:
			s.recordBudgetWait(time.Since(started))
		case <-changed:
			timer.Stop()
			s.recordBudgetWait(time.Since(started))
		}
	}
}

func (s *Service) request(ctx context.Context, rawURL, auth string) (json.RawMessage, error) {
	if err := s.checkSourceLimit(ctx, rawURL); err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, sourceBudgetKey{}, rawURL)
	release, e := s.acquireRequest(ctx)
	if e != nil {
		return nil, e
	}
	defer release()
	return s.readSource(ctx, rawURL, auth, 1<<20, true)
}

func (s *Service) readSource(ctx context.Context, rawURL, auth string, maxBytes int, requireJSON bool) (data json.RawMessage, err error) {
	if err := s.checkSourceLimit(ctx, rawURL); err != nil {
		return nil, err
	}
	started := time.Now()
	status := 0
	defer func() { s.recordRequest(rawURL, status, err, time.Since(started)) }()
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if e != nil {
		return nil, errors.New("invalid upstream request")
	}
	r.Header.Set("User-Agent", "Subregator/0.2 (+https://github.com/subregator/subregator-backend)")
	r.Header.Set("Accept", "application/json, application/rdap+json")
	if auth != "" {
		r.Header.Set("Authorization", "Bearer "+auth)
	}
	response, e := s.client.Do(r)
	if e != nil {
		return nil, errors.New("upstream request failed")
	}
	defer response.Body.Close()
	status = response.StatusCode
	if response.StatusCode == 404 {
		return nil, ErrNoData
	}
	if response.StatusCode == 429 {
		return nil, &sourceLimited{Until: s.deferSource(ctx, rawURL, response.Header.Get("Retry-After"))}
	}
	if response.StatusCode != 200 {
		return nil, errors.New("upstream unavailable")
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, int64(maxBytes)+1))
	if e != nil || len(b) > maxBytes || requireJSON && !json.Valid(b) {
		return nil, errors.New("invalid or oversized upstream response")
	}
	return b, nil
}
func (s *Service) ripe(ctx context.Context, endpoint string, params url.Values) (Metric, error) {
	u := "https://stat.ripe.net/data/" + endpoint + "/data.json?" + params.Encode()
	b, e := s.request(ctx, u, "")
	if e != nil {
		return Metric{}, e
	}
	var envelope struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if e = json.Unmarshal(b, &envelope); e != nil || envelope.Status != "ok" || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return Metric{}, errors.New("invalid RIPEstat response")
	}
	return Metric{SourceURL: u, ObservedAt: observedNow(), Data: envelope.Data}, nil
}
func (s *Service) fetchMetric(ctx context.Context, target Target, q Query, m Metric) Metric {
	var result Metric
	var e error
	switch m.Name {
	case "rdap":
		result, e = s.rdap(ctx, target)
	case "ipinfo_lite":
		u := "https://api.ipinfo.io/lite/" + url.PathEscape(target.Value)
		var b json.RawMessage
		b, e = s.request(ctx, u, s.token)
		if e == nil {
			var data struct {
				IP            string `json:"ip"`
				ASN           string `json:"asn"`
				Name          string `json:"as_name"`
				Domain        string `json:"as_domain"`
				CountryCode   string `json:"country_code"`
				Country       string `json:"country"`
				ContinentCode string `json:"continent_code"`
				Continent     string `json:"continent"`
			}
			e = json.Unmarshal(b, &data)
			if e == nil && data.IP != target.Value {
				e = errors.New("IPinfo address mismatch")
			}
			if e == nil {
				result.Data, _ = json.Marshal(data)
				result.SourceURL = u
				result.ObservedAt = observedNow()
			}
		}
	case "asn_rank":
		result, e = s.asRank(ctx, target, q)
	case "rpki":
		result, e = s.rpki(ctx, target, q)
	case "asn_neighbours":
		if target.Kind != "asn" {
			result, e = s.neighbours(ctx, target, q)
			break
		}
		fallthrough
	default:
		endpoint := map[string]string{"prefix_overview": "prefix-overview", "routing_status": "routing-status", "looking_glass": "looking-glass", "routing_history": "routing-history", "registration": "whois", "registration_history": "historical-whois", "allocation_history": "allocation-history", "transfer_history": "transfer-history", "asn_overview": "as-overview", "asn_neighbours": "asn-neighbours"}[m.Name]
		params := url.Values{"resource": {target.Value}}
		if m.Name == "routing_history" {
			if q.StartTime != "" {
				params.Set("starttime", q.StartTime)
				params.Set("endtime", q.EndTime)
			} else {
				params.Set("starttime", time.Now().UTC().Add(-7*24*time.Hour).Format(time.RFC3339))
			}
			params.Set("max_rows", "300")
			params.Set("normalise_visibility", "true")
		}
		if m.Name == "registration_history" && q.Version != "" {
			params.Set("version", q.Version)
		}
		if m.Name == "prefix_overview" {
			params.Set("max_related", "20")
		}
		result, e = s.ripe(ctx, endpoint, params)
	}
	if e != nil {
		m.Status = "unavailable"
		m.Error = "Free upstream source unavailable or response invalid"
		if errors.Is(e, ErrNoData) {
			m.Status = "no_data"
			m.Error = "No observation in this source coverage"
			m.ObservedAt = observedNow()
		}
		if errors.Is(e, ErrBusy) {
			m.Status = "rate_limited"
			m.Error = "Upstream request budget reached; retry later"
		}
		var limited *sourceLimited
		if errors.As(e, &limited) {
			m.RetryAt = &limited.Until
		}
		return m
	}
	m.Status = "ok"
	m.Data = result.Data
	m.ObservedAt = result.ObservedAt
	m.SourceURL = result.SourceURL
	m.Registration = result.Registration
	if m.Name == "registration" {
		m.Registration = normalizeWhois(m.Data, m.SourceURL, target)
	}
	if m.Registration != nil {
		m.SourceUpdatedAt = registrationUpdatedAt(m.Registration)
	}
	return m
}
func (s *Service) origins(ctx context.Context, target Target, q Query) (string, []uint32, error) {
	name := "prefix_overview"
	if target.Kind == "ip" {
		name = "network_info"
	}
	params := url.Values{"resource": {target.Value}}
	endpoint := "prefix-overview"
	if name == "network_info" {
		endpoint = "network-info"
	}
	var m Metric
	var e error
	if target.Kind == "prefix" {
		if q.overview != nil {
			m = *q.overview
		} else {
			m = s.metric(ctx, target, Query{Resource: target.Value}, "prefix_overview")
		}
		if m.Status != "ok" {
			switch m.Status {
			case "no_data":
				return "", nil, ErrNoData
			case "rate_limited":
				if m.RetryAt != nil {
					return "", nil, &sourceLimited{Until: *m.RetryAt}
				}
				return "", nil, ErrBusy
			default:
				return "", nil, errors.New("origin observation unavailable")
			}
		}
	} else {
		m, e = s.ripe(ctx, endpoint, params)
	}
	if e != nil {
		return "", nil, e
	}
	var data struct {
		Prefix   string            `json:"prefix"`
		Resource string            `json:"resource"`
		ASNs     []json.RawMessage `json:"asns"`
	}
	if e = json.Unmarshal(m.Data, &data); e != nil {
		return "", nil, e
	}
	prefix := data.Prefix
	if target.Kind == "prefix" {
		prefix = target.Value
	}
	asns := []uint32{}
	if q.ASN != 0 {
		asns = append(asns, q.ASN)
	} else {
		for _, raw := range data.ASNs {
			if n := originASN(raw); n != 0 {
				asns = append(asns, n)
			}
		}
	}
	if len(asns) > 4 {
		asns = asns[:4]
	}
	if prefix == "" || len(asns) == 0 {
		return "", nil, ErrNoData
	}
	return prefix, asns, nil
}
func (s *Service) rpki(ctx context.Context, target Target, q Query) (Metric, error) {
	prefix, asns, e := s.origins(ctx, target, q)
	if e != nil {
		return Metric{}, e
	}
	results := []any{}
	for _, asn := range asns {
		m, e := s.ripe(ctx, "rpki-validation", url.Values{"resource": {strings.TrimPrefix(asnTarget(asn), "AS")}, "prefix": {prefix}})
		if e != nil {
			return Metric{}, e
		}
		results = append(results, map[string]any{"asn": asn, "source_url": m.SourceURL, "data": m.Data})
	}
	b, _ := json.Marshal(map[string]any{"prefix": prefix, "origins": results, "origin_limit": 4})
	return Metric{Data: b, ObservedAt: observedNow(), SourceURL: "https://stat.ripe.net/docs/data-api/api-endpoints/rpki-validation"}, nil
}
func (s *Service) neighbours(ctx context.Context, target Target, q Query) (Metric, error) {
	_, asns, e := s.origins(ctx, target, q)
	if e != nil {
		return Metric{}, e
	}
	results := []any{}
	for _, asn := range asns {
		m, e := s.ripe(ctx, "asn-neighbours", url.Values{"resource": {asnTarget(asn)}})
		if e != nil {
			return Metric{}, e
		}
		results = append(results, map[string]any{"asn": asn, "source_url": m.SourceURL, "data": m.Data})
	}
	b, _ := json.Marshal(map[string]any{"origins": results, "origin_limit": 4})
	return Metric{Data: b, ObservedAt: observedNow(), SourceURL: "https://stat.ripe.net/docs/data-api/api-endpoints/asn-neighbours"}, nil
}

func observedNow() *time.Time { at := time.Now().UTC(); return &at }

func originASN(raw json.RawMessage) uint32 {
	var object struct {
		ASN json.RawMessage `json:"asn"`
	}
	if len(raw) > 0 && raw[0] == '{' {
		if json.Unmarshal(raw, &object) != nil {
			return 0
		}
		raw = object.ASN
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		text = string(raw)
	}
	target, e := ParseTarget(text)
	if e != nil || target.Kind != "asn" {
		return 0
	}
	return target.ASN
}

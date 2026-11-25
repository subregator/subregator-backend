package intelligence

import (
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

type UpstreamStats struct {
	Source       string  `json:"source"`
	Requests     uint64  `json:"requests"`
	Failures     uint64  `json:"failures"`
	RateLimited  uint64  `json:"rate_limited"`
	AuthFailures uint64  `json:"auth_failures"`
	NoData       uint64  `json:"no_data"`
	DurationMS   float64 `json:"duration_ms"`
}

type CheckCoverage struct {
	DuePrefixes        int            `json:"due_prefixes"`
	SuppressedPrefixes int            `json:"suppressed_prefixes"`
	Running            int            `json:"running"`
	Name               string         `json:"name"`
	Source             string         `json:"source"`
	Collection         map[string]int `json:"collection"`
	Freshness          map[string]int `json:"freshness"`
	OldestAgeSeconds   *float64       `json:"oldest_age_seconds"`
}

type CollectionStatus struct {
	SchedulerPolicy            string          `json:"scheduler_policy"`
	DueJobs                    int             `json:"due_jobs"`
	RunningJobs                int             `json:"running_jobs"`
	GeneratedAt                time.Time       `json:"generated_at"`
	ProcessStartedAt           time.Time       `json:"process_started_at"`
	EligiblePrefixes           int             `json:"eligible_prefixes"`
	DuePrefixes                int             `json:"due_prefixes"`
	UnscheduledPrefixes        int             `json:"unscheduled_prefixes"`
	OldestDueSeconds           *float64        `json:"oldest_due_seconds"`
	Checks                     []CheckCoverage `json:"checks"`
	Upstreams                  []UpstreamStats `json:"upstreams"`
	RequestBudgetRPM           int             `json:"request_budget_rpm"`
	BudgetDenials              uint64          `json:"budget_denials"`
	BudgetWaits                uint64          `json:"budget_waits"`
	BudgetWaitSeconds          float64         `json:"budget_wait_seconds"`
	PersistenceFailures        uint64          `json:"persistence_failures"`
	SchedulerSweepFloorSeconds float64         `json:"scheduler_sweep_floor_seconds"`
	Semantics                  string          `json:"semantics"`
}

func upstreamName(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "other"
	}
	switch strings.ToLower(u.Hostname()) {
	case "stat.ripe.net":
		return "RIPEstat"
	case "data.iana.org":
		return "IANA RDAP bootstrap"
	case "rdap.arin.net", "rdap.db.ripe.net", "rdap.apnic.net", "rdap.lacnic.net", "rdap.afrinic.net":
		return "RIR RDAP"
	case "api.asrank.caida.org":
		return "CAIDA ASRank"
	case "api.ipinfo.io":
		return "IPinfo Lite"
	case "www.spamhaus.org":
		return "Spamhaus DROP"
	}
	return "other"
}

func (s *Service) recordRequest(raw string, status int, err error, elapsed time.Duration) {
	name := upstreamName(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.stats[name]
	r.Source = name
	r.Requests++
	r.DurationMS += float64(elapsed) / float64(time.Millisecond)
	if err != nil && status != 404 {
		r.Failures++
	}
	if status == 429 {
		r.RateLimited++
	}
	if status == 401 || status == 403 {
		r.AuthFailures++
	}
	if status == 404 {
		r.NoData++
	}
	s.stats[name] = r
	s.notifyBudget()
}

func (s *Service) notifyBudget() {
	close(s.budgetChanged)
	s.budgetChanged = make(chan struct{})
}

func (s *Service) persistenceFailed() {
	s.mu.Lock()
	s.persistenceFailures++
	s.mu.Unlock()
}

func (s *Service) recordBudgetWait(elapsed time.Duration) {
	s.mu.Lock()
	s.budgetWaits++
	s.budgetWaitDuration += elapsed
	s.mu.Unlock()
}

func publishedPrefixes(store *catalog.Store) map[string]bool {
	active := map[string]bool{}
	for _, offer := range store.View().Offers {
		if offer.Resource.Prefix != nil {
			if target, err := ParseTarget(*offer.Resource.Prefix); err == nil {
				active[target.Value] = true
			}
		}
	}
	return active
}

func (a *Automatic) Status(store *catalog.Store) CollectionStatus {
	now := time.Now().UTC()
	active := publishedPrefixes(store)
	out := CollectionStatus{GeneratedAt: now, EligiblePrefixes: len(active), Checks: []CheckCoverage{}, Upstreams: []UpstreamStats{}, SchedulerPolicy: "per_check_ttl", Semantics: "process_local_collection_health_not_subnet_safety"}
	names := []string{"prefix_overview", "rpki", "routing_status", "registration", "rdap", "spamhaus_drop"}
	a.mu.RLock()
	for key := range active {
		due, scheduled := a.due[key]
		if !scheduled {
			out.UnscheduledPrefixes++
		}
		if !scheduled || !due.IsZero() && !now.Before(due) {
			out.DuePrefixes++
			if scheduled {
				age := now.Sub(due).Seconds()
				if out.OldestDueSeconds == nil || age > *out.OldestDueSeconds {
					out.OldestDueSeconds = &age
				}
			}
		}
	}
	for _, name := range names {
		c := CheckCoverage{Name: name, Source: definitions[name].Source, Collection: map[string]int{}, Freshness: map[string]int{}}
		if name == "spamhaus_drop" {
			c.Source = "Spamhaus DROP"
		}
		for key := range active {
			if job, found := a.jobs[key][name]; found {
				if job.Next.IsZero() {
					c.SuppressedPrefixes++
				} else if !job.Next.After(now) {
					c.DuePrefixes++
					out.DueJobs++
				}
				if job.Running {
					c.Running++
					out.RunningJobs++
				}
			}
			o := observation("pending", nil, nil, now)
			var observed *time.Time
			if report, ok := a.reports[key]; ok {
				var check *Check
				switch name {
				case "prefix_overview":
					check = &report.BGP
				case "rpki":
					check = &report.RPKI
				case "spamhaus_drop":
					check = &report.Blocklist
				}
				if check != nil {
					o = checkObservation(*check, key, name, now)
					observed = check.ObservedAt
				}
			}
			useMetric := name != "prefix_overview" && name != "rpki"
			if observed == nil && o.CollectionStatus != "not_applicable" {
				useMetric = true
			}
			for _, m := range a.metrics[key] {
				if m.Name == name && useMetric {
					o = observation(m.Status, m.ObservedAt, m.ExpiresAt, now)
					observed = m.ObservedAt
				}
			}
			if observed == nil && (o.CollectionStatus == "pending" || o.CollectionStatus == "failed") && !a.service.network {
				o.CollectionStatus = "disabled"
			}
			c.Collection[o.CollectionStatus]++
			c.Freshness[o.Freshness]++
			if observed != nil && !observed.After(now) {
				age := now.Sub(*observed).Seconds()
				if c.OldestAgeSeconds == nil || age > *c.OldestAgeSeconds {
					c.OldestAgeSeconds = &age
				}
			}
		}
		out.Checks = append(out.Checks, c)
	}
	a.mu.RUnlock()
	s := a.service
	s.mu.Lock()
	out.ProcessStartedAt, out.RequestBudgetRPM = s.startedAt, s.rpm
	out.BudgetDenials, out.BudgetWaits, out.BudgetWaitSeconds = s.budgetDenials, s.budgetWaits, s.budgetWaitDuration.Seconds()
	out.PersistenceFailures = s.persistenceFailures
	for _, stats := range s.stats {
		out.Upstreams = append(out.Upstreams, stats)
	}
	s.mu.Unlock()
	sort.Slice(out.Upstreams, func(i, j int) bool { return out.Upstreams[i].Source < out.Upstreams[j].Source })
	return out
}

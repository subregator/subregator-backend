package intelligence

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

type scheduledCheck struct {
	Next     time.Time
	Failures int
	Running  bool
}

type checkWork struct {
	Context  context.Context
	Key      string
	Overview *Metric
}

type checkResult struct {
	Key, Name string
	Metric    Metric
	Blocklist Check
	Next      time.Time
}

func nextCheck(m Metric, previous scheduledCheck, now time.Time) scheduledCheck {
	next := scheduledCheck{}
	switch m.Status {
	case "disabled", "not_configured", "not_applicable":
		return next
	case "pending":
		next.Next = now
	case "ok", "no_data":
		if m.ExpiresAt != nil && m.ExpiresAt.After(now) {
			next.Next = *m.ExpiresAt
		} else {
			next.Next = now.Add(time.Minute)
		}
	default:
		next.Failures = min(previous.Failures+1, 5)
		next.Next = now.Add(min(15*time.Minute, time.Minute<<uint(next.Failures-1)))
	}
	if m.RetryAt != nil && m.RetryAt.After(next.Next) {
		next.Next = *m.RetryAt
	}
	return next
}

func (a *Automatic) Run(ctx context.Context, store *catalog.Store) {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	names := append(append([]string{}, automaticChecks...), "spamhaus_drop")
	queues := map[string]chan checkWork{}
	busy, cursors := map[string]bool{}, map[string]string{}
	cancels := map[string]map[string]context.CancelFunc{}
	dropInitialized := map[bool]bool{}
	results := make(chan checkResult, len(names))
	for _, name := range names {
		queue := make(chan checkWork, 1)
		queues[name] = queue
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case work := <-queue:
					result := checkResult{Key: work.Key, Name: name}
					workCtx := context.WithValue(work.Context, automaticBudgetKey{}, true)
					if name == "spamhaus_drop" {
						workCtx = context.WithValue(ctx, automaticBudgetKey{}, true)
						p := netip.MustParsePrefix(work.Key)
						feed := a.drop[p.Addr().Is4()]
						result.Blocklist = feed.check(workCtx, a.service, p, time.Now())
						if a.service.network {
							result.Next = feed.Next
							if feed.pendingSave {
								result.Next = minTime(result.Next, feed.retrySave)
							}
							if !result.Next.After(time.Now()) {
								result.Next = time.Now().Add(time.Minute)
							}
						}
					} else {
						result.Metric = a.service.metric(workCtx, Target{Value: work.Key, Kind: "prefix"}, Query{Resource: work.Key, overview: work.Overview}, name)
					}
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	for ctx.Err() == nil {
		active := publishedPrefixes(store)
		keys := make([]string, 0, len(active))
		for key := range active {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		a.mu.Lock()
		for key := range a.jobs {
			if !active[key] {
				for _, cancel := range cancels[key] {
					cancel()
				}
				delete(cancels, key)
				delete(a.jobs, key)
				delete(a.evidence, key)
				delete(a.reports, key)
				delete(a.metrics, key)
				delete(a.due, key)
			}
		}
		a.mu.Unlock()
		for _, key := range keys {
			if ctx.Err() != nil {
				return
			}
			a.mu.RLock()
			_, known := a.jobs[key]
			a.mu.RUnlock()
			if !known {
				a.restoreSchedule(ctx, key, names)
			}
		}
		a.mu.Lock()
		now := time.Now()
		for _, name := range names {
			if busy[name] {
				continue
			}
			start := sort.SearchStrings(keys, cursors[name])
			for i := 0; i < len(keys); i++ {
				key := keys[(start+i)%len(keys)]
				// One shared feed covers every prefix in a family; reserve the first single-request window for it.
				if name != "spamhaus_drop" && a.service.rpm == 1 && !dropInitialized[netip.MustParsePrefix(key).Addr().Is4()] {
					continue
				}
				job := a.jobs[key][name]
				if job.Next.IsZero() || job.Next.After(now) {
					continue
				}
				work := checkWork{Key: key}
				if name == "rpki" {
					overview, found := a.evidence[key]["prefix_overview"]
					if !found || a.jobs[key]["prefix_overview"].Running || (overview.Status != "ok" && overview.Status != "no_data") || overview.ExpiresAt == nil || !overview.ExpiresAt.After(now) {
						continue
					}
					work.Overview = &overview
				}
				job.Running = true
				workContext, workCancel := context.WithCancel(ctx)
				work.Context = workContext
				if cancels[key] == nil {
					cancels[key] = map[string]context.CancelFunc{}
				}
				cancels[key][name] = workCancel
				a.jobs[key][name] = job
				busy[name] = true
				cursors[name] = key + "\x00"
				queues[name] <- work
				break
			}
		}
		a.mu.Unlock()
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case result := <-results:
			timer.Stop()
			busy[result.Name] = false
			if cancel := cancels[result.Key][result.Name]; cancel != nil {
				cancel()
				delete(cancels[result.Key], result.Name)
			}
			if publishedPrefixes(store)[result.Key] {
				if result.Name == "spamhaus_drop" {
					dropInitialized[netip.MustParsePrefix(result.Key).Addr().Is4()] = true
				}
				a.completeCheck(ctx, result)
			}
		case <-timer.C:
		}
	}
}

func (a *Automatic) restoreSchedule(ctx context.Context, key string, names []string) {
	if a.service.cache != nil {
		b, _, found, err := a.service.cache.CacheGet(ctx, "automatic:"+key)
		if err != nil {
			a.service.persistenceFailed()
		}
		var report OfferChecks
		if err == nil && found && json.Unmarshal(b, &report) == nil && report.Resource == key {
			a.mu.Lock()
			a.reports[key] = report
			a.mu.Unlock()
		}
	}
	r, _ := a.service.Cached(ctx, Query{Resource: key, Checks: automaticChecks})
	a.mu.Lock()
	a.jobs[key] = map[string]scheduledCheck{}
	a.evidence[key] = map[string]Metric{}
	for _, name := range names {
		a.jobs[key][name] = scheduledCheck{Next: time.Now()}
	}
	for _, m := range r.Metrics {
		a.jobs[key][m.Name] = nextCheck(m, scheduledCheck{}, time.Now())
		if !a.service.network {
			a.jobs[key][m.Name] = scheduledCheck{}
		}
		if m.Name == "prefix_overview" || m.Name == "rpki" {
			a.evidence[key][m.Name] = compactEvidence(m)
		}
	}
	blocklist := a.reports[key].Blocklist
	if blocklist.Status == "" {
		blocklist = unknownCheck()
	}
	a.syncDue(key)
	a.mu.Unlock()
	a.publish(ctx, key, r, blocklist)
}

func (a *Automatic) completeCheck(ctx context.Context, result checkResult) {
	a.mu.Lock()
	jobs, exists := a.jobs[result.Key]
	if !exists {
		a.mu.Unlock()
		return
	}
	if result.Name == "spamhaus_drop" {
		jobs[result.Name] = scheduledCheck{Next: result.Next}
	} else {
		jobs[result.Name] = nextCheck(result.Metric, jobs[result.Name], time.Now())
		if result.Name == "prefix_overview" || result.Name == "rpki" {
			a.evidence[result.Key][result.Name] = compactEvidence(result.Metric)
		}
	}
	metrics := append([]Metric{}, a.metrics[result.Key]...)
	if result.Name != "spamhaus_drop" {
		replaced := false
		for i := range metrics {
			if metrics[i].Name == result.Name {
				metrics[i] = result.Metric
				replaced = true
			}
		}
		if !replaced {
			metrics = append(metrics, result.Metric)
		}
	}
	for i := range metrics {
		if evidence, ok := a.evidence[result.Key][metrics[i].Name]; ok {
			metrics[i] = evidence
		}
	}
	blocklist := a.reports[result.Key].Blocklist
	if result.Name == "spamhaus_drop" {
		blocklist = result.Blocklist
	}
	if blocklist.Status == "" {
		blocklist = unknownCheck()
	}
	a.syncDue(result.Key)
	a.mu.Unlock()
	a.publish(ctx, result.Key, Report{Resource: Target{Value: result.Key, Kind: "prefix"}, Metrics: metrics}, blocklist)
}

func (a *Automatic) syncDue(key string) {
	var due time.Time
	for _, job := range a.jobs[key] {
		if !job.Next.IsZero() && (due.IsZero() || job.Next.Before(due)) {
			due = job.Next
		}
	}
	a.due[key] = due
}

func compactEvidence(m Metric) Metric {
	if m.Name == "prefix_overview" {
		var data struct {
			Resource  string            `json:"resource"`
			Less      *bool             `json:"is_less_specific"`
			Announced *bool             `json:"announced"`
			Filtered  *int              `json:"num_filtered_out"`
			ASNs      []json.RawMessage `json:"asns"`
		}
		if json.Unmarshal(m.Data, &data) == nil {
			if len(data.ASNs) > 4 {
				n := len(data.ASNs) - 4
				if data.Filtered != nil {
					n += max(0, *data.Filtered)
				}
				data.Filtered = &n
				data.ASNs = data.ASNs[:4]
			}
			for i, raw := range data.ASNs {
				data.ASNs[i], _ = json.Marshal(map[string]uint32{"asn": originASN(raw)})
			}
			if len(data.Resource) <= 100 {
				m.Data, _ = json.Marshal(data)
				return m
			}
		}
	} else {
		var data struct {
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
		if json.Unmarshal(m.Data, &data) == nil && len(data.Prefix) <= 100 && len(data.Origins) <= 4 {
			valid := true
			for i := range data.Origins {
				o := &data.Origins[i]
				if len(o.Data.Prefix) > 100 || len(o.Data.Status) > 32 {
					valid = false
					break
				}
				o.Data.Resource, _ = json.Marshal(originASN(o.Data.Resource))
			}
			if valid {
				m.Data, _ = json.Marshal(data)
				return m
			}
		}
	}
	m.Data = json.RawMessage("null")
	return m
}

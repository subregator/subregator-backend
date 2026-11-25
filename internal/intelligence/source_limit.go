package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type sourceLimit struct {
	mu       sync.Mutex
	loaded   bool
	until    time.Time
	pending  bool
	deadline atomic.Pointer[time.Time]
}

type sourceBudgetKey struct{}

type sourceLimited struct{ Until time.Time }

func (e *sourceLimited) Error() string { return "source retry window is active" }
func (e *sourceLimited) Unwrap() error { return ErrBusy }

func retryAfter(raw string, now time.Time) time.Time {
	if seconds, err := strconv.ParseUint(raw, 10, 32); err == nil && seconds > 0 {
		return now.Add(time.Duration(seconds) * time.Second)
	}
	if date, err := http.ParseTime(raw); err == nil && date.After(now) {
		return date
	}
	return now.Add(time.Minute)
}

func (s *Service) sourceLimit(raw string) *sourceLimit {
	name := sourceLimitKey(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.limits[name] == nil {
		s.limits[name] = &sourceLimit{}
	}
	return s.limits[name]
}

func sourceLimitKey(raw string) string {
	name := upstreamName(raw)
	if name == "RIR RDAP" {
		u, _ := url.Parse(raw)
		name += ":" + strings.ToLower(u.Hostname())
	}
	return name
}

func (s *Service) saveSourceLimit(ctx context.Context, raw string, limit *sourceLimit) error {
	if s.cache == nil {
		limit.pending = false
		return nil
	}
	b, _ := json.Marshal(struct {
		Until time.Time `json:"until"`
	}{limit.until})
	err := s.cache.CachePut(ctx, "source_limit:"+sourceLimitKey(raw), b, limit.until)
	limit.pending = err != nil
	if err != nil {
		s.persistenceFailed()
	}
	return err
}

func (s *Service) checkSourceLimit(ctx context.Context, raw string) error {
	limit := s.sourceLimit(raw)
	limit.mu.Lock()
	defer limit.mu.Unlock()
	if !limit.loaded {
		if s.cache != nil {
			b, _, found, err := s.cache.CacheGet(ctx, "source_limit:"+sourceLimitKey(raw))
			if err != nil {
				s.persistenceFailed()
				return errors.New("source schedule unavailable")
			}
			if found {
				var stored struct {
					Until time.Time `json:"until"`
				}
				if json.Unmarshal(b, &stored) != nil || stored.Until.IsZero() {
					return errors.New("source schedule invalid")
				}
				limit.until = stored.Until
				deadline := limit.until
				limit.deadline.Store(&deadline)
			}
		}
		limit.loaded = true
	}
	if limit.pending && s.saveSourceLimit(ctx, raw, limit) != nil {
		return errors.New("source schedule persistence unavailable")
	}
	if time.Now().Before(limit.until) {
		return &sourceLimited{Until: limit.until}
	}
	return nil
}

func (s *Service) deferSource(ctx context.Context, raw, header string) time.Time {
	limit := s.sourceLimit(raw)
	limit.mu.Lock()
	defer limit.mu.Unlock()
	until := retryAfter(header, time.Now().UTC())
	if until.After(limit.until) {
		limit.until = until
	}
	limit.loaded = true
	deadline := limit.until
	limit.deadline.Store(&deadline)
	s.mu.Lock()
	s.notifyBudget()
	s.mu.Unlock()
	s.saveSourceLimit(ctx, raw, limit)
	return limit.until
}

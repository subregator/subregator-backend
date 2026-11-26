package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSlowRegistrationCannotBlockOtherPrefixes(t *testing.T) {
	var overviews atomic.Int32
	blocked := make(chan struct{})
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.Path, "/whois/"):
			select {
			case <-blocked:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
			return response(200, `{"status":"ok","data":{}}`), nil
		case strings.Contains(r.URL.Path, "prefix-overview"):
			overviews.Add(1)
			return response(200, fmt.Sprintf(`{"status":"ok","data":{"resource":%q,"asns":[{"asn":13335}],"announced":true,"is_less_specific":false,"num_filtered_out":0}}`, r.URL.Query().Get("resource"))), nil
		case strings.Contains(r.URL.Path, "rpki-validation"):
			return response(200, fmt.Sprintf(`{"status":"ok","data":{"prefix":%q,"resource":"13335","status":"valid"}}`, r.URL.Query().Get("prefix"))), nil
		case r.URL.Host == "www.spamhaus.org":
			return response(200, dropFixture(time.Now())), nil
		case r.URL.Host == "stat.ripe.net":
			return response(200, `{"status":"ok","data":{}}`), nil
		}
		return response(404, `{}`), nil
	})
	s.rpm = 600
	a := NewAutomatic(s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.Run(ctx, coverageStore(t, 3)) }()
	defer func() { cancel(); close(blocked); <-done }()
	deadline := time.Now().Add(time.Second)
	for overviews.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if overviews.Load() != 3 {
		t.Fatalf("slow registration blocked routing: %d/3 prefixes", overviews.Load())
	}
}

func TestSourceRetryAfterSurvivesRestart(t *testing.T) {
	cache := &memoryCache{}
	var calls atomic.Int32
	transport := roundTrip(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		r := response(429, `{}`)
		r.Header.Set("Retry-After", "3600")
		return r, nil
	})
	for i := 0; i < 2; i++ {
		s := New(cache, true, "", 120)
		s.client.Transport = transport
		s.request(context.Background(), "https://stat.ripe.net/data/whois/data.json", "")
	}
	if calls.Load() != 1 {
		t.Fatalf("restart bypassed source Retry-After: %d calls", calls.Load())
	}
}

func TestScheduleTTLBackoffAndSuppression(t *testing.T) {
	now := time.Now().UTC()
	expires := now.Add(6 * time.Hour)
	for _, status := range []string{"ok", "no_data"} {
		job := nextCheck(Metric{Status: status, ExpiresAt: &expires}, scheduledCheck{}, now)
		if !job.Next.Equal(expires) || job.Failures != 0 {
			t.Fatalf("%s ignored source TTL: %+v", status, job)
		}
	}
	job := scheduledCheck{}
	for i := 1; i <= 8; i++ {
		job = nextCheck(Metric{Status: "unavailable"}, job, now)
		want := min(15*time.Minute, time.Minute<<uint(min(i, 5)-1))
		if job.Next.Sub(now) != want {
			t.Fatalf("unbounded or missing backoff: %+v", job)
		}
	}
	for _, status := range []string{"disabled", "not_configured", "not_applicable"} {
		if next := nextCheck(Metric{Status: status}, job, now); !next.Next.IsZero() || next.Failures != 0 {
			t.Fatalf("terminal configuration retries: %+v", next)
		}
	}
	if next := nextCheck(Metric{Status: "rate_limited", RetryAt: &expires}, job, now); !next.Next.Equal(expires) {
		t.Fatal("Retry-After was shortened")
	}
}

func TestSourceCooldownIsIndependentAndUsesHTTPDate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	header := now.Add(time.Hour).Format(http.TimeFormat)
	if !retryAfter(header, now).Equal(now.Add(time.Hour)) {
		t.Fatal("HTTP-date Retry-After ignored")
	}
	var calls atomic.Int32
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if strings.EqualFold(r.URL.Host, "rdap.arin.net") {
			result := response(429, `{}`)
			result.Header.Set("Retry-After", header)
			return result, nil
		}
		return response(200, `{}`), nil
	})
	_, err := s.request(context.Background(), "https://RDAP.ARIN.NET/registry/ip/1.1.1.1", "")
	if !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if _, err := s.request(context.Background(), "https://rdap.apnic.net/ip/1.1.1.1", ""); err != nil {
		t.Fatalf("one RIR throttled another: %v", err)
	}
	s.request(context.Background(), "https://rdap.arin.net/registry/ip/8.8.8.8", "")
	if calls.Load() != 2 {
		t.Fatalf("source isolation/cooldown failed: %d", calls.Load())
	}
}

func TestSchedulerCancelsRemovedPrefix(t *testing.T) {
	started, canceled := make(chan struct{}), make(chan struct{})
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/whois/") {
			close(started)
			<-r.Context().Done()
			close(canceled)
			return nil, r.Context().Err()
		}
		if r.URL.Host == "www.spamhaus.org" {
			return response(200, dropFixture(time.Now())), nil
		}
		return response(404, `{}`), nil
	})
	s.rpm = 600
	store := coverageStore(t, 1)
	a := NewAutomatic(s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); a.Run(ctx, store) }()
	defer func() { cancel(); <-done }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("registration did not start")
	}
	if err := store.Apply("test", nil, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("removed prefix retained an active lookup")
	}
}

func TestCompactEvidenceIsBoundedAndConservative(t *testing.T) {
	r := reportFixture(t)
	for _, m := range r.Metrics {
		compact := compactEvidence(m)
		if len(compact.Data) > 4096 {
			t.Fatal("summary retained raw upstream payload")
		}
	}
	r.Metrics[0].Data = json.RawMessage(`{"resource":"1.1.1.0/24","asns":[1,2,3,4,5],"num_filtered_out":-1,"is_less_specific":false,"announced":true}`)
	r.Metrics[0] = compactEvidence(r.Metrics[0])
	var data struct {
		ASNs     []any `json:"asns"`
		Filtered int   `json:"num_filtered_out"`
	}
	if json.Unmarshal(r.Metrics[0].Data, &data) != nil || len(data.ASNs) != 4 || data.Filtered <= 0 {
		t.Fatalf("omitted origins were represented as complete: %s", r.Metrics[0].Data)
	}
}

func TestAutomaticBudgetWaitsAreFIFO(t *testing.T) {
	s := New(nil, true, "", 1)
	release, err := s.acquireRequest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), automaticBudgetKey{}, true))
	defer cancel()
	granted := make(chan int, 2)
	for id := 1; id <= 2; id++ {
		go func() {
			release, err := s.acquireRequest(ctx)
			if err == nil {
				release()
				granted <- id
			}
		}()
		deadline := time.Now().Add(time.Second)
		for {
			s.mu.Lock()
			queued := len(s.budgetQueue)
			s.mu.Unlock()
			if queued == id {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("request did not join FIFO")
			}
			time.Sleep(time.Millisecond)
		}
	}
	for expected := 1; expected <= 2; expected++ {
		s.mu.Lock()
		s.window = time.Now().Add(-time.Minute)
		s.notifyBudget()
		s.mu.Unlock()
		select {
		case id := <-granted:
			if id != expected {
				t.Fatalf("budget FIFO reordered requests: %d, want %d", id, expected)
			}
		case <-time.After(time.Second):
			t.Fatal("budget window did not resume the oldest request")
		}
	}
	s.mu.Lock()
	remaining := len(s.budgetQueue)
	s.mu.Unlock()
	if remaining != 0 || len(s.httpSlots) != 0 {
		t.Fatal("completed requests retained queue entries or slots")
	}
}

func TestQueuedSourceCooldownDoesNotSpendBudget(t *testing.T) {
	s := New(&memoryCache{}, true, "", 1)
	release, err := s.acquireRequest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), automaticBudgetKey{}, true))
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := s.request(ctx, "https://stat.ripe.net/data/whois/data.json", ""); done <- err }()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		waiting := len(s.budgetQueue)
		s.mu.Unlock()
		if waiting == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("request did not queue")
		}
		time.Sleep(time.Millisecond)
	}
	s.deferSource(context.Background(), "https://stat.ripe.net/data/whois/data.json", "3600")
	s.mu.Lock()
	s.used = 0
	s.window = time.Now()
	s.notifyBudget()
	s.mu.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, ErrBusy) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("throttled waiter did not leave the queue")
	}
	s.mu.Lock()
	used, queued := s.used, len(s.budgetQueue)
	s.mu.Unlock()
	if used != 0 || queued != 0 {
		t.Fatalf("throttled source consumed budget or queue capacity: used=%d queued=%d", used, queued)
	}
}

func TestSharedDROPSurvivesPrefixRemoval(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var downloads atomic.Int32
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "www.spamhaus.org" {
			downloads.Add(1)
			close(started)
			select {
			case <-release:
				return response(200, dropFixture(time.Now())), nil
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return response(404, `{}`), nil
	})
	s.rpm = 600
	store := coverageStore(t, 2)
	offers := store.View().Offers
	a := NewAutomatic(s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.Run(ctx, store) }()
	released := false
	defer func() {
		cancel()
		if !released {
			close(release)
		}
		<-done
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DROP download did not start")
	}
	if err := store.Apply("test", offers[1:], nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		a.mu.RLock()
		_, exists := a.jobs["11.0.0.0/24"]
		a.mu.RUnlock()
		if !exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("removed prefix not reconciled")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	released = true
	deadline = time.Now().Add(time.Second)
	for a.Get("11.0.1.0/24").Blocklist.Freshness != "fresh" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if a.Get("11.0.1.0/24").Blocklist.Freshness != "fresh" || downloads.Load() != 1 {
		t.Fatal("prefix removal canceled the shared reserved dataset")
	}
}

func TestPublicDemandReservesBudget(t *testing.T) {
	s := New(nil, true, "", 4)
	take := func(ctx context.Context) {
		t.Helper()
		release, err := s.acquireRequest(ctx)
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	take(context.Background())
	s.window = time.Now().Add(-time.Minute)
	automatic := context.WithValue(context.Background(), automaticBudgetKey{}, true)
	for range 3 {
		take(automatic)
	}
	ctx, cancel := context.WithTimeout(automatic, 20*time.Millisecond)
	defer cancel()
	if release, err := s.acquireRequest(ctx); err != context.DeadlineExceeded {
		if release != nil {
			release()
		}
		t.Fatalf("background consumed public reserve: %v", err)
	}
	take(context.Background())
	if _, err := s.acquireRequest(context.Background()); err != ErrBusy {
		t.Fatalf("global budget exceeded: %v", err)
	}
}

func TestAutomaticBudgetWithoutPublicDemand(t *testing.T) {
	for _, rpm := range []int{1, 4} {
		t.Run(fmt.Sprint(rpm), func(t *testing.T) {
			s := New(nil, true, "", rpm)
			if rpm == 1 {
				s.publicDemandUntil = time.Now().Add(time.Minute)
			}
			ctx := context.WithValue(context.Background(), automaticBudgetKey{}, true)
			for range rpm {
				release, err := s.acquireRequest(ctx)
				if err != nil {
					t.Fatal(err)
				}
				release()
			}
			if s.used != rpm {
				t.Fatalf("unused background capacity: %d", s.used)
			}
		})
	}
}

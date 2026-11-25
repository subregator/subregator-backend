package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/subregator/subregator-backend/internal/testdb"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/history"
	"github.com/subregator/subregator-backend/internal/intelligence"
)

func TestLocalLoad(t *testing.T) {
	if os.Getenv("SUBREGATOR_LOADTEST") != "1" {
		t.Skip("set SUBREGATOR_LOADTEST=1 for isolated local HTTP load tests")
	}
	fixtureStarted := time.Now()
	s := store(t, 10000)
	dsn := testdb.URL(t)
	d, err := history.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err = d.AcquireWriter(context.Background()); err != nil {
		t.Fatal(err)
	}
	offers := append([]catalog.Offer(nil), s.View().Offers...)
	for revision := 0; revision < 5; revision++ {
		for i := range offers {
			offers[i].Terms.Summary = fmt.Sprintf("revision %d", revision)
		}
		if err := d.Save(catalog.State{Version: 1, Offers: offers, Sources: s.View().Sources}, "test", time.Now(), true); err != nil {
			t.Fatal(err)
		}
	}
	events, err := d.Events(context.Background(), history.Query{Providers: []string{"test"}, AfterID: 49999, Limit: 2})
	if err != nil || len(events.Items) != 1 || events.Items[0].ID != 50000 {
		t.Fatal("unexpected history fixture", err)
	}
	testdb.Analyze(t, dsn)
	t.Logf("fixture_seconds=%.2f", time.Since(fixtureStarted).Seconds())
	t.Logf("fixture: offers=10000 events=50000 go=%s cpus=%d", runtime.Version(), runtime.NumCPU())
	limited := os.Getenv("SUBREGATOR_LOAD_LIMITS") == "1"
	transport := &http.Transport{MaxIdleConns: 256, MaxIdleConnsPerHost: 128}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	scenarios := []struct{ name, path, body string }{
		{"search", "/api/v1/offers?country=DE&currency=USD&sort=price_asc&limit=50", ""},
		{"history", "/api/v1/history?provider=test&limit=50", ""},
		{"history_network", "/api/v1/history?resource=10.39.15.0/24&limit=50", ""},
		{"resources", "/api/v1/resources?provider=test&limit=50", ""},
		{"mcp_search", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_offers","arguments":{"filters":{"country":"DE","currency":"USD","sort":"price_asc","limit":"50"}}}}`},
	}
	for _, scenario := range scenarios {
		for _, concurrency := range []int{1, 8, 32, 128} {
			t.Run(fmt.Sprintf("%s/c%d", scenario.name, concurrency), func(t *testing.T) {
				extras := Services{History: d, Automatic: intelligence.NewAutomatic(intelligence.New(d, false, "", 120))}
				if limited {
					extras.Limits = NewRequestLimits(100, 32)
				}
				server := httptest.NewServer(Handler(s, "", extras))
				defer server.Close()
				const count = 256
				latencies := make([]float64, count)
				codes := make([]int, count)
				failures := make([]bool, count)
				jobs := make(chan int, count)
				for i := 0; i < count; i++ {
					jobs <- i
				}
				close(jobs)
				var wg sync.WaitGroup
				started := time.Now()
				for w := 0; w < concurrency; w++ {
					wg.Go(func() {
						for i := range jobs {
							method := "GET"
							if scenario.body != "" {
								method = "POST"
							}
							req, _ := http.NewRequest(method, server.URL+scenario.path, bytes.NewBufferString(scenario.body))
							req.Header.Set("Content-Type", "application/json")
							req.Header.Set("Accept", "application/json, text/event-stream")
							req.Header.Set("MCP-Protocol-Version", "2025-11-25")
							at := time.Now()
							resp, e := client.Do(req)
							if e != nil {
								failures[i] = true
							} else {
								body, e := io.ReadAll(resp.Body)
								resp.Body.Close()
								codes[i] = resp.StatusCode
								failures[i] = e != nil || (resp.StatusCode != 200 && !(limited && (resp.StatusCode == 429 || resp.StatusCode == 503) && resp.Header.Get("Retry-After") == "1")) || (resp.StatusCode == 200 && ((scenario.body == "" && !json.Valid(body)) || (scenario.body != "" && (!bytes.Contains(body, []byte(`"result"`)) || bytes.Contains(body, []byte(`"isError":true`))))))
							}
							latencies[i] = float64(time.Since(at).Microseconds()) / 1000
						}
					})
				}
				wg.Wait()
				seconds := time.Since(started).Seconds()
				statuses := map[int]int{}
				for i, code := range codes {
					statuses[code]++
					if failures[i] {
						t.Errorf("request %d failed with status %d", i, code)
					}
				}
				successes := []float64{}
				for i, code := range codes {
					if code == 200 {
						successes = append(successes, latencies[i])
					}
				}
				slices.Sort(successes)
				if len(successes) == 0 {
					t.Fatal("no successful requests")
				}
				t.Logf("success_p95_ms=%.2f", successes[len(successes)*95/100])
				slices.Sort(latencies)
				t.Logf("requests=%d rps=%.1f p50_ms=%.2f p95_ms=%.2f p99_ms=%.2f statuses=%v", count, float64(count)/seconds, latencies[count/2], latencies[count*95/100], latencies[count*99/100], statuses)
			})
		}
	}
	t.Run("steady_50rps", func(t *testing.T) {
		extras := Services{History: d, Automatic: intelligence.NewAutomatic(intelligence.New(d, false, "", 120))}
		if limited {
			extras.Limits = NewRequestLimits(100, 32)
		}
		server := httptest.NewServer(Handler(s, "", extras))
		defer server.Close()
		const count = 500
		latencies := make([]float64, count)
		statuses := make([]int, count)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		var wg sync.WaitGroup
		started := time.Now()
		for i := 0; i < count; i++ {
			<-ticker.C
			wg.Go(func() {
				scenario := scenarios[i%len(scenarios)]
				method := "GET"
				if scenario.body != "" {
					method = "POST"
				}
				req, _ := http.NewRequest(method, server.URL+scenario.path, bytes.NewBufferString(scenario.body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "application/json, text/event-stream")
				req.Header.Set("MCP-Protocol-Version", "2025-11-25")
				at := time.Now()
				resp, e := client.Do(req)
				if e == nil {
					_, e = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					statuses[i] = resp.StatusCode
				}
				if e != nil || statuses[i] != 200 {
					t.Errorf("steady request %d failed: status=%d error=%v", i, statuses[i], e)
				}
				latencies[i] = float64(time.Since(at).Microseconds()) / 1000
			})
		}
		wg.Wait()
		seconds := time.Since(started).Seconds()
		slices.Sort(latencies)
		t.Logf("requests=%d rps=%.1f p50_ms=%.2f p95_ms=%.2f p99_ms=%.2f", count, float64(count)/seconds, latencies[count/2], latencies[count*95/100], latencies[count*99/100])
	})

}

package intelligence

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type recordingArchive struct {
	memoryCache
	records []ArchivedObservation
}

func (c *recordingArchive) SaveObservation(_ context.Context, r ArchivedObservation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, r)
	return nil
}

func TestCollectorArchivesNormalizedFactsAndFailures(t *testing.T) {
	for _, prefix := range []string{"1.1.1.0/24", "2001:4860::/32"} {
		cache := &recordingArchive{}
		s := New(cache, true, "", 120)
		if err := s.SetHistoryChecks("prefix_overview"); err != nil {
			t.Fatal(err)
		}
		failed := false
		s.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
			if failed {
				return response(503, `{"secret":"never-persist"}`), nil
			}
			return response(200, `{"status":"ok","data":{"resource":"`+prefix+`","announced":true,"is_less_specific":false,"num_filtered_out":0,"asns":[{"asn":13335}],"raw_secret":"never-persist"}}`), nil
		})
		q := Query{Resource: prefix, Checks: []string{"prefix_overview"}}
		if _, err := s.Inspect(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if len(cache.records) != 1 || !cache.records[0].Comparable || strings.Contains(string(cache.records[0].Evidence), "never-persist") {
			t.Fatal(cache.records)
		}
		if _, err := s.Cached(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Inspect(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if len(cache.records) != 1 {
			t.Fatal("cache read archived a poll")
		}
		cache.mu.Lock()
		for k, r := range cache.rows {
			r.expires = time.Now().Add(-time.Second)
			cache.rows[k] = r
		}
		cache.mu.Unlock()
		failed = true
		if _, err := s.Inspect(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if len(cache.records) != 2 || cache.records[1].Comparable || cache.records[1].Observation.CollectionStatus != "failed" {
			t.Fatal(cache.records)
		}
		b, _ := json.Marshal(cache.records)
		if strings.Contains(string(b), "never-persist") {
			t.Fatal(string(b))
		}
		for _, name := range []string{"abuse", "irr", "spamhaus_zen"} {
			s.archiveMetric(context.Background(), Target{Value: prefix, Kind: "prefix"}, Query{}, Metric{Name: name})
		}
		if len(cache.records) != 2 {
			t.Fatal("optional source archived")
		}
	}
}

func TestHistoryPolicyDefaultAndValidation(t *testing.T) {
	s := New(nil, false, "", 120)
	if len(s.HistoryChecks()) != 0 {
		t.Fatal("history defaults on")
	}
	for _, raw := range []string{"abuse", "irr", "spamhaus_zen", "rdap,rdap", "rpki,", "unknown"} {
		if s.SetHistoryChecks(raw) == nil {
			t.Fatal(raw)
		}
	}
	if err := s.SetHistoryChecks("prefix_overview,rpki,registration,rdap,spamhaus_drop"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetHistoryChecks(""); err != nil || len(s.HistoryChecks()) != 0 {
		t.Fatal(err)
	}
}

package intelligence

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func irrdStatusFixture(now time.Time) string {
	rows := []any{}
	for _, source := range []string{"RIPE", "RIPE-NONAUTH", "ARIN", "APNIC", "LACNIC", "AFRINIC"} {
		rows = append(rows, map[string]any{"source": source, "rpslDataUpdated": now.UTC().Format(time.RFC3339Nano), "objectClassFilter": []string{"route", "route6"}})
	}
	b, _ := json.Marshal(map[string]any{"data": map[string]any{"databaseStatus": rows}})
	return string(b)
}

func TestIRRdGraphQLNormalization(t *testing.T) {
	target, _ := ParseTarget("1.1.1.0/24")
	raw := `{"data":{"rpslObjects":[{"objectClass":"route","prefix":"1.1.1.0/24","origin":"AS13335","source":"APNIC","rpslPk":"1.1.1.0/24AS13335","objectText":"private-contact@example.net"},{"objectClass":"route","prefix":"1.1.0.0/16","origin":"AS13335","source":"RIPE","rpslPk":"1.1.0.0/16AS13335"}]}}`
	d, err := normalizeIRR([]byte(raw), []byte(irrdStatusFixture(time.Now())), target, time.Now())
	if err != nil || d.Completeness != "complete" || len(d.Objects) != 2 || len(d.Registries) != 6 || d.Objects[0].Relation != "exact" || d.Objects[1].Relation != "covering" {
		t.Fatalf("IRRd GraphQL result not normalized: %+v %v", d, err)
	}
	b, _ := json.Marshal(d)
	var fields map[string]any
	json.Unmarshal(b, &fields)
	if fields["metadata_url"] == "" || strings.Contains(string(b), "private-contact") {
		t.Fatal("missing normalized provenance")
	}
	for _, registry := range d.Registries {
		if registry.URL == "" || registry.TimestampKind != "mirror_data_updated" {
			t.Fatal("missing registry attribution or timestamp semantics", registry)
		}
	}
}

func TestIRRdRequestContract(t *testing.T) {
	calls := 0
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.URL.String() != DefaultIRRdURL || r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("unexpected mirror request", r.Method, r.URL)
		}
		var body struct {
			Query     string
			Variables map[string]json.RawMessage
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Fatal("invalid GraphQL request")
		}
		for _, field := range []string{"objectText", "adminC", "techC", "notify", "changed", "remarks"} {
			if strings.Contains(body.Query, field) {
				t.Fatal("requested contact/raw fields", field)
			}
		}
		var sources []string
		if json.Unmarshal(body.Variables["sources"], &sources) != nil || len(sources) != 6 || slices.Contains(sources, "RPKI") || slices.Contains(sources, "RADB") {
			t.Fatal("unbounded source coverage", sources)
		}
		if strings.Contains(body.Query, "databaseStatus") {
			return response(200, irrdStatusFixture(time.Now())), nil
		}
		if string(body.Variables["prefix"]) != `"1.1.1.0/24"` || string(body.Variables["limit"]) != "201" || !strings.Contains(body.Query, "ipAny:") || !strings.Contains(body.Query, "invalid") || !strings.Contains(body.Query, "suppressed") {
			t.Fatal("missing scope/limit or hiding conflicts", body)
		}
		return response(200, irrFixture("1.1.1.0/24", 13335)), nil
	})
	enableIRR(t, s)
	target, _ := ParseTarget("1.1.1.0/24")
	m, err := s.irr(context.Background(), target)
	if err != nil || calls != 2 || m.IRR == nil || m.IRR.Completeness != "complete" {
		t.Fatal(m, err, calls)
	}
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), "subregator-irrd") || strings.Contains(string(b), "private-contact") {
		t.Fatal("private upstream details leaked")
	}
	if s.stats["IRRd"].Requests != 2 {
		t.Fatal("mirror requests not attributed", s.stats)
	}
}

func TestIRRdGraphQLAndRowFailures(t *testing.T) {
	target, _ := ParseTarget("1.1.1.0/24")
	for _, raw := range []string{`{"data":null}`, `{"data":{"rpslObjects":null}}`, `{"data":{"rpslObjects":[]},"errors":[{"message":"private failure"}]}`} {
		if d, err := normalizeIRR([]byte(raw), []byte(irrdStatusFixture(time.Now())), target, time.Now()); err == nil {
			t.Fatal("GraphQL failure accepted", d)
		}
	}
	for _, row := range []string{
		`{"objectClass":"route","prefix":"1.1.1.0/24","origin":"AS0","source":"RIPE"}`,
		`{"objectClass":"route6","prefix":"1.1.1.0/24","origin":"AS13335","source":"RIPE"}`,
		`{"objectClass":"route","prefix":"1.1.1.0/24","origin":"AS13335","source":"RPKI"}`,
		`{"objectClass":"route","prefix":"1.1.1.0/24","origin":"AS13335","source":"RADB"}`,
		`{"objectClass":"route","prefix":"8.8.8.0/24","origin":"AS13335","source":"RIPE"}`,
		`{"objectClass":"route","prefix":"1.1.1.0/24","origin":"AS4294967296","source":"RIPE"}`,
		`{"objectClass":"route","prefix":"1.1.1.0/24","origin":"AS13335","source":"RIPE","rpslPk":"private-contact@example.net"}`,
	} {
		d, err := normalizeIRR([]byte(`{"data":{"rpslObjects":[`+row+`]}}`), []byte(irrdStatusFixture(time.Now())), target, time.Now())
		if err != nil || d.Completeness != "partial" {
			t.Fatal("malformed row established complete coverage", d, err)
		}
		b, _ := json.Marshal(d)
		if strings.Contains(string(b), "private-contact") {
			t.Fatal("unvalidated object key leaked")
		}
	}
}

func TestIRRdMetadataCoverage(t *testing.T) {
	target, _ := ParseTarget("1.1.1.0/24")
	var full map[string]any
	json.Unmarshal([]byte(irrdStatusFixture(time.Now())), &full)
	for _, kind := range []string{"missing", "duplicate", "classes", "future", "graphql_error"} {
		t.Run(kind, func(t *testing.T) {
			var meta map[string]any
			b, _ := json.Marshal(full)
			json.Unmarshal(b, &meta)
			data := meta["data"].(map[string]any)
			rows := data["databaseStatus"].([]any)
			switch kind {
			case "missing":
				data["databaseStatus"] = rows[:5]
			case "duplicate":
				data["databaseStatus"] = append(rows, rows[0])
			case "classes":
				rows[0].(map[string]any)["objectClassFilter"] = []string{"route"}
			case "future":
				rows[0].(map[string]any)["rpslDataUpdated"] = time.Now().Add(time.Hour).Format(time.RFC3339)
			case "graphql_error":
				meta["errors"] = []any{map[string]any{"message": "private failure"}}
			}
			b, _ = json.Marshal(meta)
			d, err := normalizeIRR([]byte(irrFixture(target.Value, 13335)), b, target, time.Now())
			if err != nil || d.Completeness != "partial" || len(d.Objects) != 1 || len(d.Registries) != 6 {
				t.Fatal("metadata gap hidden", d, err)
			}
		})
	}
}

func TestIRRdEndpointValidation(t *testing.T) {
	for _, endpoint := range []string{"", "ftp://mirror/graphql/", "http://mirror/graphql/?secret=private", "http://user:private@mirror/graphql/", "http://mirror/graphql/#private", "http://mirror:70000/graphql/", "http://mirror:/graphql/", "http://mirror/api/", " http://mirror/graphql/"} {
		s := New(nil, true, "", 120)
		if err := s.EnableIRR(endpoint); err == nil || strings.Contains(err.Error(), "private") || s.irrEnabled {
			t.Fatal("invalid endpoint accepted or disclosed", err)
		}
	}
}

func TestIRRdLive(t *testing.T) {
	endpoint := os.Getenv("SUBREGATOR_IRRD_LIVE_URL")
	if endpoint == "" {
		t.Skip("SUBREGATOR_IRRD_LIVE_URL required for private mirror probe")
	}
	s := New(nil, true, "", 120)
	if err := s.EnableIRR(endpoint); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"1.1.1.0/24", "2001:200:136::/48", "2001:4860:4860::/48"} {
		target, _ := ParseTarget(prefix)
		m := s.metric(context.Background(), target, Query{Resource: prefix}, "irr")
		if m.Status != "ok" || m.IRR == nil || m.IRR.Completeness != "complete" || len(m.IRR.Registries) != 6 {
			t.Fatal("private mirror contract failed", prefix, m)
		}
		if prefix != "2001:4860:4860::/48" && len(m.IRR.Objects) == 0 {
			t.Fatal("expected positive mirror observation", prefix)
		}
		if m.IRR.Status != "bgp_unavailable" || s.stats["RIPEstat"].Requests != 0 {
			t.Fatal("invented BGP comparison or queried RIS")
		}
		b, _ := json.Marshal(m)
		if strings.Contains(string(b), endpoint) || strings.Contains(string(b), "objectText") {
			t.Fatal("raw/private data leaked")
		}
		t.Logf("%s: objects=%d registries=%d complete; no BGP assertion", prefix, len(m.IRR.Objects), len(m.IRR.Registries))
		if dir := os.Getenv("SUBREGATOR_IRRD_LIVE_OUTPUT"); dir != "" {
			filename := "ipv4.json"
			if strings.Contains(prefix, ":") {
				filename = "ipv6.json"
			}
			if prefix == "2001:4860:4860::/48" {
				filename = "ipv6-missing.json"
			}
			if err := os.WriteFile(filepath.Join(dir, filename), b, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestIRRdRejectsRetiredEvidence(t *testing.T) {
	now, expires := time.Now().UTC(), time.Now().UTC().Add(time.Hour)
	detail := IRRExplanation{Prefix: "1.1.1.0/24", Completeness: "complete", Objects: []IRRObject{{Class: "route", Prefix: "1.1.1.0/24", Origin: 13335, Registry: "RADB", Relation: "exact"}}, Registries: []IRRRegistry{{Name: "RADB", UpdatedAt: &now, Freshness: "fresh"}}, MetadataURL: "https://irrexplorer.nlnog.net/api/metadata/"}
	b, _ := json.Marshal(detail)
	s := New(&memoryCache{}, true, "", 120)
	s.irrEnabled = true
	t.Run("metric cache", func(t *testing.T) {
		m := Metric{Name: "irr", Status: "ok", Source: "IRRexplorer", Data: b, ObservedAt: &now, ExpiresAt: &expires}
		raw, _ := json.Marshal(m)
		s.cache.CachePut(context.Background(), `{"Resource":"1.1.1.0/24","Name":"irr","Start":"","End":"","Version":"","ASN":0}`, raw, expires)
		r, err := s.Cached(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"irr"}})
		if err != nil || r.Metrics[0].IRR != nil || string(r.Metrics[0].Data) != "null" {
			t.Fatal("retired hosted-service evidence was published", r, err)
		}
	})
	t.Run("compact offer report", func(t *testing.T) {
		a := NewAutomatic(s)
		a.reports[detail.Prefix] = OfferChecks{IRR: &Check{Source: "IRRexplorer", Status: "consistent", Freshness: "fresh", IRR: &detail, ObservedAt: &now, ExpiresAt: &expires}}
		if c := a.Get(detail.Prefix).IRR; c == nil || c.IRR != nil || c.Status == "consistent" {
			t.Fatal("retired compact report was published", c)
		}
	})
}

func TestIRRdDoesNotSpendExternalBudget(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if irrMetadataRequest(r) {
			return response(200, irrdStatusFixture(time.Now())), nil
		}
		return response(200, irrFixture("1.1.1.0/24", 13335)), nil
	})
	enableIRR(t, s)
	s.rpm = 1
	release, err := s.acquireRequest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	target, _ := ParseTarget("1.1.1.0/24")
	m, err := s.irr(context.Background(), target)
	if err != nil || m.IRR == nil || m.IRR.Completeness != "complete" || s.used != 1 {
		t.Fatalf("private mirror consumed or waited for external allowance: %+v %v used=%d", m, err, s.used)
	}
	for range cap(s.httpSlots) {
		s.httpSlots <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := s.irrd(ctx, `query { databaseStatus { source } }`, nil); err != context.DeadlineExceeded {
		t.Fatal("mirror bypassed shared concurrency or cancellation", err)
	}
	for range cap(s.httpSlots) {
		<-s.httpSlots
	}
}

func TestIRRdSharesMetadataAcrossPrefixes(t *testing.T) {
	metadataCalls := 0
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		var body struct {
			Query     string
			Variables struct{ Prefix string }
		}
		json.NewDecoder(r.Body).Decode(&body)
		if strings.Contains(body.Query, "databaseStatus") {
			metadataCalls++
			return response(200, irrdStatusFixture(time.Now())), nil
		}
		return response(200, irrFixture(body.Variables.Prefix, 13335)), nil
	})
	enableIRR(t, s)
	var captured *time.Time
	for _, prefix := range []string{"1.1.1.0/24", "8.8.8.0/24", "9.9.9.0/24"} {
		target, _ := ParseTarget(prefix)
		m, err := s.irr(context.Background(), target)
		if err != nil || m.IRR == nil || m.IRR.Completeness != "complete" || m.IRR.MetadataObservedAt == nil {
			t.Fatal(m, err)
		}
		if captured != nil && !captured.Equal(*m.IRR.MetadataObservedAt) {
			t.Fatal("shared metadata capture time was rewritten")
		}
		captured = m.IRR.MetadataObservedAt
	}
	if metadataCalls != 1 || s.stats["IRRd"].Requests != 4 {
		t.Fatal("common metadata requested for every prefix", metadataCalls, s.stats)
	}
}

func TestIRRdMetadataRefreshAndCancellation(t *testing.T) {
	started, resume := make(chan struct{}), make(chan struct{})
	calls := 0
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			close(started)
			<-resume
		}
		return response(200, irrdStatusFixture(time.Now())), nil
	})
	enableIRR(t, s)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, _, err := s.mirrorMetadata(context.Background(), nil); err != nil {
			t.Error(err)
		}
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.mirrorMetadata(ctx, nil); err != context.Canceled {
		t.Fatal("metadata waiter ignored cancellation", err)
	}
	close(resume)
	<-done
	if _, _, err := s.mirrorMetadata(context.Background(), nil); err != nil || calls != 1 {
		t.Fatal("finished metadata not shared", calls, err)
	}
	s.irrdMetadata.observedAt = time.Now().Add(-6 * time.Minute)
	if _, _, err := s.mirrorMetadata(context.Background(), nil); err != nil || calls != 2 {
		t.Fatal("expired metadata not refreshed", calls, err)
	}
}

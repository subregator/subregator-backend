package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/subregator/subregator-backend/internal/catalog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + name)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestRealFormatFixtures(t *testing.T) {
	at := time.Now().UTC()
	offers, _, _, total, e := ParseOnie(read(t, "onie.json"), at)
	if e != nil || len(offers) != 2 || total != 2 {
		t.Fatal(e)
	}
	peak, e := ParsePeaktera(read(t, "peaktera.html"), at)
	if e != nil || len(peak) != 1 || len(peak[0].Quotes) != 4 {
		t.Fatal(e)
	}
	for _, list := range [][]catalog.Offer{offers, peak} {
		for _, o := range list {
			var p catalog.Provider
			for _, v := range catalog.Providers() {
				if v.ID == o.ProviderID {
					p = v
				}
			}
			if _, e := catalog.Normalize(o, p, at); e != nil {
				t.Fatal(e)
			}
		}
	}
	if peak[0].Quotes[0].MinimumMonths != nil {
		t.Fatal("billing term assumed to be contractual minimum")
	}
	if peak[0].Quotes[0].Fees[0].Amount.AmountMinor != 0 {
		t.Fatal("confirmed zero setup lost")
	}
	if offers[0].Quotes[0].Fees[1].Amount != nil {
		t.Fatal("unknown deposit became zero")
	}
}
func TestOniePaging(t *testing.T) {
	for _, mode := range []string{"good", "changed_total", "wrong_page", "duplicate", "short_page", "status"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				page := r.URL.Query().Get("page")
				n := calls
				prefix := "192.0.2.0/24"
				if page == "2" {
					prefix = "198.51.100.0/24"
				}
				total := 2
				if calls == 2 {
					switch mode {
					case "changed_total":
						total = 3
					case "wrong_page":
						n = 1
					case "duplicate":
						prefix = "192.0.2.0/24"
					case "short_page":
						fmt.Fprint(w, `{"available":true,"page":2,"per_page":1,"total":2,"items":[]}`)
						return
					case "status":
						w.WriteHeader(429)
						return
					}
				}
				fmt.Fprintf(w, `{"available":true,"page":%d,"per_page":1,"total":%d,"items":[{"prefix":%q,"price_cents":100,"rir":"arin"}]}`, n, total, prefix)
			}))
			defer srv.Close()
			out, e := LoadOnie(context.Background(), Client(), srv.URL, time.Now())
			if mode == "good" {
				if e != nil || len(out) != 2 || calls != 2 {
					t.Fatal(e, calls)
				}
			} else if e == nil {
				t.Fatal("invalid page accepted")
			}
		})
	}
}
func TestMalformedProviderPayloads(t *testing.T) {
	for _, b := range [][]byte{[]byte(`{}`), []byte(`{"available":true,"page":1,"per_page":0,"total":1}`), []byte(`{"available":true,"page":1,"per_page":1,"total":1,"items":[{"prefix":"192.0.2.0/24"}]}`)} {
		if _, _, _, _, e := ParseOnie(b, time.Now()); e == nil {
			t.Fatal("accepted malformed ONIE")
		}
	}
	for _, b := range [][]byte{[]byte("<html>challenge</html>"), []byte(`<div data-page="{&quot;props&quot;:{}}">`)} {
		if _, e := ParsePeaktera(b, time.Now()); e == nil {
			t.Fatal("accepted malformed Peaktera")
		}
	}
}
func TestPrefixBroker(t *testing.T) {
	b := read(t, "prefixbroker.html")
	offers, e := ParsePrefixBroker(b, time.Now())
	if e != nil || len(offers) != 2 {
		t.Fatal(e, len(offers))
	}
	var p catalog.Provider
	for _, x := range catalog.Providers() {
		if x.ID == "prefix-broker" {
			p = x
		}
	}
	for _, o := range offers {
		n, e := catalog.Normalize(o, p, time.Now())
		if e != nil || n.Resource.Prefix != nil || n.Geography.Basis != "seller_country" || n.Quotes[0].Price.Currency != "EUR" {
			t.Fatal(e, n)
		}
	}
	if offers[0].Quotes[0].Price.AmountMinor != 13516800 {
		t.Fatal("European money parsing")
	}
	if _, e = ParsePrefixBroker([]byte(strings.Replace(string(b), "Browse 2", "Browse 3", 1)), time.Now()); e == nil {
		t.Fatal("incomplete catalog accepted")
	}
}
func TestFeedValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feed.json")
	feed := Feed{SchemaVersion: 1, ProviderID: "test", Complete: true, Offers: []catalog.Offer{}}
	write := func() {
		b, _ := json.Marshal(feed)
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write()
	if o, e := ReadFeed(path, "test"); e != nil || len(o) != 0 {
		t.Fatal(e)
	}
	feed.Complete = false
	write()
	if _, e := ReadFeed(path, "test"); e == nil {
		t.Fatal("partial feed accepted")
	}
	feed.Complete = true
	write()
	if _, e := ReadFeed(path, "other"); e == nil {
		t.Fatal("wrong provider accepted")
	}
	os.WriteFile(path, []byte(`{"schema_version":1,"provider_id":"test","complete":true,"offers":[],"unexpected":true}`), 0600)
	if _, e := ReadFeed(path, "test"); e == nil {
		t.Fatal("unknown feed field accepted")
	}
}
func TestHTTPBoundsAndRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", 302)
			return
		}
		w.Write([]byte(strings.Repeat("a", maxBody+1)))
	}))
	defer srv.Close()
	for _, path := range []string{"/redirect", "/large"} {
		if _, e := fetch(context.Background(), Client(), srv.URL+path); e == nil {
			t.Fatal("unbounded response or redirect accepted")
		}
	}
}

func TestFeedRequiresObservationTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feed.json")
	f := Feed{SchemaVersion: 1, ProviderID: "test", Complete: true, Offers: []catalog.Offer{{ProviderID: "test"}}}
	b, _ := json.Marshal(f)
	os.WriteFile(path, b, 0600)
	if _, e := ReadFeed(path, "test"); e == nil {
		t.Fatal("undated feed accepted")
	}
}

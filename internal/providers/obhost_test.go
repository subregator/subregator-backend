package providers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

type providerTransport func(*http.Request) (*http.Response, error)

func (f providerTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestWorkerCollectsOBHostPublicInventory(t *testing.T) {
	p := catalog.Provider{ID: "obhost", Name: "OBHost", URL: "https://www.obhost.net/ip-subnet-leasing", Policy: catalog.Policy{Publication: "public_source", PrefixVisibility: "full", MinRefreshSeconds: 86400}}
	store, e := catalog.NewStore("", []catalog.Provider{p})
	if e != nil {
		t.Fatal(e)
	}
	fixture := read(t, "obhost.html")
	old := http.DefaultTransport
	http.DefaultTransport = providerTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.String() != p.URL {
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(fixture))), Header: make(http.Header)}, nil
	})
	defer func() { http.DefaultTransport = old }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); Run(ctx, store, "", true) }()
	deadline := time.After(2 * time.Second)
	for len(store.View().Offers) != 3 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("OBHost public inventory was not collected")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	<-done
	for _, o := range store.View().Offers {
		if o.Resource.Prefix == nil || o.Routing.RPKI != "" || o.Routing.BGP != "" {
			t.Fatal("public prefix lost or provider claims became check results")
		}
	}
}

func TestOBHostPreservesSourceMeaningAndRejectsIncompleteCatalogue(t *testing.T) {
	at := time.Now().UTC()
	fixture := string(read(t, "obhost.html"))
	offers, e := ParseOBHost([]byte(fixture), at)
	if e != nil || len(offers) != 3 {
		t.Fatalf("%v %+v", e, offers)
	}
	if offers[0].Quotes[0].Price.AmountMinor != 14000 || offers[1].Quotes[0].Price.AmountMinor != 26050 || offers[1].Availability != "unavailable" || len(offers[2].Quotes) != 0 {
		t.Fatal("money, reserved stock or unknown quote changed meaning")
	}
	if offers[0].Geography.Country != "" || offers[0].Geography.Basis != "unknown" || offers[1].Geography.Country != "PK" || offers[0].Resource.RIR != "" {
		t.Fatal("missing source information was inferred")
	}
	var provider catalog.Provider
	for _, p := range catalog.Providers() {
		if p.ID == "obhost" {
			provider = p
		}
	}
	for _, o := range offers {
		if _, e = catalog.Normalize(o, provider, at); e != nil {
			t.Fatal(e)
		}
	}
	euro, e := ParseOBHost([]byte(strings.Replace(fixture, ">USD<", ">EUR<", 1)), at)
	if e != nil || euro[0].Quotes[0].Price.Currency != "EUR" || euro[0].Quotes[0].Price.AmountMinor != 14000 {
		t.Fatal("source currency was converted or inferred")
	}
	for _, tc := range []struct{ name, old, next string }{
		{"wrong count", "<strong>3</strong>", "<strong>4</strong>"},
		{"truncated table", "</tbody>", ""},
		{"malformed row", "</tr>", ""},
		{"noncanonical prefix", "192.0.2.0", "192.0.2.1"},
		{"wrong address count", ">256<", ">512<"},
		{"unknown currency", ">USD<", ">JPY<"},
		{"changed state", "> Reserved<", "> Requested<"},
		{"changed billing", "/mo</span>", "/yr</span>"},
		{"invalid price", ">140<", ">140.123<"},
		{"missing quote", "ip-inv-price-contact", "different-marker"},
		{"mismatched prefix length", `data-size="/24"`, `data-size="/23"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := ParseOBHost([]byte(strings.Replace(fixture, tc.old, tc.next, 1)), at); e == nil {
				t.Fatal("invalid/incomplete source accepted")
			}
		})
	}
}

package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPeakteraAPI(t *testing.T) {
	at := time.Now().UTC()
	b := read(t, "peaktera.csv")
	offers, e := ParsePeaktera(b, at)
	if e != nil || len(offers) != 1 || len(offers[0].Quotes) != 4 {
		t.Fatalf("CSV: %v %+v", e, offers)
	}
	q := offers[0].Quotes[0]
	if q.Price.AmountMinor != 50000 || q.Fees[1].Amount.AmountMinor != 100000 || q.MinimumMonths == nil || *q.MinimumMonths != 1 {
		t.Fatal("billing or deposit lost", q)
	}
	for _, change := range [][2]string{{"1500.00", "500.00"}, {"500.00", "-1.00"}, {"term=monthly", "term=annual"}, {"USD", "bad"}} {
		if _, e := ParsePeaktera([]byte(strings.Replace(string(b), change[0], change[1], 1)), at); e == nil {
			t.Fatal("accepted invalid CSV", change)
		}
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 1 {
			if r.Header.Get("If-None-Match") != `"v1"` {
				t.Error("ETag missing")
			}
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write(b)
	}))
	defer server.Close()
	f := &peakteraFeed{}
	if _, e := f.load(context.Background(), Client(), server.URL, at); e != nil {
		t.Fatal(e)
	}
	next := at.Add(15 * time.Minute)
	got, e := f.load(context.Background(), Client(), server.URL, next)
	if e != nil || !got[0].ObservedAt.Equal(next) {
		t.Fatal("304 must validate retained offers", e)
	}
}

func TestPeakteraResponseAge(t *testing.T) {
	at := time.Now().UTC()
	b := read(t, "peaktera.csv")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Age", "3500")
		w.Header().Set("ETag", `"v1"`)
		if calls > 1 {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Write(b)
	}))
	defer server.Close()
	f := &peakteraFeed{}
	for i := 0; i < 2; i++ {
		offers, e := f.load(context.Background(), Client(), server.URL, at)
		if e != nil {
			t.Fatal(e)
		}
		if !offers[0].ObservedAt.Equal(at.Add(-3500 * time.Second)) {
			t.Fatal("cached response reset the publication deadline", offers[0].ObservedAt)
		}
		if offers[0].Publishable(at.Add(101 * time.Second)) {
			t.Fatal("cached response extended publication beyond one hour")
		}
	}
}

package intelligence

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestRDAPRedirectDoesNotCountAsFailure(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Host {
		case "data.iana.org":
			return response(200, `{"services":[[["163.0.0.0/8"],["https://rdap.apnic.net/"]]]}`), nil
		case "rdap.apnic.net":
			v := response(301, `{}`)
			v.Header.Set("Location", "https://rdap.db.ripe.net/ip/163.5.251.0")
			return v, nil
		case "rdap.db.ripe.net":
			return response(200, `{"handle":"test","startAddress":"163.5.251.0","endAddress":"163.5.251.255","entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@example.net"]]]}]}`), nil
		}
		t.Fatalf("unexpected request %s", r.URL.Host)
		return nil, nil
	})
	r, err := s.Inspect(context.Background(), Query{Resource: "163.5.251.0/24", Checks: []string{"rdap"}})
	if err != nil || r.Metrics[0].Status != "ok" {
		t.Fatalf("%v %+v", err, r)
	}
	stats := s.stats["RIR RDAP"]
	if stats.Requests != 2 || stats.Failures != 0 || stats.Redirects != 1 {
		t.Fatalf("successful RDAP referral counted as failure: %+v", stats)
	}
	work := s.workStats["rdap"]
	if work.SuccessfulChecks != 1 || work.FailedChecks != 0 || work.Redirects != 1 || work.HTTPAttempts != 3 || work.ExternalRequests != 3 {
		t.Fatal(work)
	}
}

func TestCheckWorkCountersAreBoundedAndSeparateOutcomes(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/data/prefix-overview/data.json":
			return response(200, `{"status":"ok","data":{"resource":"1.1.1.0/24","announced":true,"is_less_specific":false,"asns":[{"asn":13335}]}}`), nil
		case "/data/routing-status/data.json":
			return response(200, `{"status":"bad","data":{}}`), nil
		case "/data/rpki-validation/data.json":
			return response(404, `{}`), nil
		}
		return response(200, `{}`), nil
	})
	for _, name := range []string{"prefix_overview", "routing_status", "rpki"} {
		_, err := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{name}})
		if err != nil {
			t.Fatal(err)
		}
	}
	overview := s.workStats["prefix_overview"]
	routing := s.workStats["routing_status"]
	rpki := s.workStats["rpki"]
	if overview.HTTPAttempts != 1 || overview.ExternalRequests != 1 || overview.SuccessfulChecks != 1 {
		t.Fatalf("overview %+v", overview)
	}
	if routing.HTTPAttempts != 1 || routing.HTTPFailures != 0 || routing.FailedChecks != 1 {
		t.Fatalf("invalid normalized response %+v", routing)
	}
	if rpki.NoDataChecks != 1 || rpki.FailedChecks != 0 {
		t.Fatalf("no-data %+v", rpki)
	}
	ctx := context.WithValue(context.Background(), checkWorkKey{}, "https://secret/1.1.1.0/24")
	s.updateWork(ctx, func(w *CheckWorkStats) { w.DeferredChecks++ })
	if s.workStats["other"].DeferredChecks != 1 || len(s.workStats) != 4 {
		t.Fatal(s.workStats)
	}
	restart := New(nil, true, "", 120)
	if len(restart.workStats) != 0 || len(restart.stats) != 0 {
		t.Fatal("counters survived restart")
	}
}

func TestPrivateWorkAndBudgetWaits(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) { return response(200, `{}`), nil })
	ctx := context.WithValue(context.Background(), checkWorkKey{}, "irr")
	if _, err := s.readSource(ctx, s.irrdURL, "", 1024, true); err != nil {
		t.Fatal(err)
	}
	if stats := s.workStats["irr"]; stats.PrivateRequests != 1 || stats.ExternalRequests != 0 || stats.HTTPAttempts != 1 {
		t.Fatal(stats)
	}
	s.rpm = 1
	s.used = 1
	s.window = time.Now()
	if _, err := s.acquireRequest(ctx); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	waiting, cancel := context.WithTimeout(context.WithValue(ctx, automaticBudgetKey{}, true), 10*time.Millisecond)
	defer cancel()
	if _, err := s.acquireRequest(waiting); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	stats := s.workStats["irr"]
	if stats.BudgetWaits == 0 || stats.BudgetWaitSeconds <= 0 || stats.BudgetDenials != 1 || stats.ExternalRequests != 0 {
		t.Fatal(stats)
	}
}

func TestRejectedRDAPReferralIsFinalCheckFailure(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "data.iana.org" {
			return response(200, `{"services":[[["163.0.0.0/8"],["https://rdap.apnic.net/"]]]}`), nil
		}
		v := response(302, `{}`)
		v.Header.Set("Location", "https://example.net/ip/163.5.251.0")
		return v, nil
	})
	r, err := s.Inspect(context.Background(), Query{Resource: "163.5.251.0/24", Checks: []string{"rdap"}})
	if err != nil || r.Metrics[0].Status != "unavailable" {
		t.Fatal(err, r)
	}
	stats := s.workStats["rdap"]
	if stats.Redirects != 1 || stats.FailedChecks != 1 || stats.HTTPFailures != 0 || stats.ExternalRequests != 2 {
		t.Fatal(stats)
	}
}

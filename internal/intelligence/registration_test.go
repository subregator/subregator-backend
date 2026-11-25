package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRDAPRegistrationEnvelopeAndContacts(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "abuse-contact-finder") {
			t.Fatal("published abuse contact triggered an additional lookup")
		}
		if r.URL.Host == "data.iana.org" {
			return response(200, `{"services":[[["1.0.0.0/8"],["https://rdap.apnic.net/"]]]}`), nil
		}
		return response(200, `{"handle":"NET-EXAMPLE","name":"NETWORK-LABEL","startAddress":"1.1.0.0","endAddress":"1.1.255.255","entities":[{"handle":"ORG-EXAMPLE","roles":["registrant"],"vcardArray":["vcard",[["kind",{},"text","org"],["fn",{},"text","Example Network Ltd"]]],"entities":[{"handle":"ABUSE-EXAMPLE","roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@example.net"]]]}]}]}`), nil
	})
	r, err := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"rdap"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r.Metrics[0])
	var fields map[string]json.RawMessage
	json.Unmarshal(b, &fields)
	var registration struct {
		RIR           string `json:"rir"`
		AbuseContacts []struct {
			Email string `json:"email"`
		} `json:"abuse_contacts"`
	}
	if json.Unmarshal(fields["registration"], &registration) != nil || registration.RIR != "APNIC" || len(registration.AbuseContacts) != 1 || registration.AbuseContacts[0].Email != "abuse@example.net" {
		t.Fatalf("missing normalized registration: %s", b)
	}
}

func TestRDAPRejectsUnrelatedRange(t *testing.T) {
	s := mockService(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "data.iana.org" {
			return response(200, `{"services":[[["1.0.0.0/8"],["https://rdap.apnic.net/"]]]}`), nil
		}
		return response(200, `{"handle":"WRONG-NETWORK","startAddress":"8.8.8.0","endAddress":"8.8.8.255"}`), nil
	})
	r, err := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"rdap"}})
	if err != nil || r.Metrics[0].Status != "unavailable" {
		t.Fatal(fmt.Sprintf("unrelated registration accepted: %+v %v", r, err))
	}
}

func TestAllRIRRegistrationShapes(t *testing.T) {
	for _, tc := range []struct {
		rir, host string
		org       any
		kind      string
		uri       bool
	}{
		{"ARIN", "rdap.arin.net", "Example Inc", "org", false},
		{"RIPE NCC", "rdap.db.ripe.net", []string{"Example GmbH", "Network"}, "org", true},
		{"APNIC", "rdap.apnic.net", "Example Pty Ltd", "", false},
		{"LACNIC", "rdap.lacnic.net", "Exemplo Redes", "org", false},
		{"AFRINIC", "rdap.afrinic.net", "Example Networks", "org", false},
	} {
		t.Run(tc.rir, func(t *testing.T) {
			email, emailType := "abuse@example.net", "text"
			if tc.uri {
				email, emailType = "mailto:"+email, "uri"
			}
			card := []any{"vcard", []any{[]any{"kind", map[string]any{}, "text", tc.kind}, []any{"fn", map[string]any{}, "text", "PUBLIC REGISTRANT"}, []any{"org", map[string]any{}, "text", tc.org}}}
			abuse := map[string]any{"roles": []string{"abuse"}, "vcardArray": []any{"vcard", []any{[]any{"email", map[string]any{}, emailType, email}}}}
			payload, _ := json.Marshal(map[string]any{"objectClassName": "ip network", "handle": "NET-EXAMPLE", "name": "NETWORK-LABEL", "country": "de", "type": "ALLOCATED", "startAddress": "1.1.0.0", "endAddress": "1.1.255.255", "status": []string{"active"}, "events": []any{map[string]string{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}, map[string]string{"eventAction": "last changed", "eventDate": "2025-01-01T00:00:00Z"}}, "entities": []any{map[string]any{"handle": "ORG-EXAMPLE", "roles": []string{"registrant"}, "vcardArray": card, "entities": []any{abuse}}}})
			target, _ := ParseTarget("1.1.1.0/24")
			r, err := normalizeRDAP(payload, "https://"+tc.host+"/ip/1.1.1.0", target)
			if err != nil || r.RIR != tc.rir || len(r.Records) != 1 || r.Records[0].Range.Relation != "covering" || len(r.AbuseContacts) != 1 || r.AbuseContacts[0].Verification != "not_verified" {
				t.Fatalf("invalid normalized fixture: %+v %v", r, err)
			}
			if r.Records[0].Name == r.Records[0].Entities[0].Organization || r.Records[0].Country != "DE" || registrationUpdatedAt(r) == nil {
				t.Fatalf("network/organization/date semantics lost: %+v", r)
			}
		})
	}
}

func TestRegistrationRangeScopeAndMalformedFields(t *testing.T) {
	for _, tc := range []struct{ resource, start, end, relation string }{
		{"1.1.1.0/24", "1.1.1.0", "1.1.1.255", "exact"},
		{"1.1.0.0/16", "1.1.0.0", "1.1.0.255", "contained"},
		{"1.1.1.0/24", "1.1.0.0", "1.1.1.127", "overlap"},
		{"2001:4860:4860::/48", "2001:4860::", "2001:4860:ffff:ffff:ffff:ffff:ffff:ffff", "covering"},
	} {
		target, _ := ParseTarget(tc.resource)
		scope, err := ipRegistryRange(tc.start, tc.end, target, true)
		if err != nil || scope.Relation != tc.relation {
			t.Fatalf("wrong range relation: %+v %v", scope, err)
		}
	}
	target, _ := ParseTarget("1.1.1.0/24")
	for _, payload := range []string{
		`{"handle":"missing-range"}`,
		`{"handle":"reversed","startAddress":"1.1.1.255","endAddress":"1.1.1.0"}`,
		`{"handle":"wrong-family","startAddress":"2001:4860::","endAddress":"2001:4860:ffff::"}`,
		`{"handle":"wrong-first-address","startAddress":"1.1.1.128","endAddress":"1.1.1.255"}`,
		`{"handle":"wrong-class","objectClassName":"autnum","startAddress":"1.1.1.0","endAddress":"1.1.1.255"}`,
	} {
		if _, err := normalizeRDAP(json.RawMessage(payload), "https://rdap.apnic.net/ip/1.1.1.0", target); err == nil {
			t.Fatal("invalid response accepted", payload)
		}
	}
	asn, _ := ParseTarget("AS13335")
	first, last := uint32(13300), uint32(13400)
	if scope, err := asnRegistryRange(&first, &last, asn); err != nil || scope.Relation != "covering" {
		t.Fatal(scope, err)
	}
}

func TestAbuseFallbackOnlyWhenNeededAndFailureRetainsRegistration(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			fallbackCalls := 0
			s := mockService(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "data.iana.org" {
					return response(200, `{"services":[[["1.0.0.0/8"],["https://rdap.apnic.net/"]]]}`), nil
				}
				if strings.Contains(r.URL.Path, "abuse-contact-finder") {
					fallbackCalls++
					if failed {
						return response(503, `{}`), nil
					}
					return response(200, `{"status":"ok","data":{"abuse_contacts":["role@example.net"],"authoritative_rir":"apnic","parameters":{"resource":"1.1.1.0/24"}}}`), nil
				}
				return response(200, `{"handle":"NET-EXAMPLE","startAddress":"1.1.1.0","endAddress":"1.1.1.255","entities":[{"roles":["technical"],"vcardArray":["vcard",[["email",{},"text","not-abuse@example.net"]]]}]}`), nil
			})
			r, err := s.Inspect(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"rdap"}})
			if err != nil || r.Metrics[0].Status != "ok" || fallbackCalls != 1 {
				t.Fatal(r, err, fallbackCalls)
			}
			reg := r.Metrics[0].Registration
			if failed {
				if reg.AbuseStatus != "unavailable" || reg.Completeness != "partial" {
					t.Fatal(reg)
				}
			} else if len(reg.AbuseContacts) != 1 || reg.AbuseContacts[0].Source != "ripe_stat_abuse_contact_finder" {
				t.Fatal(reg)
			}
			cached, err := s.Cached(context.Background(), Query{Resource: "1.1.1.0/24", Checks: []string{"rdap"}})
			if err != nil || fallbackCalls != 1 {
				t.Fatal("cached read triggered fallback")
			}
			got, _ := json.Marshal(cached.Metrics[0].Registration)
			want, _ := json.Marshal(reg)
			if string(got) != string(want) {
				t.Fatalf("cached registration changed: %s != %s", got, want)
			}
		})
	}
}

func TestWhoisNormalizationAndLegacyCache(t *testing.T) {
	target, _ := ParseTarget("1.1.1.0/24")
	raw := json.RawMessage(`{"authorities":["apnic"],"records":[[{"key":"inetnum","value":"1.1.0.0 - 1.1.255.255"},{"key":"netname","value":"NETWORK-LABEL"},{"key":"org","value":"ORG-EXAMPLE"},{"key":"org-name","value":"Example Ltd"},{"key":"abuse-mailbox","value":"abuse@example.net"},{"key":"last-modified","value":"2025-01-01T00:00:00Z"}]],"irr_records":[[{"key":"abuse-mailbox","value":"ignore-irr@example.net"}]]}`)
	r := normalizeWhois(raw, "https://stat.ripe.net/data/whois/data.json?resource=1.1.1.0%2F24", target)
	if r.RIR != "APNIC" || len(r.Records) != 1 || r.Records[0].Range.Relation != "covering" || r.Records[0].Entities[0].Role != "referenced" || len(r.AbuseContacts) != 1 {
		t.Fatalf("wrong WHOIS projection: %+v", r)
	}
	s := New(&memoryCache{}, true, "", 120)
	now, expires := time.Now(), time.Now().Add(time.Hour)
	m := Metric{Name: "registration", Status: "ok", ObservedAt: &now, ExpiresAt: &expires, Data: raw, SourceURL: "https://stat.ripe.net/data/whois/data.json"}
	payload, _ := json.Marshal(m)
	s.cache.CachePut(context.Background(), metricKey(target, Query{}, "registration"), payload, expires)
	report, err := s.Cached(context.Background(), Query{Resource: target.Value, Checks: []string{"registration"}})
	if err != nil || report.Metrics[0].Registration == nil || report.Metrics[0].ObservedAt != nil && !report.Metrics[0].ObservedAt.Equal(now) {
		t.Fatal("legacy cache did not normalize without changing provenance", report, err)
	}
}

func TestNestedRegistrantDoesNotBecomeNetworkRegistrant(t *testing.T) {
	target, _ := ParseTarget("1.1.1.0/24")
	raw := json.RawMessage(`{"handle":"NET-EXAMPLE","startAddress":"1.1.1.0","endAddress":"1.1.1.255","entities":[{"roles":["registrant"],"handle":"DIRECT","entities":[{"roles":["registrant"],"handle":"NESTED"}]},{"roles":["technical"],"entities":[{"roles":["registrant"],"handle":"TECHNICAL-REGISTRANT"},{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@example.net"]]]}]}]}`)
	r, err := normalizeRDAP(raw, "https://rdap.apnic.net/ip/1.1.1.0", target)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Records[0].Entities) != 1 || r.Records[0].Entities[0].Handle != "DIRECT" {
		t.Fatalf("nested entity role attributed to network: %+v", r.Records[0].Entities)
	}
	if len(r.AbuseContacts) != 1 {
		t.Fatal("nested abuse contact was lost", r)
	}
}

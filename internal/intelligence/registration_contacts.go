package intelligence

import (
	"context"
	"encoding/json"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

func (s *Service) abuseContactFallback(ctx context.Context, target Target, registration *Registration) {
	resource := target.Value
	if target.Kind == "prefix" && len(registration.Records) > 0 {
		relation := registration.Records[0].Range.Relation
		if relation == "contained" || relation == "overlap" {
			resource = netip.MustParsePrefix(target.Value).Addr().String()
		}
	}
	m, err := s.ripe(ctx, "abuse-contact-finder", url.Values{"resource": {resource}})
	if err != nil {
		registration.AbuseStatus = "unavailable"
		registration.issue("abuse_contact_lookup_unavailable")
		return
	}
	var data struct {
		Contacts   []string `json:"abuse_contacts"`
		RIR        string   `json:"authoritative_rir"`
		Parameters struct {
			Resource string `json:"resource"`
		} `json:"parameters"`
	}
	if json.Unmarshal(m.Data, &data) != nil || data.Contacts == nil {
		registration.AbuseStatus = "unavailable"
		registration.issue("invalid_abuse_contact_response")
		return
	}
	if data.RIR != "" && canonicalRIR(data.RIR) != registration.RIR {
		registration.AbuseStatus = "unavailable"
		registration.issue("abuse_contact_rir_mismatch")
		return
	}
	if data.Parameters.Resource != "" {
		actual, e := ParseTarget(data.Parameters.Resource)
		expected, _ := ParseTarget(resource)
		if e != nil || actual != expected {
			registration.AbuseStatus = "unavailable"
			registration.issue("abuse_contact_resource_mismatch")
			return
		}
	}
	for i, email := range data.Contacts {
		if i == 32 {
			registration.issue("abuse_contact_limit")
			break
		}
		registration.addContact(email, "", "ripe_stat_abuse_contact_finder", m.SourceURL, resource)
	}
}

func registrationUpdatedAt(r *Registration) *time.Time {
	var latest *time.Time
	for _, record := range r.Records {
		for _, event := range record.Events {
			if !strings.EqualFold(event.Action, "last changed") {
				continue
			}
			if at, err := time.Parse(time.RFC3339, event.Date); err == nil && (latest == nil || at.After(*latest)) {
				at = at.UTC()
				latest = &at
			}
		}
	}
	return latest
}

func decorateRegistration(m Metric, target Target) Metric {
	if m.Status != "ok" && m.Status != "stale" || m.ObservedAt == nil {
		return m
	}
	if m.Registration == nil {
		switch m.Name {
		case "rdap":
			var err error
			m.Registration, err = normalizeRDAP(m.Data, m.SourceURL, target)
			if err != nil {
				m.Status = "unavailable"
				m.Error = "Cached RDAP registration is invalid for the requested resource"
				return m
			}
		case "registration":
			m.Registration = normalizeWhois(m.Data, m.SourceURL, target)
		}
	}
	if m.Registration != nil && m.SourceUpdatedAt == nil {
		m.SourceUpdatedAt = registrationUpdatedAt(m.Registration)
	}
	return m
}

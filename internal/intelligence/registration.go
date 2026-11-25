package intelligence

import (
	"encoding/json"
	"errors"
	"net/mail"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Registration struct {
	RIR           string           `json:"rir,omitempty"`
	SourceKind    string           `json:"source_kind"`
	Completeness  string           `json:"completeness"`
	Authorities   []string         `json:"authorities"`
	Records       []RegistryRecord `json:"records"`
	AbuseContacts []AbuseContact   `json:"abuse_contacts"`
	AbuseStatus   string           `json:"abuse_status"`
	Issues        []string         `json:"issues"`
	Semantics     string           `json:"semantics"`
}

type RegistryRange struct {
	Kind         string  `json:"kind"`
	Resource     string  `json:"resource"`
	Relation     string  `json:"relation"`
	StartAddress string  `json:"start_address,omitempty"`
	EndAddress   string  `json:"end_address,omitempty"`
	StartASN     *uint32 `json:"start_asn,omitempty"`
	EndASN       *uint32 `json:"end_asn,omitempty"`
}

type RegistryRecord struct {
	Handle    string           `json:"handle,omitempty"`
	Name      string           `json:"name,omitempty"`
	Type      string           `json:"type,omitempty"`
	Country   string           `json:"country,omitempty"`
	SourceURL string           `json:"source_url"`
	Range     RegistryRange    `json:"range"`
	Statuses  []string         `json:"statuses"`
	Entities  []RegistryEntity `json:"entities"`
	Events    []RegistryEvent  `json:"events"`
}

type RegistryEntity struct {
	Handle       string   `json:"handle,omitempty"`
	Name         string   `json:"name,omitempty"`
	Kind         string   `json:"kind"`
	Organization string   `json:"organization,omitempty"`
	Role         string   `json:"role"`
	Statuses     []string `json:"statuses"`
}

type RegistryEvent struct {
	Action string `json:"action"`
	Date   string `json:"date"`
}

type AbuseContact struct {
	Email        string `json:"email"`
	EntityHandle string `json:"entity_handle,omitempty"`
	Source       string `json:"source"`
	SourceURL    string `json:"source_url"`
	Resource     string `json:"resource"`
	Verification string `json:"verification"`
}

type rdapData struct {
	ObjectClass  string          `json:"objectClassName,omitempty"`
	Handle       string          `json:"handle"`
	Name         string          `json:"name"`
	Type         string          `json:"type"`
	Country      string          `json:"country"`
	StartAddress string          `json:"startAddress,omitempty"`
	EndAddress   string          `json:"endAddress,omitempty"`
	StartAutnum  *uint32         `json:"startAutnum,omitempty"`
	EndAutnum    *uint32         `json:"endAutnum,omitempty"`
	Entities     json.RawMessage `json:"entities,omitempty"`
	Events       json.RawMessage `json:"events,omitempty"`
	Notices      json.RawMessage `json:"notices,omitempty"`
	Links        json.RawMessage `json:"links,omitempty"`
	Status       []string        `json:"status,omitempty"`
}

func newRegistration(kind string) *Registration {
	return &Registration{SourceKind: kind, Completeness: "complete", Authorities: []string{}, Records: []RegistryRecord{}, AbuseContacts: []AbuseContact{}, AbuseStatus: "not_published", Issues: []string{}, Semantics: "public_registry_records_not_beneficial_ownership_or_selling_authority"}
}

func (r *Registration) issue(code string) {
	r.Completeness = "partial"
	if !slices.Contains(r.Issues, code) {
		r.Issues = append(r.Issues, code)
	}
}

func (r *Registration) text(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
		r.issue("invalid_or_oversized_field")
		return ""
	}
	return value
}

func canonicalRIR(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ripe", "ripe ncc", "ripencc":
		return "RIPE NCC"
	case "arin":
		return "ARIN"
	case "apnic":
		return "APNIC"
	case "lacnic":
		return "LACNIC"
	case "afrinic":
		return "AFRINIC"
	}
	return ""
}

func rirForURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return ""
	}
	switch strings.ToLower(u.Hostname()) {
	case "rdap.arin.net":
		return "ARIN"
	case "rdap.db.ripe.net":
		return "RIPE NCC"
	case "rdap.apnic.net":
		return "APNIC"
	case "rdap.lacnic.net":
		return "LACNIC"
	case "rdap.afrinic.net":
		return "AFRINIC"
	}
	return ""
}

func prefixEnd(prefix netip.Prefix) netip.Addr {
	b := prefix.Masked().Addr().As16()
	first := prefix.Bits()
	if prefix.Addr().Is4() {
		first += 96
	}
	for bit := first; bit < 128; bit++ {
		b[bit/8] |= 1 << uint(7-bit%8)
	}
	return netip.AddrFrom16(b).Unmap()
}

func ipRegistryRange(start, end string, target Target, firstAddress bool) (RegistryRange, error) {
	bad := errors.New("invalid registration address range")
	a, err := netip.ParseAddr(start)
	if err != nil || a.Zone() != "" || a.Is4In6() {
		return RegistryRange{}, bad
	}
	z, err := netip.ParseAddr(end)
	if err != nil || z.Zone() != "" || z.Is4In6() || a.Is4() != z.Is4() || a.Compare(z) > 0 {
		return RegistryRange{}, bad
	}
	var first, last netip.Addr
	if target.Kind == "prefix" {
		p, err := netip.ParsePrefix(target.Value)
		if err != nil {
			return RegistryRange{}, bad
		}
		first, last = p.Addr(), prefixEnd(p)
	} else if target.Kind == "ip" {
		first, err = netip.ParseAddr(target.Value)
		if err != nil {
			return RegistryRange{}, bad
		}
		last = first
	} else {
		return RegistryRange{}, bad
	}
	if a.Is4() != first.Is4() || a.Compare(last) > 0 || z.Compare(first) < 0 || firstAddress && (a.Compare(first) > 0 || z.Compare(first) < 0) {
		return RegistryRange{}, bad
	}
	relation := "overlap"
	if a == first && z == last {
		relation = "exact"
	} else if a.Compare(first) <= 0 && z.Compare(last) >= 0 {
		relation = "covering"
	} else if a.Compare(first) >= 0 && z.Compare(last) <= 0 {
		relation = "contained"
	}
	resource := a.String() + " - " + z.String()
	if relation == "exact" {
		resource = target.Value
	}
	return RegistryRange{Kind: "ip", Resource: resource, Relation: relation, StartAddress: a.String(), EndAddress: z.String()}, nil
}

func asnRegistryRange(start, end *uint32, target Target) (RegistryRange, error) {
	if target.Kind != "asn" || start == nil || end == nil || *start > *end || target.ASN < *start || target.ASN > *end {
		return RegistryRange{}, errors.New("invalid registration ASN range")
	}
	relation, resource := "covering", asnTarget(*start)+" - "+asnTarget(*end)
	if *start == target.ASN && *end == target.ASN {
		relation, resource = "exact", target.Value
	}
	return RegistryRange{Kind: "asn", Resource: resource, Relation: relation, StartASN: start, EndASN: end}, nil
}

func normalizeRDAP(raw json.RawMessage, source string, target Target) (*Registration, error) {
	var data rdapData
	if json.Unmarshal(raw, &data) != nil || data.Handle == "" {
		return nil, errors.New("invalid RDAP response")
	}
	r := newRegistration("rdap")
	r.RIR = rirForURL(source)
	if r.RIR == "" {
		return nil, errors.New("untrusted RDAP source")
	}
	r.Authorities = append(r.Authorities, r.RIR)
	var scope RegistryRange
	var err error
	if target.Kind == "asn" {
		if data.ObjectClass != "" && data.ObjectClass != "autnum" {
			return nil, errors.New("unexpected RDAP object class")
		}
		scope, err = asnRegistryRange(data.StartAutnum, data.EndAutnum, target)
	} else {
		if data.ObjectClass != "" && data.ObjectClass != "ip network" {
			return nil, errors.New("unexpected RDAP object class")
		}
		scope, err = ipRegistryRange(data.StartAddress, data.EndAddress, target, true)
	}
	if err != nil {
		return nil, err
	}
	if scope.Relation == "contained" || scope.Relation == "overlap" {
		r.issue("registration_range_partially_covers_query")
	}
	record := RegistryRecord{Handle: r.text(data.Handle), Name: r.text(data.Name), Type: r.text(data.Type), Country: r.text(data.Country), SourceURL: source, Range: scope, Statuses: []string{}, Entities: []RegistryEntity{}, Events: []RegistryEvent{}}
	for _, status := range data.Status {
		if len(record.Statuses) == 32 {
			r.issue("status_limit")
			break
		}
		if value := r.text(status); value != "" {
			record.Statuses = append(record.Statuses, value)
		}
	}
	if record.Country != "" {
		country := strings.ToUpper(record.Country)
		if len(country) == 2 && country[0] >= 'A' && country[0] <= 'Z' && country[1] >= 'A' && country[1] <= 'Z' {
			record.Country = country
		} else {
			r.issue("invalid_country")
			record.Country = ""
		}
	}
	remaining := 128
	r.rdapEntities(data.Entities, &record, 0, &remaining)
	var events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	}
	if len(data.Events) > 0 && json.Unmarshal(data.Events, &events) != nil {
		r.issue("invalid_events")
	}
	for i, event := range events {
		if i == 32 {
			r.issue("event_limit")
			break
		}
		r.addEvent(&record, event.Action, event.Date)
	}
	r.Records = append(r.Records, record)
	return r, nil
}

func (r *Registration) addEvent(record *RegistryRecord, action, date string) {
	action = r.text(action)
	if action == "" {
		r.issue("invalid_event")
		return
	}
	parsed, err := time.Parse(time.RFC3339, date)
	if err != nil {
		parsed, err = time.Parse("2006-01-02", date)
	}
	if err != nil || parsed.After(time.Now().Add(5*time.Minute)) {
		r.issue("invalid_event")
		return
	}
	record.Events = append(record.Events, RegistryEvent{Action: action, Date: date})
}

func (r *Registration) addContact(email, handle, source, sourceURL, resource string) {
	email = strings.TrimSpace(email)
	a, err := mail.ParseAddress(email)
	if err != nil || a.Name != "" || a.Address != email || len(email) > 254 {
		r.issue("invalid_abuse_contact")
		return
	}
	for _, c := range r.AbuseContacts {
		if c.Email == email && c.Source == source && c.Resource == resource {
			return
		}
	}
	if len(r.AbuseContacts) == 32 {
		r.issue("abuse_contact_limit")
		return
	}
	r.AbuseContacts = append(r.AbuseContacts, AbuseContact{Email: email, EntityHandle: r.text(handle), Source: source, SourceURL: sourceURL, Resource: resource, Verification: "not_verified"})
	r.AbuseStatus = "published_unverified"
}

func (r *Registration) rdapEntities(raw json.RawMessage, record *RegistryRecord, depth int, remaining *int) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	if depth >= 8 {
		r.issue("entity_depth_limit")
		return
	}
	var nodes []json.RawMessage
	if json.Unmarshal(raw, &nodes) != nil {
		r.issue("invalid_entities")
		return
	}
	for _, node := range nodes {
		if *remaining == 0 {
			r.issue("entity_count_limit")
			return
		}
		*remaining--
		var entity struct {
			Handle   string          `json:"handle"`
			Roles    []string        `json:"roles"`
			Status   []string        `json:"status"`
			VCard    json.RawMessage `json:"vcardArray"`
			Entities json.RawMessage `json:"entities"`
		}
		if json.Unmarshal(node, &entity) != nil {
			r.issue("invalid_entity")
			continue
		}
		registrant, abuse := false, false
		for _, role := range entity.Roles {
			switch strings.ToLower(role) {
			case "registrant":
				registrant = depth == 0
			case "abuse":
				abuse = true
			}
		}
		if registrant || abuse {
			name, kind, organization, emails := r.card(entity.VCard)
			if registrant {
				if len(record.Entities) < 32 {
					statuses := []string{}
					for i, s := range entity.Status {
						if i == 32 {
							r.issue("entity_status_limit")
							break
						}
						statuses = append(statuses, r.text(s))
					}
					record.Entities = append(record.Entities, RegistryEntity{Handle: r.text(entity.Handle), Name: name, Kind: kind, Organization: organization, Role: "registrant", Statuses: statuses})
				} else {
					r.issue("registrant_limit")
				}
			}
			if abuse {
				for _, email := range emails {
					r.addContact(email, entity.Handle, "rdap", record.SourceURL, record.Range.Resource)
				}
			}
		}
		r.rdapEntities(entity.Entities, record, depth+1, remaining)
	}
}

func (r *Registration) card(raw json.RawMessage) (name, kind, organization string, emails []string) {
	kind = "unknown"
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	var card []json.RawMessage
	var label string
	var fields []json.RawMessage
	if json.Unmarshal(raw, &card) != nil || len(card) != 2 || json.Unmarshal(card[0], &label) != nil || label != "vcard" || json.Unmarshal(card[1], &fields) != nil {
		r.issue("invalid_vcard")
		return
	}
	for i, field := range fields {
		if i == 128 {
			r.issue("vcard_property_limit")
			break
		}
		var property []json.RawMessage
		var key, value, valueType string
		if json.Unmarshal(field, &property) != nil || len(property) != 4 || json.Unmarshal(property[0], &key) != nil || json.Unmarshal(property[2], &valueType) != nil {
			r.issue("invalid_vcard_property")
			continue
		}
		if key != "fn" && key != "kind" && key != "org" && key != "email" {
			continue
		}
		if json.Unmarshal(property[3], &value) != nil {
			if key == "org" {
				var parts []string
				if json.Unmarshal(property[3], &parts) == nil && len(parts) > 0 {
					value = parts[0]
				} else {
					r.issue("invalid_organization")
				}
			} else {
				r.issue("invalid_vcard_value")
			}
		}
		value = r.text(value)
		if valueType != "text" && !(key == "email" && valueType == "uri") {
			r.issue("invalid_vcard_type")
			continue
		}
		switch key {
		case "fn":
			name = value
		case "kind":
			if value != "" {
				kind = value
			}
		case "org":
			organization = value
		case "email":
			if valueType == "uri" {
				u, err := url.Parse(value)
				if err != nil || u.Scheme != "mailto" || u.RawQuery != "" || u.Fragment != "" || u.Opaque == "" {
					r.issue("invalid_abuse_contact_uri")
					continue
				}
				value = u.Opaque
			}
			if value != "" {
				emails = append(emails, value)
			}
		}
	}
	if organization == "" && kind == "org" {
		organization = name
	}
	return
}

func normalizeWhois(raw json.RawMessage, source string, target Target) *Registration {
	r := newRegistration("whois")
	var data struct {
		Authorities []string `json:"authorities"`
		Records     [][]struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"records"`
	}
	if json.Unmarshal(raw, &data) != nil {
		r.issue("invalid_whois_records")
		return r
	}
	for _, authority := range data.Authorities {
		if rir := canonicalRIR(authority); rir != "" && !slices.Contains(r.Authorities, rir) {
			r.Authorities = append(r.Authorities, rir)
		}
	}
	if len(r.Authorities) == 1 {
		r.RIR = r.Authorities[0]
	}
	for i, fields := range data.Records {
		if i == 32 {
			r.issue("record_limit")
			break
		}
		values := map[string]string{}
		for j, field := range fields {
			if j == 128 {
				r.issue("record_field_limit")
				break
			}
			key := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(field.Key), "-", ""))
			if values[key] == "" {
				values[key] = r.text(field.Value)
			}
		}
		var scope RegistryRange
		var err error
		if target.Kind == "asn" {
			value := values["autnum"]
			if value == "" {
				value = values["asnumber"]
			}
			if value == "" {
				continue
			}
			start, end, rangeOK := strings.Cut(value, "-")
			if !rangeOK {
				end = start
			}
			a, e1 := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(start)), "AS"), 10, 32)
			z, e2 := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(end)), "AS"), 10, 32)
			if e1 != nil || e2 != nil {
				r.issue("invalid_whois_range")
				continue
			}
			first, last := uint32(a), uint32(z)
			scope, err = asnRegistryRange(&first, &last, target)
		} else {
			value := values["inetnum"]
			if value == "" {
				value = values["inet6num"]
			}
			if value == "" {
				value = values["netrange"]
			}
			if value == "" {
				continue
			}
			if p, e := netip.ParsePrefix(value); e == nil {
				scope, err = ipRegistryRange(p.Masked().Addr().String(), prefixEnd(p).String(), target, false)
			} else {
				first, last, ok := strings.Cut(value, "-")
				if !ok {
					r.issue("invalid_whois_range")
					continue
				}
				scope, err = ipRegistryRange(strings.TrimSpace(first), strings.TrimSpace(last), target, false)
			}
		}
		if err != nil {
			r.issue("unrelated_or_invalid_whois_range")
			continue
		}
		record := RegistryRecord{Handle: values["nethandle"], Name: values["netname"], Type: values["status"], Country: values["country"], SourceURL: source, Range: scope, Statuses: []string{}, Entities: []RegistryEntity{}, Events: []RegistryEvent{}}
		if record.Type == "" {
			record.Type = values["nettype"]
		}
		if record.Name == "" {
			record.Name = values["asname"]
		}
		if value := values["status"]; value != "" {
			record.Statuses = append(record.Statuses, value)
		}
		if values["org"] != "" || values["orgname"] != "" {
			record.Entities = append(record.Entities, RegistryEntity{Handle: values["org"], Name: values["orgname"], Organization: values["orgname"], Kind: "unknown", Role: "referenced", Statuses: []string{}})
		}
		for _, event := range []struct{ key, action string }{{"created", "registration"}, {"lastmodified", "last changed"}} {
			if date := values[event.key]; date != "" {
				r.addEvent(&record, event.action, date)
			}
		}
		for j, field := range fields {
			if j == 128 {
				break
			}
			if strings.EqualFold(strings.ReplaceAll(field.Key, "-", ""), "abusemailbox") {
				r.addContact(field.Value, "", "whois", source, scope.Resource)
			}
		}
		if scope.Relation == "contained" || scope.Relation == "overlap" {
			r.issue("registration_range_partially_covers_query")
		}
		r.Records = append(r.Records, record)
	}
	if len(r.Records) == 0 && r.Completeness != "partial" {
		r.Completeness = "unknown"
	}
	return r
}

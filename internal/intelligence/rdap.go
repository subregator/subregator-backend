package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type sourceRedirect struct{ location string }

func (e *sourceRedirect) Error() string { return "upstream redirect refused" }

func asnTarget(asn uint32) string { return "AS" + strconv.FormatUint(uint64(asn), 10) }
func (s *Service) rdap(ctx context.Context, target Target) (Metric, error) {
	family := "asn"
	value := target.Value
	path := "autnum/" + strings.TrimPrefix(value, "AS")
	if target.Kind != "asn" {
		addr, e := netip.ParseAddr(value)
		if e != nil {
			p, e := netip.ParsePrefix(value)
			if e != nil {
				return Metric{}, e
			}
			addr = p.Addr()
		}
		family = "ipv6"
		if addr.Is4() {
			family = "ipv4"
		}
		value = addr.String()
		path = "ip/" + value
	}
	bootstrapURL := "https://data.iana.org/rdap/" + family + ".json"
	key := "rdap_bootstrap_" + family
	var raw json.RawMessage
	if s.cache != nil {
		if b, expires, found, e := s.cache.CacheGet(ctx, key); e == nil && found && time.Now().Before(expires) {
			raw = b
		}
	}
	if len(raw) == 0 {
		b, e := s.request(ctx, bootstrapURL, "")
		if e != nil {
			return Metric{}, e
		}
		raw = b
		if s.cache != nil {
			s.cache.CachePut(ctx, key, raw, time.Now().Add(24*time.Hour))
		}
	}
	var bootstrap struct {
		Services [][][]string `json:"services"`
	}
	if e := json.Unmarshal(raw, &bootstrap); e != nil {
		return Metric{}, e
	}
	base := ""
	best := -1
	for _, service := range bootstrap.Services {
		if len(service) != 2 {
			continue
		}
		for _, network := range service[0] {
			match := false
			bits := 0
			if family == "asn" {
				a, z, ok := strings.Cut(network, "-")
				if !ok {
					a = network
					z = network
				}
				start, e1 := strconv.ParseUint(a, 10, 32)
				end, e2 := strconv.ParseUint(z, 10, 32)
				match = e1 == nil && e2 == nil && uint64(target.ASN) >= start && uint64(target.ASN) <= end
			} else {
				p, e := netip.ParsePrefix(network)
				ip, _ := netip.ParseAddr(value)
				if e == nil {
					match = p.Contains(ip)
					bits = p.Bits()
				}
			}
			if match && bits > best {
				for _, candidate := range service[1] {
					if validRDAPBase(candidate) {
						base = candidate
						best = bits
						break
					}
				}
			}
		}
	}
	if base == "" {
		return Metric{}, errors.New("no supported authoritative RDAP service")
	}
	u := strings.TrimRight(base, "/") + "/" + path
	var b json.RawMessage
	var e error
	for hop := 0; hop < 4; hop++ {
		b, e = s.request(ctx, u, "")
		var redirect *sourceRedirect
		if !errors.As(e, &redirect) || !validRDAPBase(redirect.location) {
			break
		}
		u = redirect.location
	}
	if e != nil {
		return Metric{}, e
	}
	var data rdapData
	if e = json.Unmarshal(b, &data); e != nil || data.Handle == "" {
		return Metric{}, errors.New("invalid RDAP response")
	}
	normalized, _ := json.Marshal(data)
	registration, err := normalizeRDAP(normalized, u, target)
	if err != nil {
		return Metric{}, err
	}
	if len(registration.AbuseContacts) == 0 {
		s.abuseContactFallback(ctx, target, registration)
	}
	return Metric{Data: normalized, Registration: registration, SourceUpdatedAt: registrationUpdatedAt(registration), ObservedAt: observedNow(), SourceURL: u}, nil
}
func validRDAPBase(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "rdap.arin.net", "rdap.db.ripe.net", "rdap.apnic.net", "rdap.lacnic.net", "rdap.afrinic.net":
		return true
	}
	return false
}

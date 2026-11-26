package intelligence

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type Target struct {
	Value string `json:"value"`
	Kind  string `json:"kind"`
	ASN   uint32 `json:"asn,omitempty"`
}

var reserved = []netip.Prefix{}

func init() {
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8"} {
		reserved = append(reserved, netip.MustParsePrefix(s))
	}
}
func ParseTarget(raw string) (Target, error) {
	bad := errors.New("resource must be a public IP, canonical subnet or public ASN")
	if len(raw) > 100 || raw == "" || strings.TrimSpace(raw) != raw {
		return Target{}, bad
	}
	if ip, e := netip.ParseAddr(raw); e == nil {
		ip = ip.Unmap()
		if ip.Zone() != "" {
			return Target{}, bad
		}
		bits := 128
		if ip.Is4() {
			bits = 32
		}
		p := netip.PrefixFrom(ip, bits)
		if !publicPrefix(p) {
			return Target{}, bad
		}
		return Target{Value: ip.String(), Kind: "ip"}, nil
	}
	if p, e := netip.ParsePrefix(raw); e == nil {
		if p.Addr().Is4In6() {
			return Target{}, bad
		}
		p = p.Masked()
		if !publicPrefix(p) {
			return Target{}, bad
		}
		return Target{Value: p.String(), Kind: "prefix"}, nil
	}
	value := strings.TrimPrefix(strings.ToUpper(raw), "AS")
	n, e := strconv.ParseUint(value, 10, 32)
	if e != nil || n == 0 || n == 23456 || n >= 64496 && n <= 65551 || n >= 4200000000 {
		return Target{}, bad
	}
	return Target{Value: "AS" + strconv.FormatUint(n, 10), Kind: "asn", ASN: uint32(n)}, nil
}
func publicPrefix(p netip.Prefix) bool {
	if !p.Addr().IsGlobalUnicast() || p.Addr().IsPrivate() {
		return false
	}
	for _, r := range reserved {
		if p.Overlaps(r) {
			return false
		}
	}
	return true
}

type Query struct {
	overview  *Metric
	Address   string   `json:"address,omitempty"`
	TestURL   string   `json:"test_url,omitempty"`
	Resource  string   `json:"resource"`
	Checks    []string `json:"checks,omitempty"`
	StartTime string   `json:"start_time,omitempty"`
	EndTime   string   `json:"end_time,omitempty"`
	Version   string   `json:"version,omitempty"`
	ASN       uint32   `json:"asn,omitempty"`
}

func (q *Query) validate() (Target, error) {
	target, e := ParseTarget(q.Resource)
	if e != nil {
		return target, e
	}
	q.Resource = target.Value
	if len(q.Checks) == 0 {
		if target.Kind == "asn" {
			q.Checks = []string{"asn_overview", "asn_neighbours", "registration", "rdap"}
		} else {
			q.Checks = []string{"prefix_overview", "routing_status", "rpki", "registration", "rdap"}
		}
	}
	if len(q.Checks) == 1 && q.Checks[0] == "all" {
		q.Checks = nil
		for _, d := range Capabilities() {
			q.Checks = append(q.Checks, d.Name)
		}
	}
	if q.Address != "" {
		address, e := ParseTarget(q.Address)
		if e != nil || address.Kind != "ip" || (target.Kind == "ip" && address.Value != target.Value) || target.Kind == "asn" {
			return target, errors.New("address must be an IP inside the requested resource")
		}
		if target.Kind == "prefix" {
			p, _ := netip.ParsePrefix(target.Value)
			ip, _ := netip.ParseAddr(address.Value)
			if !p.Contains(ip) {
				return target, errors.New("address is outside requested prefix")
			}
		}
		q.Address = address.Value
	}
	if q.TestURL != "" && !validTestURL(q.TestURL, target) {
		return target, errors.New("test_url must be HTTP(S), a matching public IP literal, port 80/443, without credentials, query or fragment")
	}
	if len(q.Checks) > len(definitions) {
		return target, errors.New("too many checks")
	}
	seen := map[string]bool{}
	for _, check := range q.Checks {
		if _, ok := definitions[check]; !ok || seen[check] {
			return target, errors.New("unknown or duplicate network check")
		}
		seen[check] = true
	}
	if q.StartTime != "" || q.EndTime != "" {
		if q.StartTime == "" || q.EndTime == "" {
			return target, errors.New("start_time and end_time must be provided together")
		}
		a, e := time.Parse(time.RFC3339, q.StartTime)
		if e != nil {
			return target, errors.New("invalid start_time")
		}
		z, e := time.Parse(time.RFC3339, q.EndTime)
		if e != nil || a.Before(time.Unix(0, 0)) || !z.After(a) || z.After(time.Now().Add(5*time.Minute)) || z.Sub(a) > 366*24*time.Hour {
			return target, errors.New("historical time range must be valid and at most 366 days")
		}
		q.StartTime = a.UTC().Format(time.RFC3339)
		q.EndTime = z.UTC().Format(time.RFC3339)
	}
	if q.Version != "" {
		if n, e := strconv.Atoi(q.Version); e != nil || n < 1 || n > 100000 {
			if at, e := time.Parse(time.RFC3339, q.Version); e != nil || at.After(time.Now().Add(5*time.Minute)) {
				return target, errors.New("version must be a positive version number or RFC3339 timestamp")
			}
		}
	}
	if q.ASN != 0 {
		if _, e := ParseTarget("AS" + strconv.FormatUint(uint64(q.ASN), 10)); e != nil {
			return target, e
		}
	}
	return target, nil
}

package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Policy struct {
	Publication          string   `json:"publication"`
	PrefixVisibility     string   `json:"prefix_visibility"`
	MinRefreshSeconds    int      `json:"min_refresh_seconds"`
	RefreshAfterUTC      string   `json:"refresh_after_utc,omitempty"`
	MaxCurrentAgeSeconds int      `json:"max_current_age_seconds,omitempty"`
	Conditions           []string `json:"conditions"`
}

// MaxCurrentAge defaults to two refresh intervals for existing providers.
func (p Policy) MaxCurrentAge() time.Duration {
	if p.MaxCurrentAgeSeconds > 0 {
		return time.Duration(p.MaxCurrentAgeSeconds) * time.Second
	}
	return time.Duration(p.MinRefreshSeconds) * 2 * time.Second
}

type Provider struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description"`
	Policy      Policy `json:"policy"`
}
type Resource struct {
	Family             int      `json:"family"`
	Prefix             *string  `json:"prefix"`
	PrefixLength       int      `json:"prefix_length"`
	AddressCount       string   `json:"address_count"`
	RIR                string   `json:"rir,omitempty"`
	RegistrationStatus string   `json:"registration_status,omitempty"`
	TransferRIRs       []string `json:"transfer_rirs,omitempty"`
}
type Geography struct {
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	Basis   string `json:"basis"`
}
type Routing struct {
	BGP             string `json:"bgp,omitempty"`
	RPKI            string `json:"rpki,omitempty"`
	RDNS            string `json:"rdns,omitempty"`
	LOA             string `json:"loa,omitempty"`
	OwnASN          *bool  `json:"own_asn"`
	TransitRequired *bool  `json:"transit_required"`
}
type Money struct {
	Currency    string `json:"currency"`
	AmountMinor int64  `json:"amount_minor"`
	MinorUnit   int    `json:"minor_unit"`
}
type Fee struct {
	Kind       string `json:"kind"`
	Amount     *Money `json:"amount"`
	Frequency  string `json:"frequency"`
	Condition  string `json:"condition,omitempty"`
	Refundable *bool  `json:"refundable"`
}
type Quote struct {
	OrderURL      string `json:"order_url,omitempty"`
	ID            string `json:"id"`
	Price         *Money `json:"price"`
	BillingMonths int    `json:"billing_months"`
	MinimumMonths *int   `json:"minimum_months"`
	Fees          []Fee  `json:"fees"`
	Taxes         string `json:"taxes"`
}
type Terms struct {
	Summary        string   `json:"summary,omitempty"`
	AllowedUses    []string `json:"allowed_uses,omitempty"`
	ProhibitedUses []string `json:"prohibited_uses,omitempty"`
	NoticeDays     *int     `json:"notice_days"`
	Verification   string   `json:"verification,omitempty"`
}
type Offer struct {
	ID              string     `json:"id"`
	ExternalID      string     `json:"external_id"`
	ProviderID      string     `json:"provider_id"`
	Model           string     `json:"model"`
	Availability    string     `json:"availability"`
	AvailableAt     *time.Time `json:"available_at"`
	Resource        Resource   `json:"resource"`
	Geography       Geography  `json:"geography"`
	Routing         Routing    `json:"routing"`
	Quotes          []Quote    `json:"quotes"`
	Terms           Terms      `json:"terms"`
	URL             string     `json:"url"`
	ObservedAt      time.Time  `json:"observed_at"`
	SourceUpdatedAt *time.Time `json:"source_updated_at"`
}

var hiddenCIDR = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
var token = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,79}$`)
var countryCode = regexp.MustCompile(`^[A-Z]{2}$`)
var currencyCode = regexp.MustCompile(`^[A-Z]{3}$`)

func ValidToken(s string) bool { return token.MatchString(s) }
func WebURL(s string) bool {
	u, e := url.Parse(s)
	return e == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil && len(s) <= 2048
}
func contains(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func StableID(provider, external string) string {
	h := sha256.Sum256([]byte(provider + "\x00" + external))
	return provider + "_" + hex.EncodeToString(h[:12])
}
func Normalize(o Offer, p Provider, now time.Time) (Offer, error) {
	bad := func(s string) (Offer, error) { return Offer{}, fmt.Errorf("invalid offer: %s", s) }
	if !ValidToken(p.ID) || o.ProviderID != p.ID || o.ExternalID == "" || len(o.ExternalID) > 256 {
		return bad("identity")
	}
	if !contains(p.Policy.Publication, "approved", "public_source") {
		return bad("publication not enabled")
	}
	if !contains(p.Policy.PrefixVisibility, "full", "hidden") {
		return bad("prefix policy")
	}
	if !contains(o.Model, "lease", "purchase") || !contains(o.Availability, "available", "waitlist", "upcoming", "unavailable", "unknown") {
		return bad("model or availability")
	}
	if o.AvailableAt != nil && o.AvailableAt.IsZero() {
		return bad("available_at")
	}
	if !WebURL(o.URL) {
		return bad("url")
	}
	if len(o.Terms.Summary) > 4000 || len(o.Geography.City) > 200 {
		return bad("text length")
	}
	r := &o.Resource
	if r.Family != 4 && r.Family != 6 {
		return bad("IP family")
	}
	max := 32
	if r.Family == 6 {
		max = 128
	}
	if r.PrefixLength < 0 || r.PrefixLength > max {
		return bad("prefix length")
	}
	if r.Prefix != nil {
		prefix, e := netip.ParsePrefix(*r.Prefix)
		if e != nil || prefix != prefix.Masked() || prefix.Bits() != r.PrefixLength || prefix.Addr().Is4() != (r.Family == 4) {
			return bad("prefix")
		}
		v := prefix.String()
		r.Prefix = &v
	}
	// Compute the exact count as a decimal string, including IPv6 /0.
	r.AddressCount = addressCount(max - r.PrefixLength)
	if o.Geography.Country != "" && !countryCode.MatchString(o.Geography.Country) {
		return bad("country")
	}
	if !contains(o.Geography.Basis, "provider_geolocation", "seller_country", "registry", "unknown") {
		return bad("geography basis")
	}
	if r.RIR != "" && !contains(r.RIR, "RIPE NCC", "ARIN", "APNIC", "LACNIC", "AFRINIC") {
		return bad("registry")
	}
	for _, v := range r.TransferRIRs {
		if !contains(v, "RIPE NCC", "ARIN", "APNIC", "LACNIC", "AFRINIC") {
			return bad("transfer registry")
		}
	}
	if len(o.Quotes) > 100 {
		return bad("too many quotes")
	}
	quoteIDs := map[string]bool{}
	for _, q := range o.Quotes {
		if !ValidToken(q.ID) || quoteIDs[q.ID] || q.BillingMonths < 0 || q.BillingMonths > 1200 || (o.Model == "lease" && q.BillingMonths == 0) || (o.Model == "purchase" && q.BillingMonths != 0) {
			return bad("quote")
		}
		quoteIDs[q.ID] = true
		if q.OrderURL != "" && !WebURL(q.OrderURL) {
			return bad("quote URL")
		}
		if q.MinimumMonths != nil && (*q.MinimumMonths < 0 || *q.MinimumMonths > 1200) {
			return bad("minimum term")
		}
		if !validMoney(q.Price) || len(q.Fees) > 50 || !contains(q.Taxes, "included", "excluded", "unknown") {
			return bad("price or taxes")
		}
		for _, fee := range q.Fees {
			if !ValidToken(fee.Kind) || !validMoney(fee.Amount) || !contains(fee.Frequency, "once", "monthly", "per_cycle", "unknown") || len(fee.Condition) > 1000 {
				return bad("fee")
			}
		}
	}
	if o.Terms.NoticeDays != nil && (*o.Terms.NoticeDays < 0 || *o.Terms.NoticeDays > 3650) {
		return bad("notice")
	}
	if o.ObservedAt.IsZero() {
		o.ObservedAt = now
	}
	if o.ObservedAt.After(now.Add(5*time.Minute)) || o.SourceUpdatedAt != nil && o.SourceUpdatedAt.After(now.Add(5*time.Minute)) {
		return bad("future timestamp")
	}
	encoded, err := json.Marshal(o)
	if err != nil || len(encoded) > 32768 {
		return bad("offer exceeds size limit")
	}
	if p.Policy.PrefixVisibility == "hidden" {
		r.Prefix = nil
		// Opaque identifiers and structured fields prevent hidden CIDRs leaking via source metadata.
		o.ExternalID = StableID(p.ID, o.ExternalID)
		o.Terms = Terms{}
		o.Routing = Routing{}
		o.Geography.City = ""
		for i := range o.Quotes {
			o.Quotes[i].OrderURL = ""
			for j := range o.Quotes[i].Fees {
				o.Quotes[i].Fees[j].Condition = ""
			}
		}
		if r.RegistrationStatus != "" && !contains(r.RegistrationStatus, "LEGACY", "ASSIGNED PI", "ALLOCATED PA") {
			return bad("hidden registration status")
		}
		u, _ := url.Parse(o.URL)
		u.RawQuery = ""
		u.Fragment = ""
		o.URL = u.String()
		if strings.Contains(o.URL, "%") || strings.Contains(u.Path, ":") || hiddenCIDR.MatchString(o.URL) {
			return bad("prefix in hidden product URL")
		}
	}
	o.ID = StableID(p.ID, o.ExternalID)
	if o.Quotes == nil {
		o.Quotes = []Quote{}
	}
	for i := range o.Quotes {
		if o.Quotes[i].Fees == nil {
			o.Quotes[i].Fees = []Fee{}
		}
	}
	return o, nil
}
func validMoney(m *Money) bool {
	return m == nil || currencyCode.MatchString(m.Currency) && m.AmountMinor >= 0 && m.AmountMinor <= 1_000_000_000_000 && m.MinorUnit >= 0 && m.MinorUnit <= 6
}
func NormalizeRIR(s string) string {
	s = strings.ToUpper(s)
	if s == "RIPENCC" || s == "RIPE" {
		return "RIPE NCC"
	}
	return s
}

func (o Offer) Publishable(now time.Time) bool {
	if o.ProviderID != "peaktera" {
		return true
	}
	if o.ObservedAt.IsZero() || now.Sub(o.ObservedAt) > time.Hour || o.ObservedAt.After(now.Add(time.Minute)) {
		return false
	}
	for _, q := range o.Quotes {
		if q.OrderURL == "" {
			return false
		}
	}
	return len(o.Quotes) > 0
}

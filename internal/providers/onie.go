package providers

import (
	"context"
	"errors"
	"fmt"
	"github.com/subregator/subregator-backend/internal/catalog"
	"net/http"
	"strconv"
	"time"
)

type oniePage struct {
	Available *bool  `json:"available"`
	Page      int    `json:"page"`
	PerPage   int    `json:"per_page"`
	Total     int    `json:"total"`
	UpdatedAt int64  `json:"updated_at"`
	RPKIFee   *int64 `json:"rpki_fee_cents"`
	Items     []struct {
		Prefix  string `json:"prefix"`
		Country string `json:"country"`
		City    string `json:"city"`
		RIR     string `json:"rir"`
		Price   *int64 `json:"price_cents"`
		Setup   *int64 `json:"setup_cents"`
		RPKI    string `json:"rpki"`
	} `json:"items"`
}

func money(v *int64) *catalog.Money {
	if v == nil {
		return nil
	}
	return &catalog.Money{Currency: "USD", AmountMinor: *v, MinorUnit: 2}
}
func ParseOnie(b []byte, at time.Time) ([]catalog.Offer, int, int, int, error) {
	var p oniePage
	if e := decode(b, &p); e != nil {
		return nil, 0, 0, 0, e
	}
	if p.Available == nil || p.Total < 0 || p.Total > 100000 || p.Page < 1 || p.PerPage < 1 || p.PerPage > 100 || len(p.Items) > p.PerPage {
		return nil, 0, 0, 0, errors.New("invalid ONIE pagination")
	}
	out := []catalog.Offer{}
	if !*p.Available {
		if p.Total != 0 || len(p.Items) != 0 {
			return nil, 0, 0, 0, errors.New("inconsistent ONIE availability")
		}
		return out, p.Page, p.PerPage, 0, nil
	}
	for _, x := range p.Items {
		if x.Price == nil {
			return nil, 0, 0, 0, errors.New("missing ONIE price")
		}
		bits, e := prefixBits(x.Prefix)
		if e != nil {
			return nil, 0, 0, 0, e
		}
		var updated *time.Time
		if p.UpdatedAt > 0 {
			t := time.Unix(p.UpdatedAt, 0).UTC()
			updated = &t
		}
		out = append(out, catalog.Offer{ExternalID: x.Prefix, ProviderID: "onie", Model: "lease", Availability: "available", Resource: catalog.Resource{Family: 4, Prefix: &x.Prefix, PrefixLength: bits, RIR: catalog.NormalizeRIR(x.RIR)}, Geography: catalog.Geography{Country: x.Country, City: x.City, Basis: "provider_geolocation"}, Routing: catalog.Routing{RPKI: x.RPKI}, Quotes: []catalog.Quote{{ID: "monthly", Price: money(x.Price), BillingMonths: 1, Fees: []catalog.Fee{{Kind: "setup", Amount: money(x.Setup), Frequency: "once"}, {Kind: "deposit", Frequency: "once"}, {Kind: "rpki", Amount: money(p.RPKIFee), Frequency: "unknown", Condition: "Confirm ASN/RPKI fee applicability with provider"}}, Taxes: "unknown"}}, URL: "https://onie.net/ip-subnets", ObservedAt: at, SourceUpdatedAt: updated, Terms: catalog.Terms{Summary: "Confirm commitment, deposit, permitted use and routing requirements with provider."}})
	}
	return out, p.Page, p.PerPage, p.Total, nil
}
func LoadOnie(ctx context.Context, c *http.Client, base string, at time.Time) ([]catalog.Offer, error) {
	out := []catalog.Offer{}
	total := -1
	size := 0
	seen := map[string]bool{}
	for page := 1; page <= 1000; page++ {
		b, e := fetch(ctx, c, base+"?per_page=100&page="+strconv.Itoa(page))
		if e != nil {
			return nil, e
		}
		offers, n, per, count, e := ParseOnie(b, at)
		if e != nil {
			return nil, e
		}
		if n != page {
			return nil, errors.New("ONIE page mismatch")
		}
		if page == 1 {
			total = count
			size = per
		} else if total != count || per != size {
			return nil, errors.New("ONIE catalog changed during pagination")
		}
		expected := min(per, max(0, total-(page-1)*per))
		if len(offers) != expected {
			return nil, errors.New("incomplete ONIE page")
		}
		for _, o := range offers {
			if seen[o.ExternalID] {
				return nil, errors.New("duplicate ONIE resource")
			}
			seen[o.ExternalID] = true
			out = append(out, o)
		}
		if len(out) == total {
			return out, nil
		}
	}
	return nil, fmt.Errorf("ONIE pagination limit exceeded")
}

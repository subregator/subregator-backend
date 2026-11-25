package providers

import (
	"errors"
	"github.com/subregator/subregator-backend/internal/catalog"
	"html"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"time"
)

func prefixBits(s string) (int, error) {
	p, e := netip.ParsePrefix(s)
	if e != nil {
		return 0, errors.New("invalid provider prefix")
	}
	return p.Bits(), nil
}

var dataPage = regexp.MustCompile(`\bdata-page="([^"]+)"`)

func ParsePeaktera(b []byte, at time.Time) ([]catalog.Offer, error) {
	match := dataPage.FindSubmatch(b)
	if len(match) != 2 {
		return nil, errors.New("Peaktera page format changed")
	}
	var page struct {
		Props struct {
			Offers *[]struct {
				RangeID int    `json:"range_id"`
				CIDR    string `json:"cidr"`
				Version int    `json:"version"`
				RIR     string `json:"rir"`
				Country string `json:"geo_country"`
				Quotes  map[string]struct {
					Term struct {
						Months int `json:"months"`
					} `json:"term"`
					Price   *int64 `json:"price_per_cycle"`
					Setup   *int64 `json:"setup_fee"`
					Deposit *int64 `json:"deposit"`
				} `json:"quotes"`
			} `json:"offers"`
		} `json:"props"`
	}
	if e := decode([]byte(html.UnescapeString(string(match[1]))), &page); e != nil {
		return nil, e
	}
	if page.Props.Offers == nil {
		return nil, errors.New("Peaktera offers missing")
	}
	out := []catalog.Offer{}
	for _, x := range *page.Props.Offers {
		if x.Version != 4 && x.Version != 6 {
			return nil, errors.New("invalid Peaktera family")
		}
		bits, e := prefixBits(x.CIDR)
		if e != nil {
			return nil, e
		}
		if x.RangeID <= 0 || len(x.Quotes) == 0 {
			return nil, errors.New("invalid Peaktera resource")
		}
		quotes := []catalog.Quote{}
		keys := []string{}
		for k := range x.Quotes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			q := x.Quotes[k]
			if q.Price == nil || q.Term.Months < 1 {
				return nil, errors.New("invalid Peaktera quote")
			}
			quotes = append(quotes, catalog.Quote{ID: k, Price: money(q.Price), BillingMonths: q.Term.Months, Fees: []catalog.Fee{{Kind: "setup", Amount: money(q.Setup), Frequency: "once"}, {Kind: "deposit", Amount: money(q.Deposit), Frequency: "once"}}, Taxes: "unknown"})
		}
		out = append(out, catalog.Offer{ExternalID: strconv.Itoa(x.RangeID), ProviderID: "peaktera", Model: "lease", Availability: "available", Resource: catalog.Resource{Family: x.Version, Prefix: &x.CIDR, PrefixLength: bits, RIR: catalog.NormalizeRIR(x.RIR)}, Geography: catalog.Geography{Country: x.Country, Basis: "provider_geolocation"}, Quotes: quotes, URL: "https://www.peaktera.com/ip-ranges", ObservedAt: at, Terms: catalog.Terms{Summary: "Prepaid billing cycle; confirm routing, taxes and permitted use with provider."}})
	}
	return out, nil
}

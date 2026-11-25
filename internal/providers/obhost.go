package providers

import (
	"bytes"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

var obTable = regexp.MustCompile(`(?s)<table\b[^>]*\bid="ip-inv-table"[^>]*>.*?<tbody>(.*?)</tbody>\s*</table>`)
var obTotal = regexp.MustCompile(`<strong>([0-9]+)</strong>\s+subnets available`)
var obCurrency = regexp.MustCompile(`<span id="activeCurrencyLabel"[^>]*>\s*([A-Z]{3})\s*</span>`)
var obRows = regexp.MustCompile(`(?s)<tr data-size="/([0-9]+)">(.*?)</tr>`)
var obPrefix = regexp.MustCompile(`<span class="ip-inv-cidr">([0-9.]+)<span class="ip-inv-cidr-suffix">/([0-9]+)</span></span>`)
var obIPs = regexp.MustCompile(`<span class="ip-inv-ips">([0-9,]+)</span>`)
var obCountry = regexp.MustCompile(`<span class="ip-inv-country-flag">([A-Z]{2})</span>`)
var obStatus = regexp.MustCompile(`(?s)<span class="ip-inv-status ([a-z]+)">\s*<span class="dot"></span>\s*(Available|Reserved|Leased)\s*</span>`)
var obPrice = regexp.MustCompile(`<span class="ip-price-val"[^>]*>([0-9]+(?:\.[0-9]{1,2})?)</span>\s*<span class="ip-inv-price-period">/mo</span>`)

func ParseOBHost(b []byte, at time.Time) ([]catalog.Offer, error) {
	bad := errors.New("OBHost catalogue incomplete or page format changed")
	table, total, currency := obTable.FindSubmatch(b), obTotal.FindSubmatch(b), obCurrency.FindSubmatch(b)
	if len(table) != 2 || len(total) != 2 || len(currency) != 2 {
		return nil, bad
	}
	code := string(currency[1])
	switch code {
	case "USD", "EUR", "GBP", "PKR", "SAR", "AED", "INR", "AUD", "CAD":
	default:
		return nil, bad
	}
	expected, e := strconv.Atoi(string(total[1]))
	if e != nil {
		return nil, bad
	}
	rows := obRows.FindAllSubmatch(table[1], -1)
	if len(rows) != expected || bytes.Count(table[1], []byte("<tr")) != len(rows) {
		return nil, bad
	}
	out := make([]catalog.Offer, 0, len(rows))
	seen := map[string]bool{}
	for _, row := range rows {
		prefix, ips, country, status := obPrefix.FindSubmatch(row[2]), obIPs.FindSubmatch(row[2]), obCountry.FindSubmatch(row[2]), obStatus.FindSubmatch(row[2])
		if len(prefix) != 3 || len(ips) != 2 || len(country) != 2 || len(status) != 3 || !bytes.Equal(row[1], prefix[2]) || string(status[1]) != strings.ToLower(string(status[2])) {
			return nil, bad
		}
		raw := string(prefix[1]) + "/" + string(prefix[2])
		p, e := netip.ParsePrefix(raw)
		if e != nil || !p.Addr().Is4() || p != p.Masked() || seen[raw] {
			return nil, bad
		}
		count, e := strconv.ParseUint(strings.ReplaceAll(string(ips[1]), ",", ""), 10, 64)
		if e != nil || count != uint64(1)<<uint(32-p.Bits()) {
			return nil, bad
		}
		seen[raw] = true
		geography := catalog.Geography{Basis: "provider_geolocation", Country: string(country[1])}
		if geography.Country == "NA" {
			geography = catalog.Geography{Basis: "unknown"}
		}
		availability := "available"
		if string(status[1]) != "available" {
			availability = "unavailable"
		}
		quotes := []catalog.Quote{}
		if price := obPrice.FindSubmatch(row[2]); len(price) == 2 {
			whole, fraction, _ := strings.Cut(string(price[1]), ".")
			minor, e := strconv.ParseInt(whole+fraction+strings.Repeat("0", 2-len(fraction)), 10, 64)
			if e != nil {
				return nil, bad
			}
			quotes = append(quotes, catalog.Quote{ID: "monthly", Price: &catalog.Money{Currency: code, AmountMinor: minor, MinorUnit: 2}, BillingMonths: 1, Taxes: "unknown"})
		} else if !bytes.Contains(row[2], []byte(`class="ip-inv-price-contact"`)) {
			return nil, bad
		}
		out = append(out, catalog.Offer{ProviderID: "obhost", ExternalID: raw, Model: "lease", Availability: availability, Resource: catalog.Resource{Family: 4, Prefix: &raw, PrefixLength: p.Bits()}, Geography: geography, Quotes: quotes, URL: "https://www.obhost.net/ip-subnet-leasing", ObservedAt: at, Terms: catalog.Terms{Summary: "Provider-reported inventory and pricing; ownership and reputation claims are not independently verified. Confirm availability, taxes, fees and contract terms."}})
	}
	return out, nil
}

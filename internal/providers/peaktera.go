package providers

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/subregator/subregator-backend/internal/catalog"
)

func prefixBits(s string) (int, error) {
	p, e := netip.ParsePrefix(s)
	if e != nil {
		return 0, errors.New("invalid provider prefix")
	}
	return p.Bits(), nil
}

func ParsePeaktera(b []byte, at time.Time) ([]catalog.Offer, error) {
	r := csv.NewReader(bytes.NewReader(b))
	header, e := r.Read()
	if e != nil {
		return nil, e
	}
	columns := map[string]int{}
	for i, name := range header {
		if _, ok := columns[name]; ok {
			return nil, errors.New("duplicate Peaktera column")
		}
		columns[name] = i
	}
	for _, name := range strings.Fields("prefix prefix_length addresses rir country city term term_months price_per_cycle setup_fee deposit due_today currency order_url") {
		if _, ok := columns[name]; !ok {
			return nil, errors.New("Peaktera column missing: " + name)
		}
	}
	out := []catalog.Offer{}
	byPrefix := map[string]int{}
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		get := func(name string) string { return row[columns[name]] }
		prefix, err := netip.ParsePrefix(get("prefix"))
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return nil, errors.New("invalid Peaktera prefix")
		}
		months, err := strconv.Atoi(get("term_months"))
		if err != nil || months < 1 || months > 1200 || !catalog.ValidToken(get("term")) {
			return nil, errors.New("invalid Peaktera term")
		}
		if get("prefix_length") != strconv.Itoa(prefix.Bits()) || get("addresses") != strconv.FormatUint(uint64(1)<<(32-prefix.Bits()), 10) {
			return nil, errors.New("invalid Peaktera block size")
		}
		order, err := url.Parse(get("order_url"))
		if err != nil || order.Scheme != "https" || order.Host != "www.peaktera.com" || order.User != nil || order.Path != "/portal/checkout" || order.Query().Get("prefix") != prefix.String() || order.Query().Get("term") != get("term") {
			return nil, errors.New("invalid Peaktera order URL")
		}
		amounts := map[string]*catalog.Money{}
		for _, name := range strings.Fields("price_per_cycle setup_fee deposit due_today") {
			parts := strings.Split(get(name), ".")
			if len(parts) != 2 || len(parts[1]) != 2 {
				return nil, errors.New("invalid Peaktera money")
			}
			for _, c := range parts[0] + parts[1] {
				if c < '0' || c > '9' {
					return nil, errors.New("invalid Peaktera money")
				}
			}
			n, err := strconv.ParseInt(parts[0]+parts[1], 10, 64)
			if err != nil || n < 0 || n > 1_000_000_000_000 {
				return nil, errors.New("invalid Peaktera money")
			}
			amounts[name] = &catalog.Money{Currency: get("currency"), AmountMinor: n, MinorUnit: 2}
		}
		if amounts["due_today"].AmountMinor != amounts["price_per_cycle"].AmountMinor+amounts["setup_fee"].AmountMinor+amounts["deposit"].AmountMinor {
			return nil, errors.New("invalid Peaktera upfront total")
		}
		refundable, ownASN := true, true
		q := catalog.Quote{ID: get("term"), OrderURL: order.String(), Price: amounts["price_per_cycle"], BillingMonths: months, MinimumMonths: &months, Taxes: "unknown", Fees: []catalog.Fee{{Kind: "setup", Amount: amounts["setup_fee"], Frequency: "once"}, {Kind: "deposit", Amount: amounts["deposit"], Frequency: "once", Refundable: &refundable}}}
		i, exists := byPrefix[prefix.String()]
		if !exists {
			cidr := prefix.String()
			basis := "provider_geolocation"
			if j, ok := columns["geo_source"]; ok && row[j] == "rir" {
				basis = "registry"
			}
			o := catalog.Offer{ExternalID: cidr, ProviderID: "peaktera", Model: "lease", Availability: "available", Resource: catalog.Resource{Family: 4, Prefix: &cidr, PrefixLength: prefix.Bits(), RIR: catalog.NormalizeRIR(get("rir"))}, Geography: catalog.Geography{Country: get("country"), City: get("city"), Basis: basis}, Routing: catalog.Routing{RPKI: "included", LOA: "included", RDNS: "included", OwnASN: &ownASN}, URL: "https://www.peaktera.com/ip-ranges?size=" + strconv.Itoa(prefix.Bits()), ObservedAt: at, Quotes: []catalog.Quote{}, Terms: catalog.Terms{Summary: "Prepaid billing term is the minimum commitment. ROA, IRR, LOA, rDNS and geofeed included. Own ASN required; transit not included. Deposit refundable. Checkout confirms availability, taxes and final price."}}
			i = len(out)
			byPrefix[cidr] = i
			out = append(out, o)
		}
		out[i].Quotes = append(out[i].Quotes, q)
	}
	var p catalog.Provider
	for _, v := range catalog.Providers() {
		if v.ID == "peaktera" {
			p = v
		}
	}
	for _, o := range out {
		if _, err := catalog.Normalize(o, p, at); err != nil {
			return nil, err
		}
	}
	return out, nil
}

type peakteraFeed struct {
	etag string
	body []byte
}

func (f *peakteraFeed) load(ctx context.Context, client *http.Client, endpoint string, at time.Time) ([]catalog.Offer, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "Subregator/0.1 (+https://github.com/subregator/subregator-backend)")
	req.Header.Set("Cache-Control", "no-cache")
	if f.etag != "" {
		req.Header.Set("If-None-Match", f.etag)
	}
	res, e := client.Do(req)
	if e != nil {
		return nil, errors.New("Peaktera request failed")
	}
	defer res.Body.Close()
	if raw := res.Header.Get("Age"); raw != "" {
		age, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || age < 0 || age > 3600 {
			return nil, errors.New("Peaktera cached response too old")
		}
		at = at.Add(-time.Duration(age) * time.Second)
	}
	if res.StatusCode == http.StatusNotModified && f.body != nil {
		return ParsePeaktera(f.body, at)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Peaktera HTTP %d", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if e != nil || len(b) > maxBody {
		return nil, errors.New("invalid Peaktera response body")
	}
	offers, e := ParsePeaktera(b, at)
	if e == nil {
		f.etag = res.Header.Get("ETag")
		f.body = b
	}
	return offers, e
}

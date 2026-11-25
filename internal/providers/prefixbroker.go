package providers

import (
	"errors"
	"github.com/subregator/subregator-backend/internal/catalog"
	"html"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var brokerCards = regexp.MustCompile(`(?s)<a href="(/buy-ipv4/offers/[a-z0-9-]+/)" class="offers-card [^"]*">(.*?)</a>`)
var brokerTitle = regexp.MustCompile(`offers-card-title">/(\d+) block`)
var brokerPrice = regexp.MustCompile(`(?s)Purchase price</span>\s*<span class="offers-card-value">&euro; ([\d.,]+)</span>`)
var brokerCountry = regexp.MustCompile(`/gfx/flags/([a-z]{2})\.svg`)
var brokerRegistry = regexp.MustCompile(`text-light flex-fill">(RIPE|ARIN|APNIC|LACNIC|AFRINIC) ([A-Z ]+)</small>`)
var brokerTransfers = regexp.MustCompile(`(?s)Transferable to:</strong><br\s*/?>\s*([A-Z, ]+)`)
var brokerTotal = regexp.MustCompile(`Browse (\d+) IPv4 offers`)

func ParsePrefixBroker(b []byte, at time.Time) ([]catalog.Offer, error) {
	count := brokerTotal.FindSubmatch(b)
	if len(count) != 2 {
		return nil, errors.New("Prefix Broker count missing")
	}
	expected, _ := strconv.Atoi(string(count[1]))
	cards := brokerCards.FindAllSubmatch(b, -1)
	if len(cards) != expected {
		return nil, errors.New("Prefix Broker catalog incomplete")
	}
	out := []catalog.Offer{}
	for _, card := range cards {
		bits := brokerTitle.FindSubmatch(card[2])
		price := brokerPrice.FindSubmatch(card[2])
		country := brokerCountry.FindSubmatch(card[2])
		registry := brokerRegistry.FindSubmatch(card[2])
		if len(bits) != 2 || len(price) != 2 || len(country) != 2 || len(registry) != 3 {
			return nil, errors.New("Prefix Broker card format changed")
		}
		transfers := []string{}
		if m := brokerTransfers.FindSubmatch(card[2]); len(m) == 2 {
			for _, r := range strings.Split(strings.TrimSpace(string(m[1])), ",") {
				transfers = append(transfers, catalog.NormalizeRIR(strings.TrimSpace(r)))
			}
		}
		n, _ := strconv.Atoi(string(bits[1]))
		value := strings.ReplaceAll(string(price[1]), ".", "")
		parts := strings.Split(value, ",")
		if len(parts) != 2 || len(parts[1]) != 2 {
			return nil, errors.New("invalid euro price")
		}
		minor, e := strconv.ParseInt(parts[0]+parts[1], 10, 64)
		if e != nil {
			return nil, errors.New("invalid euro amount")
		}
		out = append(out, catalog.Offer{ExternalID: strings.TrimPrefix(string(card[1]), "/buy-ipv4/offers/"), ProviderID: "prefix-broker", Model: "purchase", Availability: "available", Resource: catalog.Resource{Family: 4, PrefixLength: n, RIR: catalog.NormalizeRIR(string(registry[1])), RegistrationStatus: html.UnescapeString(string(registry[2])), TransferRIRs: transfers}, Geography: catalog.Geography{Country: strings.ToUpper(string(country[1])), Basis: "seller_country"}, Quotes: []catalog.Quote{{ID: "purchase", Price: &catalog.Money{Currency: "EUR", AmountMinor: minor, MinorUnit: 2}, Fees: []catalog.Fee{{Kind: "setup", Frequency: "once"}}, Taxes: "unknown"}}, URL: "https://www.prefixbroker.com" + string(card[1]), ObservedAt: at})
	}
	return out, nil
}

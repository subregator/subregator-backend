package api

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/subregator/subregator-backend/internal/catalog"
	"github.com/subregator/subregator-backend/internal/history"
)

func validateMarketSchema(t *testing.T, name string, value any) {
	t.Helper()
	var doc struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openAPI, &doc); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"$defs": doc.Components.Schemas, "$ref": "#/$defs/" + name})
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.ReplaceAll(raw, []byte("#/components/schemas/"), []byte("#/$defs/"))
	var schema jsonschema.Schema
	if err = json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var instance any
	if err = json.Unmarshal(encoded, &instance); err != nil {
		t.Fatal(err)
	}
	if err = resolved.Validate(instance); err != nil {
		t.Fatal(err)
	}
}

func TestMarketOpenAPIResponseContract(t *testing.T) {
	view := store(t, 1).View()
	item := Search(view, query(t, ""), time.Now()).Items[0]
	costs := []QuoteCosts{quoteCosts(item.Quotes[0], item.Model)}
	t.Run("offer", func(t *testing.T) {
		validateMarketSchema(t, "MarketOffer", MarketOffer{item, "exact", *item.Resource.Prefix, costs})
	})
	t.Run("event", func(t *testing.T) {
		event := MarketEvent{history.Event{ID: 1, ListingID: item.ID, ProviderID: item.ProviderID, ResourceID: history.ResourceID(item.Offer), NextResourceID: history.ResourceID(item.Offer), Type: "changed", ObservedAt: time.Now().UTC(), Before: &item.Offer, After: &item.Offer, ChangedFields: []string{"quotes"}}, costs, costs}
		validateMarketSchema(t, "MarketEvent", event)
	})
	t.Run("derived_amount", func(t *testing.T) {
		q := catalog.Quote{ID: "monthly", Price: &catalog.Money{Currency: "USD", AmountMinor: 1_000_000_000_000, MinorUnit: 2}, BillingMonths: 1, Taxes: "included", Fees: []catalog.Fee{{Kind: "setup", Amount: &catalog.Money{Currency: "USD", AmountMinor: 1, MinorUnit: 2}, Frequency: "once"}}}
		costs := quoteCosts(q, "lease")
		if costs.FirstPeriodTotal == nil || costs.FirstPeriodTotal.AmountMinor != 1_000_000_000_001 {
			t.Fatal(costs)
		}
		validateMarketSchema(t, "QuoteCosts", costs)
	})
}

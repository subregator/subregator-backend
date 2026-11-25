package api

import (
	"math"
	"testing"

	"github.com/subregator/subregator-backend/internal/catalog"
)

func TestQuotedTotalsPreserveFeesPrecisionAndUnknowns(t *testing.T) {
	money := func(n int64, unit int) *catalog.Money {
		return &catalog.Money{Currency: "USD", AmountMinor: n, MinorUnit: unit}
	}
	q := catalog.Quote{ID: "annual", Price: money(12000, 2), BillingMonths: 12, Taxes: "included", Fees: []catalog.Fee{{Kind: "setup", Amount: money(1000, 2), Frequency: "once"}, {Kind: "deposit", Amount: money(300, 1), Frequency: "once"}, {Kind: "service", Amount: money(50, 2), Frequency: "monthly"}, {Kind: "cycle", Amount: money(200, 2), Frequency: "per_cycle"}}}
	result := quoteCosts(q, "lease")
	if result.FirstPeriodTotal == nil || result.FirstPeriodTotal.AmountMinor != 16800 || result.RenewalTotal == nil || result.RenewalTotal.AmountMinor != 12800 {
		t.Fatal(result)
	}
	for _, tax := range []string{"unknown", "excluded"} {
		x := q
		x.Taxes = tax
		if r := quoteCosts(x, "lease"); r.FirstPeriodTotal != nil || r.RenewalTotal != nil {
			t.Fatal("invented tax", r)
		}
	}
	once := q
	once.Fees = []catalog.Fee{{Kind: "setup", Frequency: "once"}}
	if r := quoteCosts(once, "lease"); r.FirstPeriodTotal != nil || r.RenewalTotal == nil {
		t.Fatal("unknown setup/renewal", r)
	}
	conditional := q
	conditional.Fees = []catalog.Fee{{Kind: "service", Amount: money(100, 2), Frequency: "monthly", Condition: "if used"}}
	if r := quoteCosts(conditional, "lease"); r.FirstPeriodTotal != nil || r.RenewalTotal != nil {
		t.Fatal("assumed condition", r)
	}
	mixed := q
	mixed.Fees = []catalog.Fee{{Kind: "setup", Amount: &catalog.Money{Currency: "EUR", AmountMinor: 100, MinorUnit: 2}, Frequency: "once"}}
	if r := quoteCosts(mixed, "lease"); r.FirstPeriodTotal != nil || r.RenewalTotal == nil {
		t.Fatal("currency conversion", r)
	}
	overflow := q
	overflow.Price = money(1_000_000_000_000, 0)
	overflow.Fees = make([]catalog.Fee, 50)
	for i := range overflow.Fees {
		overflow.Fees[i] = catalog.Fee{Kind: "service", Amount: money(1_000_000_000_000, 6), Frequency: "monthly"}
	}
	overflow.BillingMonths = 1200
	r := quoteCosts(overflow, "lease")
	if r.FirstPeriodTotal == nil || r.FirstPeriodTotal.AmountMinor <= 0 || r.FirstPeriodTotal.AmountMinor > math.MaxInt64 {
		t.Fatal("exact arithmetic", r)
	}
	overflow.Price = money(math.MaxInt64, 0)
	if r := quoteCosts(overflow, "lease"); r.FirstPeriodTotal != nil {
		t.Fatal("overflow wrapped", r)
	}
	purchase := q
	purchase.BillingMonths = 0
	purchase.Fees = nil
	if r := quoteCosts(purchase, "purchase"); r.FirstPeriodTotal == nil || r.RenewalTotal != nil {
		t.Fatal("purchase renewal", r)
	}
	unknown := q
	unknown.Price = nil
	if r := quoteCosts(unknown, "lease"); r.FirstPeriodTotal != nil {
		t.Fatal("invented price", r)
	}
}

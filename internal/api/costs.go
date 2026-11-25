package api

import (
	"math/big"

	"github.com/subregator/subregator-backend/internal/catalog"
)

type QuoteCosts struct {
	Quote               catalog.Quote  `json:"quote"`
	FirstPeriodTotal    *catalog.Money `json:"first_period_total"`
	RenewalTotal        *catalog.Money `json:"renewal_total"`
	FirstPeriodUnknowns []string       `json:"first_period_unknowns"`
	RenewalUnknowns     []string       `json:"renewal_unknowns"`
}

func quoteCosts(q catalog.Quote, model string) QuoteCosts {
	first, fu := quoteTotal(q, model, false)
	renewal, ru := quoteTotal(q, model, true)
	return QuoteCosts{q, first, renewal, fu, ru}
}

func quoteTotal(q catalog.Quote, model string, renewal bool) (*catalog.Money, []string) {
	unknown := []string{}
	if renewal && model == "purchase" {
		return nil, []string{"not_recurring"}
	}
	if q.Price == nil {
		return nil, []string{"price_unknown"}
	}
	if q.Taxes != "included" {
		unknown = append(unknown, "taxes_"+q.Taxes)
	}
	unit := q.Price.MinorUnit
	for _, fee := range q.Fees {
		if renewal && fee.Frequency == "once" {
			continue
		}
		if fee.Amount != nil && fee.Amount.Currency == q.Price.Currency {
			unit = max(unit, fee.Amount.MinorUnit)
		}
	}
	total := new(big.Int)
	add := func(m *catalog.Money, count int) {
		amount := big.NewInt(m.AmountMinor)
		scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(unit-m.MinorUnit)), nil)
		amount.Mul(amount, scale)
		amount.Mul(amount, big.NewInt(int64(count)))
		total.Add(total, amount)
	}
	add(q.Price, 1)
	for _, fee := range q.Fees {
		if renewal && fee.Frequency == "once" {
			continue
		}
		if fee.Condition != "" {
			unknown = append(unknown, "conditional_fee")
			continue
		}
		if fee.Amount == nil {
			unknown = append(unknown, "fee_amount_unknown")
			continue
		}
		if fee.Amount.Currency != q.Price.Currency {
			unknown = append(unknown, "fee_currency_mismatch")
			continue
		}
		count := 1
		switch fee.Frequency {
		case "once", "per_cycle":
		case "monthly":
			if model != "lease" {
				unknown = append(unknown, "purchase_monthly_fee")
				continue
			}
			count = q.BillingMonths
		default:
			unknown = append(unknown, "fee_frequency_unknown")
			continue
		}
		add(fee.Amount, count)
	}
	if !total.IsInt64() {
		unknown = append(unknown, "amount_overflow")
	}
	if len(unknown) > 0 {
		return nil, unknown
	}
	return &catalog.Money{Currency: q.Price.Currency, AmountMinor: total.Int64(), MinorUnit: unit}, unknown
}

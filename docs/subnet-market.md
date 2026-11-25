# Subnet market and price history

BE-11 and BE-17 are projections over existing offers, resource/provider identities, listing before/after events and provider polls. They add no source integration, background work, dependency or archive. They do not depend on the opt-in network-observation archive from BE-10. PostgreSQL receives one additive index on existing polls; schema version and stored history are unchanged.

## Read contract

REST `GET /api/v1/market` and MCP `subnet_market` accept the same filters. `resource` is a required IPv4/IPv6 CIDR, normalized to its canonical network. Only existing public data is read. All availability states are returned with explicit freshness; a historical provider association is separate from a current observed offer. A stale retained offer is not fresh availability. Existing `/offers`, `/history`, `/resources` and `/providers` reads remain available.

```sh
curl 'http://localhost:8080/api/v1/market?resource=1.1.1.0/24'
curl 'http://localhost:8080/api/v1/market?resource=1.1.1.0/24&provider=onie&model=lease&currency=USD&billing_months=1&limit=50'
curl 'http://localhost:8080/api/v1/market?resource=2001:4860::/48&relation=overlap'
```

MCP arguments: `{"filters":{"resource":"1.1.1.0/24","model":"lease","currency":"USD","billing_months":"1"}}`. These examples describe the request contract; they do not assert that a live provider currently offers these prefixes.

The response separates:

- `current`: paged observed offers, availability/freshness, actual `relation`, `price_scope` and per-quote costs. Preserve offer URLs, per-term order links and provider attribution from `/providers`; for Peaktera display “Data: Peaktera”.
- `historical_providers`: exact-prefix provider associations with first/last ingestion-observation bounds, not current presence, continuous availability or ownership.
- `history`: original listing before/after events plus matching `before_prices`/`after_prices` and the tracking start. Event and source observation/update times remain distinct. Removed/replaced listings and resources moving in/out remain traceable. An empty price projection can mean the event's side moved out of the requested prefix/model/currency/term; it does not erase the original lifecycle event.
- `polls`: provider inventory attempts for historically associated exact-prefix providers. `complete=false` exposes failure/incomplete-import gaps without raw diagnostics. A complete provider snapshot is not itself proof that this prefix was present; consult listing events. Polls preceding a first association do not establish earlier price coverage.

`limit` (1–200) applies independently to current offers, history and polls. Current pagination uses `offset` and `snapshot`; a changed snapshot returns 409. History uses `after_id=history.next_after_id`; polls use `after_poll_id=polls.next_after_id`. Null cursors indicate the end of each stream. The streams are independently read and can advance during collection; there is no cross-stream transactional snapshot. Reconstruct history from tracking start and every event page; do not interpolate through failed/missing polls or assume price continuity between observations. Repeated unchanged quotes do not create price events. A successful complete empty inventory can create `removed`; source failure retains the last observation. Removal does not establish a sale or transfer.

Filters `provider`, `listing_id`, `model`, `currency` and `billing_months` select comparable quotes. Raw lifecycle before/after evidence remains intact so quote currency, model or term changes are visible rather than silently discarded. Group price series by provider, listing, resource, model, quote ID, currency, minor unit and billing term; never combine currencies or purchase/lease models. Source times and missing amounts remain as recorded. No FX, cheapest-provider recommendation, ownership, fraud, tenant or completed-transfer conclusion is produced.

## Quoted costs

`quote_costs` and historical price projections preserve the complete original quote: source price, billing term, minimum commitment, setup/deposit/conditional fees, refundable flags, taxes and order URL. `first_period_total` is one quoted billing period plus all reported unconditional initial charges; refundable deposits are included without assuming a future refund. Monthly fees are multiplied by the billing term. `renewal_total` is a later lease billing period and excludes once-only fees. These are quoted charges, not a guarantee that unreported fees do not exist, and not the total minimum contractual commitment. A purchase has no renewal total.

Totals are emitted only when price, relevant fees/frequencies/conditions/currencies and included taxes permit exact calculation. Missing or excluded taxes without an amount, unknown fees, unresolved conditions, mixed currencies or overflow produce null with explicit unknown reasons. An unknown once-only setup fee blocks the first total but does not block a known renewal. Source minor-unit scales are aligned exactly using integer arithmetic, with no rounding or currency conversion. Values exceeding int64 remain null. Base quotes remain visible when a total is unknown.

## Prefix relationships

`relation` defaults to `exact`; `parent` selects containing offers, `child` selects contained offers and `overlap` selects their union including exact matches. The returned per-offer relation is always exact/parent/child relative to the request. Canonical CIDRs cannot partially overlap without containment, so no artificial fourth relation is returned. A /22 and its /24 child remain different listings and prices. Every price covers the actual offered `price_scope`; parent/child prices are never scaled to or ranked as the requested subnet's price. Both requested and offered address counts are decimal strings, including IPv6 /0.

History, provider associations and polls remain exact-prefix regardless of `relation`. Request each actual prefix separately for its history. Current hidden/pending provider policies are checked before filtering/counting; hidden prefixes cannot be recovered through relationships, aggregates or old events. Historical Peaktera data remains private under existing policy, while current public Peaktera offers preserve their one-hour expiry and exact term links. Source-publication permissions are unchanged.

## Verification and limits

Local synthetic fixtures with PostgreSQL cover multiple offers, exact/grouped quote projection, price changes, failure versus complete empty imports, removed/replaced/moved resources, reappearance, restart, pagination, IPv4/IPv6, hidden/pending policy changes, Peaktera current/history boundaries and REST/MCP parity. Cost tests cover deposits/setup/monthly/cycle fees, currency scales, unknowns, conditions, overflow and purchase semantics. Network-source quotas/authentication are unchanged because these reads make zero upstream calls. No live offers, external rights, production freshness or completed sales are inferred from fixtures. Frontend remains deferred.

## Synthetic response example

Selected fields below illustrate two providers observing the same exact subnet, an asking-price change and a failed inventory attempt. This is synthetic data, not a live offer. The full response also includes original before/after offers, complete quote terms and all pagination cursors defined in OpenAPI.

```json
{
  "resource": "192.0.2.0/24",
  "address_count": "256",
  "current": {
    "items": [
      {
        "provider_id": "example-a",
        "availability": "available",
        "freshness": "stale",
        "relation": "exact",
        "price_scope": "192.0.2.0/24",
        "quotes": [{"id": "monthly", "price": {"currency": "USD", "amount_minor": 1500, "minor_unit": 2}, "billing_months": 1, "taxes": "included", "fees": []}]
      },
      {
        "provider_id": "example-b",
        "availability": "available",
        "freshness": "fresh",
        "relation": "exact",
        "price_scope": "192.0.2.0/24",
        "quotes": [{"id": "monthly", "price": {"currency": "USD", "amount_minor": 1000, "minor_unit": 2}, "billing_months": 1, "taxes": "unknown", "fees": []}]
      }
    ]
  },
  "history": {
    "tracking_started_at": "2026-11-25T00:00:00Z",
    "items": [
      {"id": 1, "provider_id": "example-a", "listing_id": "example-a_old", "type": "listed", "observed_at": "2026-11-25T00:00:00Z", "after_prices": [{"quote": {"id": "monthly", "price": {"currency": "USD", "amount_minor": 1000, "minor_unit": 2}, "billing_months": 1, "taxes": "included", "fees": []}}]},
      {"id": 2, "provider_id": "example-b", "listing_id": "example-b_other", "type": "listed", "observed_at": "2026-11-25T00:00:00Z", "after_prices": [{"quote": {"id": "monthly", "price": {"currency": "USD", "amount_minor": 1000, "minor_unit": 2}, "billing_months": 1, "taxes": "unknown", "fees": []}, "first_period_total": null, "first_period_unknowns": ["taxes_unknown"]}]},
      {"id": 3, "provider_id": "example-a", "listing_id": "example-a_old", "type": "changed", "observed_at": "2026-11-25T00:01:00Z", "before_prices": [{"quote": {"id": "monthly", "price": {"currency": "USD", "amount_minor": 1000, "minor_unit": 2}, "billing_months": 1, "taxes": "included", "fees": []}}], "after_prices": [{"quote": {"id": "monthly", "price": {"currency": "USD", "amount_minor": 1500, "minor_unit": 2}, "billing_months": 1, "taxes": "included", "fees": []}}]}
    ]
  },
  "polls": {
    "items": [
      {"id": 1, "provider_id": "example-a", "observed_at": "2026-11-25T00:00:00Z", "complete": true},
      {"id": 2, "provider_id": "example-b", "observed_at": "2026-11-25T00:00:00Z", "complete": true},
      {"id": 3, "provider_id": "example-a", "observed_at": "2026-11-25T00:01:00Z", "complete": true},
      {"id": 4, "provider_id": "example-a", "observed_at": "2026-11-25T00:02:00Z", "complete": false}
    ]
  }
}
```

For provider `example-a`, listing `example-a_old`, lease/monthly/USD with minor unit 2, the observed asking-price series is 1000 → 1500. The failed poll adds a gap, not a zero price, sale, removal or renewal-price guarantee. The second provider's USD quote is a separate series; its unknown taxes prevent a full total even when the base amount matches another offer. For a related /22 offer the response would instead say `relation=parent`, `price_scope=192.0.0.0/22` and keep its quote separate from this /24 series.

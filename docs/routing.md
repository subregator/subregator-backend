# BGP and RPKI explanations

`GET /api/v1/network` and MCP `inspect_network` return the same cached metrics. Published offers include the same normalized explanations in `checks.bgp.bgp` and `checks.rpki.rpki`. Reads never schedule collection. Hidden prefixes are not inferred, collected or attached to offers. No additional source, service, dependency, credential or configuration is required.

## BGP

The `prefix_overview` metric adds `bgp`: actual `prefix` when identified, `relation` (`exact`, `covering`, `unknown`), deduplicated `origins`, `filtered_prefixes`, `completeness` and source `query_time` when supplied. Offer checks retain `announced`, `covering_route`, `not_announced` and `unavailable`. Source 404/no coverage is `no_data`, not a non-announcement. A negative finding requires an exact, explicitly unannounced observation with an empty origin list and no filtered prefixes.

When RIPEstat sets `is_less_specific` but echoes the requested resource, the covering route's actual prefix is unknown and omitted. An unrelated returned prefix never becomes an exact or covering finding. Missing or filtered origin evidence cannot establish complete coverage. Collector visibility is limited to RIS; BGP observation is not a packet reachability guarantee.

The existing `routing_status` collector supplies separately dated `routing` context on embedded BGP checks and on network BGP metrics when `routing_status` is included in the request: RIS `peers_seeing` / `total_peers` for the address family, `query_time`, and `first_seen` / `last_seen` when supplied in a supported shape. The latter retain their own route prefix and origin; a containing route's first-seen date is not the exact prefix's first-seen date. Routing status has its own source URL, collection dates and observation envelope. Its older snapshot never refreshes the prefix overview or supplies replacement origins. Raw routing-status data remains available on the cached network metric. Missing counts and dates are omitted, never synthesized. Peer counts are not counts of collectors.

`observed_at` is capture time; `query_time` is the source snapshot time. Consumers must inspect both. `completeness=complete` describes the supplied origin set within source coverage, never worldwide visibility. Automatic compact evidence retains at most four origins and marks omitted evidence partial; it does not pretend the omitted set is empty.

## RPKI

The `rpki` metric and embedded RPKI check add `rpki`, including:

- The validated `prefix`, `basis`, aggregate `status`, `completeness`, `origin_limit=4` and `truncated` flag.
- Per-origin ASN, `status`, source URL and capture time. Supported statuses are `valid`, `invalid_asn`, `invalid_length`, `not_found` and `unavailable`. RIPEstat `unknown` maps to `not_found`; it is not invalid.
- Supplied `validating_roas` become `covering_roas` with canonical prefix, authorized `asn` (including explicit AS0) and `max_length`. Unrelated or malformed ROAs are excluded. At most 32 supplied entries per origin are examined; `roas_truncated` records that limit. An empty list means no supported explanation was supplied, not proof of no ROA. The source validity finding is not recomputed from this bounded explanation list.
- `origin_observed_at` / `origin_expires_at` when collected with prefix-overview evidence. Validation expiry cannot outlive that dependency.

All supplied origins must match the currently observed origin set for an aggregate `valid`, `invalid`, `not_found` or `mixed` finding. Different per-origin states yield `mixed`. An omitted origin, four-origin request limit, filtered/unknown BGP completeness, malformed or mismatched prefix/ASN pair, unsupported validity state or failed origin request yields `partial`. Successes survive another origin's failure; failed responses and their bodies are not published as explanations. No unknown, stale or partial result establishes a passing result. Origin ordering and duplicates do not change the compared set; changed origins invalidate the old aggregate on cached network and offer reads.

`basis=observed_origins` describes current observed origins. A query with `asn` is labeled `basis=proposed_asn` and `observation.scope.relation=prefix_asn`; it is a separate prefix/ASN validation and never a claim that the customer ASN is currently announcing. Automatic collection does not schedule proposed-ASN checks. Public queries without an existing cache entry remain pending. Current ROA validation is not historical validation, registry ownership, reputation or a safety score.

Example normalized explanation (synthetic; parent source/freshness/scope envelope omitted):

```json
{
  "prefix": "1.1.1.0/24",
  "basis": "observed_origins",
  "status": "invalid",
  "completeness": "complete",
  "origin_limit": 4,
  "truncated": false,
  "origins": [{
    "asn": 13335,
    "status": "invalid_length",
    "source_url": "https://stat.ripe.net/data/rpki-validation/data.json?resource=13335&prefix=1.1.1.0%2F24",
    "observed_at": "2026-11-25T00:00:00Z",
    "roas_truncated": false,
    "covering_roas": [{"prefix": "1.1.0.0/16", "asn": 13335, "max_length": 23}]
  }]
}
```

## Storage, limits and compatibility

Fields are additive; the raw metric payload and existing finding/freshness fields remain. Existing JSON cache rows are projected without upstream requests; legacy validations require a matching cached prefix overview for current-origin completeness. PostgreSQL requires no schema migration. Raw metrics and compact offer reports remain in the existing 50,000-entry bounded cache, survive restart while retained, and may be evicted. This is not the durable observation archive planned in BE-10. Legacy offer reports without raw metrics retain their previous limited explanations until recollection; absent fields do not prove completeness.

Collection reuses the existing shared budget, source Retry-After persistence, cancellation, four HTTP slots, eight-second HTTP timeout and 1 MiB response limit. Each RPKI collection performs at most four distinct prefix/ASN validations and reuses its prefix-overview dependency. Origin-derived ASRank/neighbour requests retain their previous four-origin bound. Full source ROA histories, independent validators and additional collector services are outside this slice.

Verification uses synthetic source fixtures, REST/MCP contract tests, race tests and real PostgreSQL restart tests. Live provider compatibility, externally verified collector capacity, source redistribution/retention permission, stand and production deployment remain unverified.

Sources: [prefix overview](https://stat.ripe.net/docs/data-api/api-endpoints/prefix-overview), [routing status](https://stat.ripe.net/docs/data-api/api-endpoints/routing-status), [RPKI validation](https://stat.ripe.net/docs/data-api/api-endpoints/rpki-validation).

See [durable observation history](observation-history.md) for the separate default-off retention/publication allowlist, source restrictions, conservative change bounds and PostgreSQL migration.

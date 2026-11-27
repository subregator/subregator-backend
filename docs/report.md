# Cached subnet report

`GET /api/v1/report?resource=1.1.1.0%2F24` and MCP `subnet_report` combine permitted exact-prefix market offers, current network observations and a bounded resource timeline. These are local and cached reads; requesting a report never schedules upstream collection. No aggregate safety score, ownership guarantee or completed-sale inference is produced.

```sh
curl --fail --get https://api.subregator.com/api/v1/report \
  --data-urlencode resource=1.1.1.0/24 --data-urlencode limit=10
```

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"subnet_report","arguments":{"filters":{"resource":"1.1.1.0/24","limit":"10"}}}}
```

The example prefix must be present in the deployment's public catalogue or permitted historical provider associations. Unknown, hidden and pending-only resources return the same 404 without disclosing cached observations. Public IPv4 and IPv6 CIDRs are supported. Current publication, prefix visibility, source enablement and history policies are evaluated on every request; a previously public resource becoming private loses access to all report sections.

## Contract

- `generated_at` is the report assembly time. Every offer and network observation retains its own source URL, observation/source-update dates, freshness, scope and completeness. There is no common source freshness timestamp.
- `market.data` is the existing `MarketCurrent` contract: published seller offers, all tariffs/terms, and `QuoteCosts` calculated by the existing monetary code. Unknown taxes/fees, conditional fees and mismatched currencies leave totals unknown. A source's reported zero and an unknown amount remain distinct. Market gaps explicitly limit coverage to published offers; no unlisted-seller coverage is implied.
- `network.data.current` is the existing cached `NetworkReport` for the automatically collected overview, routing, RPKI, registration, RDAP, optional IRR, AbuseIPDB and ZEN checks, ASN relationships and announced prefixes. `network.data.drop` reuses the automatic collector's current DROP observation. Optional sources remain subject to their existing enablement and publication gates. Missing data stays pending/disabled/not-configured, expired data stays stale and cached-storage failures are explicit metric errors with a generic public message. Raw storage errors are never returned. Other ad hoc checks remain available through the network endpoint rather than being added to this report.
- `timeline.data` is the existing `TimelineResult`, with permitted listing events and approved archived checks. `network_history` describes whether check history is enabled by configuration; it does not assert that any snapshots exist. `network_history_disabled`, `no_archived_network_observations`, `no_permitted_events`, `history_failed` and `history_disabled` distinguish those cases. Unavailable source histories remain explicit. Archive configuration is never changed by this endpoint.

Each section has `status` (`available`, `partial`, `empty`, `disabled`, `error`), nullable `data`, explicit `gaps`, `truncated`, the underlying section `url` and optional continuation `next`. Availability is not a safety or completeness verdict. Network metrics retain individual completeness and failure states. Errors in cached network or timeline reads preserve available current market data. If only historical associations could establish public access and that storage is unavailable, the request returns 503 rather than exposing retained checks for an unverified resource.

## Bounds and continuation

`limit` defaults to 20 and accepts 1–50, separately bounding offers and timeline events. `offset` and `snapshot` use the existing current-market pagination contract; `cursor` uses the existing resource- and policy-bound timeline contract. Unknown/repeated parameters are rejected. Timeline cursors are validated by the existing timeline query when history storage is available; if history is disabled or unavailable, the report keeps that section disabled/error without claiming the cursor was validated. A stale market snapshot returns 409; restart current-offer pagination. A policy change invalidates an old timeline cursor.

Follow each section's `next` URL. Current-offer pagination continues through the report endpoint, so it keeps working when history is disabled or unavailable. Timeline pagination continues through its existing endpoint. These are independent continuations, not a shared cursor or a claim of an atomic snapshot across sources. MCP clients can use `subnet_report` for current-offer continuation and `resource_timeline` for timeline continuation with the query parameters.

Each serialized section is capped at 512 KiB and the complete report at 2 MiB. If a section exceeds its cap, its `data` is omitted, `status` becomes `partial`, `truncated` is true, and `gaps` includes `section_exceeds_report_byte_limit; read_section_url`. Its `next` points to the underlying endpoint, where the caller can lower the page size. This byte limit may omit a single large observation rather than summarize away its uncertainty or silently cut evidence. Other sections remain available. A byte-limit fallback points to the original section endpoint; that endpoint can itself be unavailable (in particular, the original market endpoint also reads history). This is distinct from ordinary report offer pagination, which continues without history. The report does not take new database locks, open result sets or upstream slots; existing bounded query and cache paths own those resources.

# API and data reference

[Back to README](../README.md)

The REST API and MCP tools expose the same read-only catalogue and observations.

## API

- `GET /api/v1/offers`: filters, deterministic sorting, pagination and facets.
- `GET /api/v1/offers/{id}`: complete normalized resource and its quotes.
- `GET /api/v1/providers`: registry, publication restrictions, attempts and last successful refresh.
- `GET /openapi.json`: versioned contract.
- `GET /healthz`: process liveness.
- `GET /readyz`: successful source snapshot exists; inspect source freshness separately.

```sh
curl 'http://localhost:8080/api/v1/offers?country=DE,NL&family=4&currency=USD&sort=price_asc&limit=20'
curl 'http://localhost:8080/api/v1/offers?provider=prefix-broker&currency=EUR&model=purchase'
```

Copy the response `snapshot` into subsequent page requests with `offset`. A refresh returns 409 for an old snapshot; restart pagination. An ID is stable for the provider's external resource ID. There is no CIDR-based deduplication across providers: these may be distinct commercial offers.

Price sorting compares the cheapest matching base quote as an exact rational value: cycle amount divided by billing months for leases, full amount for purchases. Currency must be specified; no exchange rates are assumed. `min_price_minor`/`max_price_minor` use hundredths of that currency, independent of the source's `minor_unit`. Never combine purchase and lease prices into a recommendation; filter `model`. Fees, taxes and deposits remain separate, with unknown costs represented as null. Every quote is returned, with `matching_quote_ids` identifying which quotes matched the query.

`country` refers to provider geolocation/registry data by default. A seller's country only matches with `geography_basis=seller_country`; it is not the subnet's location. IPv6 counts are decimal strings to avoid integer overflow or browser precision loss. Prefixes can be hidden while size, price and conditions remain available. Empty inventory is distinct from a failed or incomplete import.

## Sources and permissions

ONIE public API and the approved [Peaktera CSV API](https://www.peaktera.com/developers) are polled every 15 minutes. Peaktera uses ETag validation, exact per-term order links and attribution (Data: Peaktera); offers expire from public responses after one hour, including after failed refreshes or restarts. Historical Peaktera data is retained privately but excluded from public history. Billing terms are minimum commitments; setup fees and refundable deposits are separate from base prices and included in any upfront total. OBHost public IPv4 inventory is collected daily, retaining exact prefixes, published monthly prices and reserved/leased availability; unpriced ranges require a quote. Explicit redistribution permission has been requested; ONIE and OBHost policies say `public_source`, not `approved`. Prefix Broker permits anonymous public-page collection at most daily and prohibits displaying prefixes. The adapter imports its purchase listings without prefixes and preserves seller-country semantics. Leasing listings need a separate adapter.

Five providers have enabled built-in collectors. ELISTEKA supplies its approved public [production JSON feed](https://elisteka.com/feeds/subregator.json), with attempts at most once every 24 hours after 04:05 UTC. IPv4 lease products may be waitlisted; available IPv6 products remain distinct. No exact ELISTEKA CIDRs are published. Other providers remain disconnected until a usable feed and display terms are agreed; ip4.market has not supplied an endpoint or credentials. The registry contains 27 providers; this does not imply 27 connected inventories. No private API credentials are required or included.

Failures, invalid rows, duplicate IDs, changed pagination totals and incomplete feeds retain the last complete provider snapshot. Source status and per-offer freshness disclose this. Staleness also takes effect after two refresh intervals even without a reported failure, unless the provider sets a shorter `max_current_age_seconds`. ELISTEKA uses a maximum of 36 hours for both the latest successful snapshot and provider offer observations. Its stale offers are excluded from default searches and facets. To inspect retained historical offers, explicitly pass `fresh_only=false`; results carry `freshness: "stale"`. For both IPv4 waitlists and IPv6 inventory, use `provider=elisteka&availability=available,waitlist&fresh_only=false`. Offer detail and listing history remain accessible; expiry never deletes observations or invents a removal event. A provider becoming successfully empty removes its old offers. Refresh intervals apply to attempts, including across restarts after a persisted failure. Do not run multiple replicas polling the same restricted provider without a shared scheduler.

## Provider feed contract

[Feed schema](../examples/feed.schema.json) and [example feed](../examples/elisteka.json) describe canonical JSON v1. The example is synthetic, waitlisted, and not loaded by default. Drop a complete feed at `<feeds-dir>/<provider-id>.json` using an atomic file replacement. Enable its registry policy in a separate providers JSON only after agreeing permission; copying `internal/catalog/providers.json` is the starting point. Every feed offer must contain the provider observation timestamp `observed_at`; rereading an old file does not make its offers fresh. File feeds take precedence over built-in polling. No arbitrary URL fetching or public ingestion endpoint is exposed.

Each offer can carry IPv4 or IPv6, purchase or lease model, available/waitlisted/upcoming/unavailable/unknown state, RIR and transfer registries, geography with provenance, multiple billing terms, money and conditional fees, routing capabilities, permitted/prohibited use, notice period, source timestamps and product URL. Missing capabilities do not mean unsupported. Unstructured raw source payloads are deliberately excluded from the public contract.

## Durable history

A successful complete provider catalogue is committed in one PostgreSQL transaction with its current snapshot, listing lifecycle and change events. Readers still use an immutable in-memory view; a database failure prevents publication of an undurable catalogue. Source failures and incomplete/invalid imports retain the last successful inventory and create no disappearance events.

- `GET /api/v1/history`: append-only `baseline`, `listed`, `changed`, `removed`, `relisted`, `resource_changed` events. Filters: provider, listing_id, resource (IP/CIDR), resource_id, type, since, until, after_id, limit.
- `GET /api/v1/listings/{id}`: first/last observations, active state, removal time, appearance count and last offer, including listings no longer in the current catalogue.
- `GET /api/v1/resources`: exact public-prefix identities and the providers that listed them. Filters: provider, resource, after_id, limit.

`resource_reappeared` records a network returning after an observed complete-catalogue absence, including a new listing ID. A changed listing ID without an intervening absence is not a reappearance. A changed CIDR under the same listing ID remains linked to both the previous and new resource histories. Appearance counts belong to the listing identity; the resource flag captures network-level reappearance.

`observed_at` on an event is collection time; the embedded offer retains the source observation timestamp. An active listing means present in the latest successful catalogue, not a guarantee of current inventory or fresh data. Resource active-offer counts have the same observation semantics. The provider list exposes freshness independently.

Public CIDRs correlate only by exact canonical prefix. Masked offers remain individual listing histories; they cannot be linked to an inferred prefix or another provider. Current publication policy also applies to historical responses. A network being seen at two sellers does not establish ownership or prove a transfer. Provider associations and registry/ASN ownership data remain separate.

Follow `next_after_id` for event pagination and polling. Event IDs are append-only; catalogue snapshot pagination remains independent. `tracking_started_at` bounds local coverage. A one-time legacy import produces baseline observations rather than invented earlier events. Observations before collection began are unavailable unless an external historical source provides them.

PostgreSQL stores networks as `cidr` with a GiST index; durable JSON payloads remain byte-preserved. A 16-connection pool separates concurrent history reads from ingestion. Catalogue transactions are serialized with an advisory transaction lock so committed event cursors retain their order; the process writer lease prevents stale in-memory snapshots from competing across processes. This release still runs one ingestion process. The pool uses a 5-second connection timeout, a 30-second statement timeout and a 60-second idle-transaction timeout. Listing history has no automatic expiry. Network cache data is disposable and bounded to 2,000 entries; it is not a complete archive of every lookup. Back up PostgreSQL with supported PostgreSQL tools and retain WAL archives for point-in-time recovery where required; filesystem copies of a running database are not a backup procedure. Database role permissions, TLS and backup retention must be configured for the deployment.

## Automatic offer checks

The Go backend continuously checks each distinct published public prefix, shared across providers. The default inspection collects prefix overview, routing status, RPKI, registration and authoritative RDAP. A single ingestion process runs bounded per-check queues, reuses source TTLs and duplicate-request suppression, and shares `SUBREGATOR_CHECKS_RPM` across actual requests. Withheld prefixes are never inferred or submitted to sources. Removed prefixes leave the live result map.

Offer list and detail responses include `checks`: exact-prefix BGP visibility, all-observed-origin RPKI validation, and overlap with the complete Spamhaus DROP IPv4 or IPv6 dataset. Results are read from memory, with no upstream calls or database reads on the offer request path. Each result exposes its own status, freshness, timestamps, source and coverage. New prefixes are explicitly pending until collected; expired observations become stale immediately. Source failures never establish a passing result. RPKI and DROP are source-scoped risk signals, not a universal reputation score or safety guarantee.

Reports and metric observations survive restart through the bounded PostgreSQL cache. Up to 2,000 recent report/metric entries are retained, plus two DROP feed records in a separate table that older cache eviction cannot remove. Evicted reports are rebuilt automatically; a restart can temporarily show pending for them. DROP is downloaded at most once per day per address family, with the next attempt persisted before download, including failed attempts. Metadata, source date, copyright, complete record count and canonical prefixes are validated before publication. A failed refresh retains explicitly stale prior data. Failed completion writes are retried without another download or a new daily reservation; stopping before a successful retry can still lose the unsaved dataset. The background collector waits for request-budget windows so multi-origin RPKI can complete even at one request per minute, publishing completed checks as it progresses. See the [Spamhaus DROP usage requirements](https://www.spamhaus.org/faqs/do-not-route-or-peer-drop/).

`GET /api/v1/network` and MCP `inspect_network` now read existing cached observations only. These cache-only operations do not consume the upstream budget. The separate `/api/v1/network/lookup` and MCP `lookup_network` can collect missing or expired observations under the same process limits. Arbitrary IP/ASN queries, advanced checks and historical parameter combinations without stored results remain pending. The updated frontend consumes the checks embedded in offers and removes per-row check requests and manual check buttons. Deploy that frontend separately. Keep the legacy frontend check-cache volume mounted in Compose until its image has been updated; the previous image requires this writable path during startup.

Collection throughput is bounded by source quotas, independently of fast catalogue reads. A large cold catalogue needs time to populate; the five-minute routing TTL can exceed the refresh capacity at the default 120 requests/minute. Measure source coverage and freshness before increasing budgets or adding sources. There is one scheduler per process; the existing database writer lease enforces a single ingestion process.

## Public network lookup

`GET /api/v1/network/lookup` accepts any public IP, prefix or ASN, without authentication. `checks=all` includes every defined check, with explicit unsupported, unconfigured and unavailable states. Active ping/traceroute use one selected address and three requested continents; whole-prefix DNSBL collection supports up to 256 addresses and resumes across requests. Throughput requires an explicit test URL inside the requested resource. See the [complete network evidence contract](network-checks.md).

```sh
curl 'http://localhost:8080/api/v1/network/lookup?resource=163.5.251.0%2F24&checks=all'
```

## Cached network observations

Optional `abuse` exposes source report counts, dates, actual search ranges and query windows without raw complaint logs. It is off by default and requires an approved AbuseIPDB account/key and public use/retention conditions. See the [abuse observation contract](abuse.md). Zero reports is not a safety or resolution finding.

Optional `irr` compares registry route/route6 objects with observed BGP origins. It is off by default until registry public-use/retention rights are confirmed. Background collection and explicit on-demand lookup can query the private IRRd mirror; cache-only REST/MCP requests read stored normalized evidence. See [IRR consistency](irr.md) for configuration, distinct outcomes, scope, dates and coverage.

BGP scope, separately dated RIS visibility and per-origin RPKI results are documented in the [routing explanation contract](routing.md). Exact and covering routes remain distinct; filtered, truncated or failed origins remain partial. Proposed ASN validation is separate from observed origins.

Current `rdap` and `registration` metrics include typed registry records, RIR, range relationships, public entities, dates and unverified abuse contacts. See the [registration contract](registration.md) for fallback collection, partial coverage and source limits.

Every metric and embedded offer check includes an additive `observation` envelope that separates collection status, freshness, completeness and typed scope from the existing finding. See the [observation contract](check-results.md) for states, examples and compatibility. `/api/v1/network/checks` reports which metric definitions are collected automatically; other definitions do not imply scheduled collection.

`GET /api/v1/network/status` and MCP `network_status` return aggregate process-local coverage for the six existing automatic checks plus the optional, default-disabled IRR and abuse checks, observation age, due/unscheduled prefixes and jobs, running/suppressed work, scheduling lag, source request counts/duration/failures, budget waits/denials and persistence failures. Reads call no upstream source or database and return no prefix IDs or credential-bearing URLs. Counters reset on restart; metadata-only coverage is rebuilt as the worker restores/recollects observations. A missing collector returns 503. `scheduler_policy` is `per_check_ttl`; the legacy sweep-floor field is deprecated and zero because artificial prefix pacing was removed. See [scheduling rules](scheduling.md), the [capacity report](collection-capacity.md) and [source-access inventory](source-access.md).

```sh
curl 'http://localhost:8080/api/v1/network/checks'
curl 'http://localhost:8080/api/v1/network?resource=1.1.1.0/24&checks=prefix_overview,routing_status,rpki,rdap'
curl 'http://localhost:8080/api/v1/network?resource=AS13335&checks=asn_neighbours,asn_rank'
curl 'http://localhost:8080/api/v1/network?resource=193.0.20.0/24&checks=registration_history&version=2020-01-01T00:00:00Z'
```

Available checks include BGP overview/status, collector AS paths, routing history, current registration, historical registration versions, allocation and transfer history, RPKI prefix/ASN validation, ASN overview/neighbours, authoritative RIR RDAP and CAIDA ASRank. IPinfo Lite optionally supplies free country/ASN data for a specific IP when a free token is configured. The on-demand lookup also supports geolocation estimates, incremental per-address DNSBL collection, public Globalping ping/traceroute jobs and bounded HTTP throughput with an explicit test URL. See the [network evidence contract](network-checks.md) for completion, limits and source coverage. No synthetic reputation or ownership score is produced.

Stored metrics carry their source URL, capture time, cache expiry, status and coverage. An unavailable check stays unknown. Failed refreshes can return explicitly stale cached observations. Cache TTLs range from one minute for Looking Glass to one day for infrequently changing records; the capabilities endpoint reports each TTL. Concurrent identical checks are deduplicated. Inspections and upstream requests have bounded concurrency and a shared configurable budget of 1..600 upstream requests/minute. Each upstream response is limited to 1 MiB; a truncated/invalid response is not accepted as complete data.

Routing-history windows accept start_time/end_time, up to 366 days per request; the default is seven days. Historical Whois accepts version number or timestamp and covers RIPE Database objects only. It is not a worldwide ownership ledger. RIR transfer records may describe a containing block and omit non-public transfers. BGP visibility and ASN adjacency are collector observations, not a packet-delivery guarantee. RPKI validates an explicit prefix/origin pair; it is not a reputation score. Origin-derived checks cover at most four ASNs.

CAIDA ASRank is an ASN customer-cone topology ranking, not a per-subnet reputation score. Responses carry attribution and date of use. Before publicly displaying CAIDA-derived results, follow the [Public AUA](https://www.caida.org/about/legal/aua/public_aua/), including its citation and publication-report requirements. This release does not send any publication reports automatically.

Sources: [RIPEstat API](https://stat.ripe.net/docs/data-api/ripestat-data-api), [historical Whois coverage](https://stat.ripe.net/docs/data-api/api-endpoints/historical-whois), [IANA RDAP bootstrap](https://data.iana.org/rdap/), [CAIDA ASRank](https://catalog.caida.org/dataset/as_rank), [IPinfo Lite](https://ipinfo.io/developers).

## MCP Streamable HTTP

The `/mcp` endpoint implements Streamable HTTP using the official Go SDK. It is stateless, uses SSE responses, negotiates the protocol and requires no sticky sessions. It exposes the same service operations and validation as REST:

`search_offers`, `get_offer`, `list_providers`, `get_listing`, `listing_history`, `known_resources`, `inspect_network`, `lookup_network`, `network_checks`, `network_status`, `get_api_schema`.

Filter tools accept a `filters` object containing the normal REST parameter names and values. Both network tools accept resource, checks (including `all`), start_time, end_time, version, asn, address and test_url. `inspect_network` is cache-only; `lookup_network` may collect external observations. Results use structured content, with protocol-standard tool errors for invalid operations. Browser clients must use the allowed origin; JSON-RPC bodies are limited to 1 MiB.

Public client connection after deployment (use `http://localhost:8080/mcp` locally):

```json
{
  "mcpServers": {
    "subregator": {
      "url": "https://mcp.subregator.com/"
    }
  }
}
```

The public API is read-only and does not provide administrative feed imports or purchasing operations. Place TLS and appropriate public request limits in front of a deployed service.

## Scope

This release remains a single-writer catalogue and history service. There is no account system, checkout, purchase automation, currency conversion or distributed scheduler. Current listing queries stay in memory; PostgreSQL stores durable observations and a bounded external-result cache. Multiple ingestion writers or independent API replicas require coordinated scheduling and cache refresh before enabling them; sharing PostgreSQL alone does not synchronize each process's in-memory catalogue.

See [subnet market and price history](subnet-market.md) for exact-prefix seller comparison, quoted costs, provider gaps, REST/MCP pagination and explicit parent/child relationships.

See [durable observation history](observation-history.md) for the separate default-off retention/publication allowlist, source restrictions, conservative change bounds and PostgreSQL migration.

See the [resource timeline](timeline.md) for cached REST/MCP pagination combining listing and permitted network histories.

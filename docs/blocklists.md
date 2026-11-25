# Independent blocklist observations

BE-09 extends the existing complete Spamhaus DROP overlap check with an optional `spamhaus_zen` check. It keeps SBL, XBL and PBL separate. Absence from DROP is never universal blocklist clearance. PBL is outbound mail policy, not an abuse conviction, and source listings do not identify a current tenant or prove ownership.

## Access and collection

The adapter uses Spamhaus **DNS Blocklists via HTTPS**, fixed endpoint `https://apibl.spamhaus.net/lookup/v1/ZEN/<IP>`. This is a separate product from DQS DNS and the Intelligence API; their keys and entitlements are not interchangeable. `SUBREGATOR_SPAMHAUS=false` is the default. Configure `SUBREGATOR_SPAMHAUS_KEY` through the process environment and enable `SUBREGATOR_SPAMHAUS=true` only after confirming the correct product, quota and public display/cache/history rights. There is no key flag, URL parameter or public key field. An absent key or off gate suppresses collection and publication of retained ZEN data.

There is no configured licensed account, numerical quota or agreed public-aggregator license verified for this integration. No trial, purchase or operator message was initiated. Authenticated live compatibility remains unverified; tests use synthetic responses based on the official protocol. The access/pilot acceptance criterion remains open. DROP's existing public permission does not establish SBL/XBL/PBL rights.

Each collection performs exactly one HTTPS GET, no DNS query, TXT lookup, pagination, active scan or address enumeration. For a current IP or single-host prefix, coverage is that exact IP. For any larger public IPv4/IPv6 prefix, only the canonical first address is queried and `selection=prefix_first_address`, `scope_relation=contained`, `completeness=partial` are explicit. This sample is a bounded initial signal, not a representative sample or a subnet-wide lookup. A listed sample does not mean every address is listed; a negative sample never means a subnet is unlisted or safe. Source-provided listing ranges are unavailable from this endpoint and are not invented.

The existing automatic worker queries published exact prefixes only; hidden or product-only prefixes stay excluded. IP observations may be collected internally, but standalone public REST/MCP requests remain cached-only. Historical/version, ASN and proposed-ASN requests are not applicable. Visitors cannot spend source quota or enable collection.

Existing FIFO budgets, four shared HTTP slots, cancellation, eight-second HTTP timeout, 1 MiB response limit, duplicate-work suppression and persisted source-wide Retry-After limits are reused. Successful samples have a conservative one-hour local TTL; this is a scheduling choice, not a source freshness promise. The source publishes no listing-update timestamp in this response. Observed time is local capture time; source_updated_at remains absent. No extra service or dependency is needed.

## Contract and failures

REST `/api/v1/network?resource=1.1.1.0/24&checks=spamhaus_zen` and MCP `inspect_network` return `metrics[].blocklists`. Offer checks expose optional `checks.zen`, independently of `checks.blocklist` (DROP). Capabilities and collection health describe the source and its configuration state.

`blocklists` contains requested resource, actual queried address, selection, scope relation, completeness and separate SBL/XBL/PBL findings. Each finding has status, all applicable source return codes and a reason. Codes 1002/1003/1009 are SBL/CSS/DROP flags, 1004 is XBL and 1010/1011 are PBL. Duplicate codes are deduplicated without dropping distinct findings. No raw external error body, account identifier, key or untrusted diagnostic text is published.

HTTP 200 requires a non-empty valid code array and matching body status. Unknown, domain-only or unexpected codes fail the observation rather than fabricating missing lists. A negative requires HTTP 404 and a valid matching JSON status with no resp field. Malformed gateway 404 pages are failures. HTTP 401/403 is access_denied; 429 is rate_limited with persisted retry time. Other HTTP/protocol errors remain unavailable. Retained observations after failed refresh are stale; expiry cannot become a fresh negative. A successful partial sample remains partial even when all three lists returned negative.

Normalized observations and offer reports use existing PostgreSQL JSON persistence and survive restart. Legacy reports without zen remain readable. The bounded cache is not durable history; BE-10 owns historical storage and change semantics. Cache expiry, source errors or eviction do not establish delisting or resolution.

DROP still validates complete family datasets, source dates/copyright and record counts, checks all containing/contained overlaps and reserves attempts durably at most once daily per family. Duplicate exact records are now rejected rather than accepted as a complete dataset. ZEN does not replace or alter that source's schedule.

## Validation and next steps

Synthetic tests cover multiple return codes, duplicate/unknown codes, positive/negative/error/access/quota cases, IPv4/IPv6 scope, partial samples, single-host scope, cached reads, PostgreSQL and offer restart, stale publication, configuration, header secrecy, cancellation, hidden-prefix restrictions and response bounds. Regression tests demonstrate duplicate DROP data and malformed negative responses failing before their corrections. Required checks are run against the unchanged base and final code; local container smoke uses source collection disabled.

Next: obtain licensed HTTPS product access and agree quota, IP selection/refresh strategy, public REST/MCP display and retention, then perform a bounded authenticated pilot. Whole-subnet SBL/XBL/PBL coverage is not implemented or claimed. A future range API or full bounded address collection needs separate capacity and coverage validation. Hosted CI for unpublished commits and production are unverified.

References reviewed 2026-11-25: [HTTPS product](https://docs.spamhaus.com/datasets/docs/source/70-access-methods/web-query-service/000-intro.html), [authentication](https://docs.spamhaus.com/datasets/docs/source/70-access-methods/web-query-service/020-api-auth.html), [requests and return codes](https://docs.spamhaus.com/datasets/docs/source/70-access-methods/web-query-service/040-api-queries.html), [list semantics](https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/030-datasets.html).

A public alternative probe of `https://sslbl.abuse.ch/blacklist/sslipblacklist.csv` returned a notice that the IP list was deprecated on 2025-01-03, with that stale update date. Its empty body was not treated as a current all-clear and it was not integrated. No claim about other SSLBL products is made from that one file.

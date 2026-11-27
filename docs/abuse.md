# Source abuse observations

The optional `abuse` check reads AbuseIPDB check-block summaries for a current public IPv4 or bounded IPv6 prefix. It returns source claims about addresses and reports, not a safety score, a clean bill of health, attribution to a current tenant or proof of resolution. A report disappearing from a rolling window does not prove it was resolved.

## Access gate and scope

`SUBREGATOR_ABUSEIPDB=false` is the default. `SUBREGATOR_ABUSEIPDB_KEY` is environment-only; no key flag, query parameter, public field or log entry is added. Configure both an approved key and `SUBREGATOR_ABUSEIPDB=true` (or `-abuseipdb=true`) only after confirming account entitlement, quota, public-display and cache-retention rights. An absent key remains `not_configured`, even with the enablement flag. An off gate suppresses collection and publication of retained abuse observations. Configuration is set before workers start. `SUBREGATOR_NETWORK=false` still prevents upstream requests.

The owner provided a key for evaluation on 2026-11-25. Authenticated requests and a final request through the Go collector succeeded. The key was used transiently without writing it to the repository, environment files, command-line arguments or issues. No production credential location has been provisioned and no source collection has been enabled. The dashboard and response headers agree on 100 check-block requests/day; the exact billing plan and any separate agreement were not inspected.

The fixed GET endpoint is `https://api.abuseipdb.com/api/v2/check-block`, with a 30-day `maxAgeInDays` and exact canonical requested prefix. Supported local scope is IPv4 /24–/31 and IPv6 /120–/127, containing 2–256 addresses. No address enumeration or subnet splitting is used. Larger ranges are intentionally not queried, even when accepted upstream. Single-host /32 and /128 requests return 422 upstream with instructions to use the separate `/check` endpoint; the adapter now rejects them locally rather than silently switching endpoints or quota pools. Historical/version parameters and proposed-ASN validation remain not applicable.

The account accepted IPv4 /24, /30, /31 and IPv6 /120, /127 with 30 days. IPv4 /23 and a 31-day window returned 402. IPv6 /119 (512 addresses) also succeeded upstream, but is outside our deliberate local bound. These observations establish only the tested shapes and account behavior; they do not establish a universal IPv6 plan limit or broad-family coverage.

HTTP 402 is `plan_limited` and paused for a day before revalidation; it never becomes an empty result or permanent silent suppression. Source-wide 429 windows survive restart; the source reset epoch is used when Retry-After is absent.

The [published terms](https://www.abuseipdb.com/legal.html), reviewed on 2026-11-25, distinguish evaluation/non-commercial Free use from commercial use and separately restrict exploitation/redistribution of API data without express permission. A successful key does not establish permission to publish an aggregator API. No plan upgrade, permission request or source-data publication was performed; commercial/public display and cache-retention conditions remain an enablement blocker.

## REST, MCP and offer contract

Use cached REST `/api/v1/network?resource=1.1.1.0/24&checks=abuse` or MCP `inspect_network`. Metrics add `abuse`; offers add optional `checks.abuse.abuse`. Public reads never start or refresh collection, fetch per-IP details or spend source budget. `/api/v1/network/checks` advertises the optional collector; `/api/v1/network/status` and MCP `network_status` distinguish its configuration/collection state and bounded source counters.

The normalized observation contains:

- Requested `prefix`, actual searched `range_start` / `range_end`, source `possible_hosts`, and `scope_relation` (`exact` or `contained`). Network address and netmask must match the requested prefix. A returned subset, such as host addresses .1–.254 of a /24, is partial for the requested /24; it is not expanded into full-prefix evidence.
- Fixed `window_days=30`, `window_start`, `window_end`, `window_basis=local_request_bounds` and `ingested_at`. The bounds run from local request start minus 30 days through response capture. They do not assert the source's exact query clock. Cache reads preserve the original window and ingestion time.
- `reported_ip_count`, `report_count` and latest known source `latest_report_at`, calculated from retained unique, valid address summaries. Counts describe source reports, not independently verified incidents. `counts_are_lower_bounds=true` marks incomplete requested-prefix evidence; absent or invalid data cannot establish a complete zero.
- Up to 256 `addresses`, each with address, source report count, supplied report timestamp and optional `source_confidence`. This confidence is the source's per-IP claim; there is no aggregate score. Duplicates, out-of-range addresses, missing/invalid timestamps or counts and inconsistent metadata make coverage partial. Parseable dates outside the requested window, including future source dates, remain visible as source claims with partial coverage rather than being silently discarded. The aggregate date is only the latest known retained source timestamp.
- `completeness`, `truncated`, `address_limit=256`, `details_coverage=not_collected` and explicit semantics. Source continuation/truncation signals are not followed and cannot count as complete coverage. No raw complaint text, reporter identities, source continuation URLs or contact data are retained or published.

Statuses are `reports_observed`, `no_reports_in_window` and `partial`. A complete zero means only that the source returned no reported addresses in the stated query scope/window. It never means safe, clean or resolved. Partial, stale or unknown evidence cannot establish a passing finding; expired offer explanations also become partial on read without changing the shared published snapshot.

Quota/auth errors, HTTP 404, malformed/error envelopes and oversized responses are failures, not negative report observations. `plan_limited` is distinct from missing configuration and unavailable data. Prior source failure handling retains stale observations where applicable; a plan denial exposes its explicit access failure. Source/ingestion dates and coverage remain separate. Past reports are never assigned to an offer's current seller or tenant.

## Work and persistence bounds

There is exactly one source request per abuse collection. There are no automatic `/check`, `/reports`, reporting, deletion or complaint-detail calls, no categories inferred from counts, no network scanning and no continuation fetch. Per-IP categories/details are deliberately deferred until a supported use case and account rights require them; the current detail work bound is zero. Adding such collection later requires its own pagination, privacy and budget verification.

The adapter reuses bounded queues, four shared HTTP slots, eight-second HTTP timeouts, the 1 MiB response limit, duplicate suppression, shared RPM budgets, source Retry-After persistence and cancellation. Successful summaries, including partial source coverage, use a one-day cache TTL to avoid repeated expensive block queries. Errors use existing backoff; account plan denials use a one-day pause. Hidden prefixes are excluded from the worker and are not inferred.

The existing PostgreSQL JSON cache and compact reports store only normalized summaries. Restart preserves retained source report and ingestion times; no schema migration or dependency is needed. Old reports without the optional field remain readable. The 50,000-entry cache may evict observations and is not a durable report archive. BE-10 owns historical storage and change semantics; aging out or cache eviction must not produce a resolution event.

## Validation and remaining work

Synthetic fixtures cover exact and subset IPv4/IPv6 scope, narrow /31 and /127, locally rejected /32 and /128 single hosts, broader/historical queries, empty/positive/partial results, source times, duplicates, mismatched ranges, pagination/truncation, overflow, 256-address bounds, missing fields, error envelopes, auth/plan/quota errors, quota restart, header secrecy, cancellation, hidden prefixes, cached-only REST/MCP, OpenAPI and PostgreSQL/report restart. These fixtures remain synthetic; live compatibility evidence is limited to the pilot below.

The unchanged BE-07 base and this branch must pass the same required checks. Review regressions are demonstrated failing before fixes, then rerun with race tests. Container smoke covers local runtime behavior with network collection disabled; it does not establish live account access or permission.

## Authenticated pilot — 2026-11-25

Thirteen read-only check-block requests were used, including validation failures and one final request through the actual Go collector. Last observed quota remaining: 87/100, with reset epoch supplied by the source. No per-IP check/report/detail call, write, account change or purchase occurred.

| Request | Observed result |
| --- | --- |
| IPv4 /24, /30, /31, 30 days | HTTP 200; returned metadata identified the complete requested address range. |
| IPv6 /120 and /127, 30 days | HTTP 200; complete requested range, accepted by the Go normalizer. |
| IPv4 /32 and IPv6 /128 | HTTP 422; source requires a different endpoint for a single host. |
| IPv4 /23 or 31-day window | HTTP 402; account query limits. |
| IPv6 /119 | HTTP 200; 512-address scope intentionally unsupported locally. |

The Go normalizer accepted five supported captured response shapes while preserving exact scope, source report dates and ingestion time; it rejected the successful upstream /119 response because it exceeds the local work bound. The actual Go collector also completed one authenticated IPv6 /127 request with its real transport and Key header. Sanitized pilot payloads remain local private test artifacts; actual report records and credentials are not committed or published in issues.

Next external step: confirm commercial/public-display and cache-retention conditions, then choose an approved capacity/plan for eligible inventory before enablement. With the observed 100-query/day quota, a cold 1,000-supported-prefix catalogue needs at least ten days before retries; full daily refresh of that example is impossible. This is a computed quota floor, not measured throughput. Hosted CI for unpublished commits, broader live coverage, public use rights, stand and production remain unverified.

Official references: [API v2](https://docs.abuseipdb.com/), [terms](https://www.abuseipdb.com/legal.html). Review date: 2026-11-25.

# Source abuse observations

The optional `abuse` check reads AbuseIPDB check-block summaries for a current public IPv4 prefix. It returns source claims about addresses and reports, not a safety score, a clean bill of health, attribution to a current tenant or proof of resolution. A report disappearing from a rolling window does not prove it was resolved.

## Access gate and scope

`SUBREGATOR_ABUSEIPDB=false` is the default. `SUBREGATOR_ABUSEIPDB_KEY` is environment-only; no key flag, query parameter, public field or log entry is added. Configure both an approved key and `SUBREGATOR_ABUSEIPDB=true` (or `-abuseipdb=true`) only after confirming account entitlement, quota, public-display and cache-retention rights. An absent key remains `not_configured`, even with the enablement flag. An off gate suppresses collection and publication of retained abuse observations. Configuration is set before workers start. `SUBREGATOR_NETWORK=false` still prevents upstream requests.

No matching key was found in the environment variable names or the original checkout's local environment configuration examined on 2026-11-25; values were not printed. No authenticated live pilot was possible. No plan, permission, source capacity or production readiness is claimed. The source therefore remains off. The first acceptance criterion in BE-08 remains open until the account pilot and terms are verified.

The provisional adapter uses one fixed GET endpoint, `https://api.abuseipdb.com/api/v2/check-block`, with a 30-day `maxAgeInDays` and the exact canonical requested prefix. It accepts IPv4 /24 through /32. Larger networks are not split or sampled. IPv6, individual IP/ASN resources, historical/version parameters and proposed-ASN validation are explicitly `not_applicable`. The API describes IPv6 support, but account-specific family limits and usable full-prefix responses have not been piloted; the adapter does not enumerate IPv6 space.

The vendor documents different plan allowances. This adapter deliberately implements the narrow common request shape; it does not infer a subscription from a key or add plan selection before a pilot. Verify current entitlement directly before enabling. A 402 response is exposed as `plan_limited` and paused for a day before revalidation; it never becomes an empty result or a permanent silent suppression. Source-wide 429 Retry-After windows survive restart; the source reset epoch is used when Retry-After is absent.

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

The existing PostgreSQL JSON cache and compact reports store only normalized summaries. Restart preserves retained source report and ingestion times; no schema migration or dependency is needed. Old reports without the optional field remain readable. The 2,000-entry cache may evict observations and is not a durable report archive. BE-10 owns historical storage and change semantics; aging out or cache eviction must not produce a resolution event.

## Validation and remaining work

Synthetic fixtures cover exact and subset IPv4 scope, /32, explicitly unsupported IPv6/broad/historical queries, empty/positive/partial results, source times, duplicates, mismatched ranges, pagination/truncation, overflow, 256-address bounds, missing fields, error envelopes, auth/plan/quota errors, quota restart, header secrecy, cancellation, hidden prefixes, cached-only REST/MCP, OpenAPI and PostgreSQL/report restart. They are not evidence of live compatibility.

The unchanged BE-07 base and this branch must pass the same required checks. Review regressions are demonstrated failing before fixes, then rerun with race tests. Container smoke covers local runtime behavior with network collection disabled; it does not establish live account access or permission.

Next external step: obtain an approved account/key and confirm query quota, family/range limits, publication and retention conditions; pilot representative supported scopes before enablement. Revisit the plan/window against actual eligible inventory and BE-02 capacity. For example, the documented Standard allowance of 100 block queries/day would require at least ten days for a cold 1,000-prefix catalogue, before retries. That computed floor is incompatible with complete daily refresh of that catalogue and is not measured throughput or an account-specific entitlement.

Official reference: [AbuseIPDB API v2: block queries, plan limits, rate handling and security](https://docs.abuseipdb.com/). Review date: 2026-11-25. Hosted CI for unpublished commits, authenticated pilot, full source coverage, public reuse rights, stand and production remain unverified.

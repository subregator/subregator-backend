# Source-aware automatic scheduling

[API reference](api.md) · [Capacity report](collection-capacity.md) · [BE-04](https://github.com/subregator/subregator-backend/issues/6)

The single ingestion process runs six bounded queues: prefix overview, RPKI, routing status, registration, RDAP and shared DROP evaluation. Each queue runs at most one job at a time and rotates fairly through eligible public prefixes. The four-slot HTTP limit still applies across all queues. External sources share the configured requests/minute budget; the private IRRd mirror shares HTTP concurrency and source cooldown handling without spending external-source allowance. This does not increase any vendor entitlement or enable distributed ingestion.

## Scheduling rules

- Each metric gets its own next due time from its cached observation expiry. Routing no longer waits for unrelated six-hour registration data; cache hits incur no fixed ten-request delay.
- RPKI waits for usable current prefix-overview evidence and receives that exact dependency instead of fetching it again. Explicit prefix/ASN validation and the four-origin limit remain. Routing-summary evidence is compacted in memory; extra origins retain incomplete-coverage metadata. Public cached metric payloads remain unchanged.
- Generic failures use per-prefix/per-check backoff of 1, 2, 4, 8 and at most 15 minutes. Successful no-data results use the normal check TTL. A source retry deadline can only delay a retry further.
- Disabled, missing-token and inapplicable checks are suppressed rather than retried as failures. Configuration is fixed for a process lifetime; a restart rebuilds the schedule. Cached observations remain readable with external collection disabled.
- Automatic upstream budget waiters are FIFO. Waiting releases the HTTP slot; cancellation removes the waiter. At one request/minute, the first shared DROP evaluation for each family has priority because one feed covers every prefix in that family. Subsequent DROP requests join the same fair budget queue.
- DROP uses one queue so its two family feed objects are not concurrently refreshed. Dataset validation, attribution, pending-save retry and persisted daily attempt reservations remain in force. A shared cached dataset serves many prefixes without additional downloads.
- Catalogue changes are reconciled between completions and about once per second while idle. Removing or withholding a prefix cancels its individual jobs and removes scheduler metadata; later results are discarded. A shared DROP download uses the collector lifetime, so removing one prefix cannot cancel a reserved dataset needed by other prefixes. Requests already sent cannot be recalled. Initially hidden/private/reserved prefixes are never queued or reconstructed.
- Cached REST/MCP reads do not enqueue work, refresh sources or consume upstream budgets. Explicit public lookups share the configured upstream budget. For five minutes after public demand, automatic collection uses at most 75% of each window (rounded up, at least one request), leaving capacity for lookups; the total limit is unchanged. Publication reuses the durable report/cache paths and conservative BGP/RPKI retention rules.

## Source retry windows

HTTP 429 establishes a source retry window from `Retry-After` in seconds or HTTP-date form. Missing or invalid values use one minute. RIPEstat endpoints share their source window; each authoritative RIR RDAP host has an independent window. Only fixed recognized source identifiers are stored; arbitrary URLs and credentials are not journal keys.

Optional metric `retry_at` is the earliest source-allowed retry, not a promised execution time. Dependencies, FIFO queueing and the shared budget can delay work further. Retained stale observations keep their earlier evidence while carrying a later retry deadline.

PostgreSQL `source_limits` stores these small deadlines outside the 50,000-entry observation cache. A shorter deadline cannot replace a later recorded one. Unavailable or invalid stored schedules defer requests rather than bypassing them. A failed deadline write is retried before the same process resumes that source. A crash before an unsuccessful write is recovered can lose the newly received deadline: unsaved state cannot survive restart. Production uses the required PostgreSQL cache; a `Service` constructed without a cache has process-local limits only.

The table is created additively at database initialization; existing offers, history and DROP data are not removed. Older binaries do not enforce `source_limits`, so rollback must preserve outstanding windows by keeping collection disabled or waiting until they expire. The single-writer lease remains required; sharing PostgreSQL does not coordinate independent polling replicas.

## Diagnostics and validation

`/api/v1/network/status` and MCP `network_status` include `scheduler_policy: per_check_ttl`, due/running job counts and per-check due, running and suppressed-prefix counts. The legacy `scheduler_sweep_floor_seconds` remains zero for compatibility and is deprecated: the former fixed pacing floor no longer exists. Zero is not a freshness guarantee. Use observed ages, queue lag, source errors and actual request counts to assess capacity.

Local tests cover slow registration without routing starvation, TTL/backoff/suppression, source windows across restart, independent RIR windows, FIFO grants/cancellation, prefix removal, bounded/incomplete routing evidence, multi-origin RPKI at one request/minute, DROP reservations/priority and real-PostgreSQL cache eviction. External quotas and production freshness targets have not been certified by these fixtures.

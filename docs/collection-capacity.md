# Collection coverage and capacity

[API reference](api.md) · [BE-02](https://github.com/subregator/subregator-backend/issues/4)

Local verification: 2026-11-25, Go 1.27.4 on macOS arm64; PostgreSQL 18.6 in OrbStack for integration tests. External responses in collector tests are local fixtures. These results do not establish production coverage or actual upstream throughput.

## Read collection health

```sh
curl 'http://localhost:8080/api/v1/network/status'
```

MCP exposes the same data through `network_status` with empty arguments. This is an aggregate read, without database or upstream requests. It does not disclose resource IDs or source URLs.

- `eligible_prefixes` counts distinct public published prefixes, shared across listings/providers; private, reserved and withheld prefixes are excluded.
- `due_prefixes` includes due work and prefixes not yet discovered by the worker. `unscheduled_prefixes` identifies the latter. `oldest_due_seconds` is null until an active due time is known; zero next-times suppress disabled jobs rather than creating epoch-aged backlog; no synthetic startup backlog age is invented.
- Each `checks` entry reports independent `collection` and `freshness` counts and nullable `oldest_age_seconds`. Missing map entries mean zero resources in that bucket. These are collection-health counts, not counts of safe subnets. The check names are prefix_overview, rpki, routing_status, registration, rdap and spamhaus_drop. BGP/RPKI coverage uses final offer evidence, including retained observations and BGP freshness bounds on RPKI; last-attempt raw metrics cannot replace that evidence. Without an observation, the latest attempt can establish a configuration/failure state such as `disabled`; an established `not_applicable` result is preserved.
- `upstreams` groups request counts, failures, HTTP 429, HTTP 401/403, HTTP 404 and cumulative duration in milliseconds by a fixed set of source names. Unknown hosts share `other`, so labels cannot grow per resource. Duration covers the HTTP read, not queueing. Failures are transport/status/body failures at that layer; source-specific semantic rejection is reflected in check coverage instead. HTTP 404 counts as no data, not a transport failure. A source with no requests has no entry.
- `budget_denials` counts immediate local request-budget rejection; `budget_waits` and `budget_wait_seconds` count completed/canceled background waits. An in-progress wait is not added until it finishes. Upstream HTTP 429 is counted separately.
- `persistence_failures` counts observed cache read/write failures in the instrumented check paths, including automatic report and DROP writes. It is not an audit of every database operation.
- Counters and coverage samples are process-local, protected for concurrent reads, and reset on restart. Restored automatic summaries can repopulate BGP/RPKI/DROP coverage; the remaining metric coverage is rebuilt when the worker reads their caches. Removed prefixes no longer count; worker cleanup releases their metadata samples. Raw metric payloads are not retained in the coverage map.

## Current scheduler (BE-04)

The per-check TTL scheduler removes fixed per-prefix pacing. `scheduler_policy` is `per_check_ttl`; the compatibility sweep-floor field is deprecated and zero. Due/running jobs and per-check suppressed/due counts describe actual scheduling. See [scheduling rules](scheduling.md) for TTL, FIFO budgets, Retry-After persistence and cancellation.

On local fixture runs, three-prefix/two-origin registration and RPKI coverage populated in **10 ms**, and cached restart restored coverage in **1 ms**, compared with the earlier 2.007 s / 2.001 s below. A blocked registration lookup did not prevent all three prefix-overview requests within the one-second test deadline. These tiny fixture timings demonstrate removal of artificial pacing, not live-source capacity. Production targets remain unverified.

## Reproducible scenarios

```sh
go test ./internal/intelligence -run 'TestCollectionCoverageScenarios|TestCollectionWorkerCoverageAndRestart|TestSlowRegistrationCannotBlockOtherPrefixes' -count=1 -v
```

The scenario matrix uses 1, 100 and 1000 public prefixes with request budgets of 1, 120 and 600/minute. It checks cold-start pending counts, populated registration coverage and conservative pending counts before a restarted worker restores data. The table below preserves the previous scheduler's computed floor, not elapsed network collection times:

| Distinct prefixes | 1 request/min | 120 requests/min | 600 requests/min |
| --- | --- | --- | --- |
| 1 | 600 s | 5 s | 1 s |
| 100 | 60,000 s | 500 s | 100 s |
| 1000 | 600,000 s | 5000 s | 1000 s |

Before BE-04, the worker visited one due prefix per interval, where `interval = max(0.1 seconds, 600 / requests_per_minute seconds)`. Thus `scheduler_sweep_floor_seconds = eligible_prefixes × interval`. The ten-call allowance is existing scheduler pacing, not a measured upstream request count for every prefix. Cache hits, multiple origins, RDAP bootstrap requests, shared DROP downloads, latency, failures and budget waits change actual work. The counter endpoint measures actual requests separately.

The worker test exercises three distinct public prefixes with two origins each, real worker iteration and cached restart at a configured 600/minute budget. On the local run, all three registration and RPKI results populated in **2.007 s**; a fresh process with external access disabled restored them in **2.001 s**, with zero new upstream requests. The first prefix starts immediately, so this cold-start timing is not a steady-state sweep measurement. Three fixed upstream groups were observed. Additional existing tests exercise one-request/minute multi-origin completion, cancellation without leaked slots, shared request limits, deduplication and DROP reservations across restart. These use fixtures rather than spending real source quotas.

## Baseline motivation for BE-04

Under the previous default pacing, a 1000-prefix catalogue had a scheduler floor of 5000 seconds, approximately 83 minutes, before additional upstream waits. A 300-second routing TTL cannot be maintained across that catalogue by the existing pacing. With that former floor alone, at most 60 prefixes fit a five-minute sweep at 120/minute; actual supported capacity can be lower.

Do not increase the budget from this calculation alone: it is shared across sources and is not an entitlement from any vendor. BE-04 now separates this work by check TTL and honors source retry windows without increasing the configured budget. Refresh targets remain provisional until a representative authorized source pilot measures age, errors and queue lag under the intended catalogue size. No production freshness target is certified by these local tests.

## Validation boundaries

Baseline commit `6918046a53317033cccf940029dbd492f08b9b5a` passed `make check` in a separate temporary checkout against the isolated test database. The changed checkout passed `make check build`, including race tests, REST/MCP, real-PostgreSQL integration and existing restart/budget tests.

New regression checks were first run against unchanged implementation code and failed for three concrete reasons: cached disabled/unconfigured/inapplicable checks appeared pending; the observation envelope was absent; collection-status REST returned 404. The fixes make these checks pass. Default sandbox attempts could not write the original Go cache, connect to PostgreSQL or bind the MCP test listener; tests were rerun with a temporary Go cache and approved local access, without weakening them.

Review also identified raw attempt metadata overriding retained/dependency-bounded BGP/RPKI coverage, and direct ASN ranking mislabeled as origin-derived scope. Separate regressions failed on the pre-fix implementation and pass after correction. The previous regression suite passed against a saved pre-review implementation; the fixed checkout passed the full `make check build` again.

BE-04 validation added failing-then-passing regressions for blocked registration, source Retry-After across restart and PostgreSQL cache eviction. Review fixes also cover shared DROP downloads surviving removal of one prefix and queued throttled sources leaving FIFO without spending global quota. The foundation baseline and pre-review regression suite passed separately; the final scheduler passed `make check build` with PostgreSQL and race tests. These changes are local and have not been deployed.


## Catalogue-scale freshness follow-up — 2026-11-27

A production snapshot showed 2,391 eligible prefixes, only 23 fresh BGP and seven fresh routing-status observations, and an oldest due job about nine hours late. The process had issued about 125,000 private-mirror requests and 66,500 RIPEstat requests with a shared 120/minute allowance. The mirror itself had updated all six configured registries that day. These are dated observations, not a post-change result.

Two avoidable pressures are addressed locally: private IRRd queries no longer consume external-source RPM; common mirror metadata is shared for five minutes instead of being fetched per prefix. The PostgreSQL cache bound rises from 2,000 to 50,000 non-DROP rows. A 2,391-prefix working set needs roughly 21,519 rows for eight enabled raw per-prefix metrics plus one compact report each, before explicit lookups and other cached data. This remains an entry bound, not a byte or retention guarantee; monitor table/index sizes. Expired observations remain stale and are never counted as fresh by this change.

There is also a hard capacity limit. BGP overview and routing status alone need at least 4,782 source requests per full sweep: **39.85 minutes at 120/minute**, even with instant responses, no failures and no other work. Adding one RPKI origin request per prefix makes that **59.78 minutes**. During sustained public demand the 75% automatic allowance makes those ideal floors **53.13 and 79.70 minutes**. Unannounced prefixes may need no RPKI request; multiple origins, registry refreshes, retries, source cooldowns and network latency can increase work. Five-minute TTLs cannot be maintained catalogue-wide under that allowance; removing private-mirror contention does not change this arithmetic.

Keep the external quota unchanged until an entitlement and capacity measurement justify increasing it. A practical initial collection objective is a bounded full sweep measured in hours, with five-minute evidence still honestly marked stale after expiry. Before promising a stronger freshness target, measure cold start and steady-state queue age, source requests and errors on the intended catalogue, and choose either an approved higher source budget or a smaller frequently refreshed subset. No source TTL is silently relaxed and no post-deployment improvement is claimed here.

Local regressions cover mirror/external allowance isolation, shared HTTP slots and cancellation, shared metadata timestamps/expiry, a 20,001-row catalogue working set, the 50,000-row eviction bound, and durable DROP/source cooldown reservations. Fixtures do not certify live-source capacity.

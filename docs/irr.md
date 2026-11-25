# IRR consistency

The optional `irr` check compares IRRexplorer route/route6 objects with Subregator's existing RIPE RIS prefix-overview observations. An IRR object is not proof of ownership or universal routing acceptance. IRRexplorer's BGP origins, RPKI-derived route objects, warning messages and aggregate scores are not used as our BGP evidence or a safety result.

## Access and configuration

Collection is **off by default**. `SUBREGATOR_IRR=false` (or `-irr=false`) returns `not_configured`, suppresses background jobs and prevents cached IRR objects being published. Enable `SUBREGATOR_IRR=true` / `-irr=true` only after confirming the operator's request entitlement, public display and cache-retention conditions. This switch does not assert or obtain third-party permission. `SUBREGATOR_NETWORK=false` still prevents upstream collection. No credential, custom URL, new service or dependency is needed. Configuration is set before workers start; runtime reconfiguration is not supported.

The selected fixed endpoint is `https://irrexplorer.nlnog.net/api/prefixes/prefix/{prefix}`, plus `/api/metadata/`. The source's public project documents JSON API use by third-party tools. A numerical hosted-service quota and a grant for public API redistribution/retention were not found in the reviewed project documentation or operator footer. The software license is not a data-use grant. Next external action: confirm those conditions with the operator, Stichting NLNOG (`stichting@nlnog.net`), before enablement. No message has been sent.

## Contract

Cached REST `/api/v1/network?resource=1.1.1.0/24&checks=irr` and MCP `inspect_network` return an additive `irr` explanation. Published offers expose the same result in `checks.irr.irr`. Public requests never fetch or refresh a source. Unsupported IP/ASN resources, IPv4 prefixes shorter than /9, IPv6 prefixes shorter than /29, historical/version parameters and proposed-ASN validation return `not_applicable` when the integration is configured. The source code's broad-prefix guard can otherwise return an empty list; that must not become a false missing-object finding. Proposed-ASN RPKI validation remains a separate check.

The explanation includes:

- Requested prefix, source coverage/completeness, truncation, source metadata URL and capture time.
- Every retained object's `class`, actual `prefix`, `origin`, `registry`, source primary key when supplied, and `relation`: `exact`, `covering` or `contained`. Duplicates and conflicting registrations remain separate objects, including across registries. Raw RPSL/contact text is excluded from storage and public responses.
- Source-reported registry `updated_at` dates, separate from collection time. Their `freshness` uses a conservative local 24-hour ceiling; old dates prevent passing. A last-update date is not proof of mirror health or an object creation date. Unknown/future/missing dates remain unknown and partial. The API does not establish that every world IRR is covered or that every configured mirror is healthy.
- Separately dated `bgp` evidence: status, origins, source URL, expiry and observation scope/completeness. An IRR result cannot outlive its BGP dependency. Filtered, missing, covering-only or stale BGP cannot establish a passing comparison. Changing or reordering origins recomputes the comparison; no new upstream lookup is needed for public reads.
- `matches_bgp` only for exact objects when comparison is supported and complete. A containing or contained object never satisfies an exact-prefix origin. `missing_origins` lists observed origins without a matching exact object.

`status` separates these outcomes:

| Status | Meaning |
| --- | --- |
| `consistent` | All currently observed exact origins have matching exact objects and no extra conflicting exact origins were returned; source dates and collection coverage meet the local checks. This remains source scoped. |
| `conflict` | At least one returned exact object's origin is outside the observed BGP origin set. Conflicting objects are preserved. |
| `missing_objects` | One or more observed exact origins have no matching exact object in the returned source coverage. Covering/contained objects may still be present. |
| `bgp_absent` | A fresh, complete exact-prefix BGP observation explicitly reports not announced. Objects are returned without claiming an origin match. |
| `bgp_unavailable` | No fresh, complete exact BGP observation is available for comparison. This is separate from a source failure. |
| `partial` | Truncated, malformed, insufficiently dated, stale or incomplete source evidence prevents a complete comparison. Retained objects remain inspectable. |

A failed HTTP request, 404, authentication error or invalid/oversized top-level response is `unavailable` at the metric/check level, not `missing_objects`. A successful complete empty array can establish source-scoped missing objects only with sufficient metadata and fresh exact BGP. A metadata failure preserves the route objects with partial coverage. Unknown, stale or partial findings never establish passing results; inspect the parent observation/freshness as well as the explanation. Registry freshness in a stored offer report belongs to that report's normalization time; expiry is still applied on every read.

The metric's `data` is the normalized collector snapshot; the additive `irr` field contains the comparison recalculated for the current BGP evidence. No source RPSL, source BGP assertion or safety score is re-exported.

## Bounds and storage

Each collection uses at most two shared-budget HTTP requests: prefix objects and source metadata. Existing four-slot concurrency, eight-second HTTP timeout, 1 MiB response limit, cancellation, source-wide persisted Retry-After and FIFO automatic budgets apply. No retries, pagination, address scanning, ASN enumeration or set expansion are added. A source failure never causes broad-prefix enumeration.

The local result retains at most 200 objects and 64 registry timestamps; extra or malformed data makes completeness partial. Ordinary source cache TTL is one hour. Partial source coverage retries after one minute, subject to longer Retry-After limits. The existing BGP worker remains independent; IRR collection can complete with `bgp_unavailable` when RIS is down. The default-disabled worker remains suppressed rather than repeatedly trying an unconfigured source. Source-name diagnostics distinguish IRRexplorer from RIPEstat and RDAP.

Existing PostgreSQL JSON cache and compact offer reports persist the normalized evidence. No database migration is required. Old reports without IRR remain readable and gain an optional check after restoration/recollection. The existing 2,000-entry eviction bound remains; this is not durable observation history. BE-10 owns the future archive, changes, retention policy and historical queries. Hidden prefixes are not eligible for collection and do not gain offer checks.

## Dated pilot and validation

Pilot: 2026-11-25, anonymous HTTPS from the local machine, one request per prefix plus one metadata request. Both prefix requests and metadata returned HTTP 200 JSON; no credentials were needed. No numerical rate-limit response headers were observed. These three successes do not establish throughput, ongoing availability or redistribution permission.

| Requested prefix | Captured response coverage | Normalizer result |
| --- | --- | --- |
| `1.1.1.0/24` | Two exact IRR objects: APNIC and RADB, origin 13335. | Both objects retained as exact; source aggregate score ignored. |
| `2001:4860:4860::/48` | One RADB route6 object for containing `2001:4860::/32`, origin 15169. | Preserved as covering; does not satisfy a missing exact /48 object. |

Captured metadata contained registry update dates ranging from the same day to more than a week old. The Go normalizer accepted both captured payloads, retained their scope, and kept the old registry dates stale. This is compatibility evidence for those two captured responses, not full live collector/scheduler validation. Captured raw RPSL/contact payloads are not repository fixtures. Committed fixtures are synthetic and follow the observed response shape.

Tests cover IPv4/IPv6, duplicates/conflicts, exact/covering/contained scope, missing objects, BGP absence/failure/staleness/filtering/origin changes, unknown metadata, disabled/unsupported operation, source errors, quotas, size bounds, cancellation, hidden prefixes, REST/MCP/OpenAPI, PostgreSQL restart, legacy reports and immutable offer reads. Live quotas, full source coverage, public reuse rights, hosted CI for unpublished commits, stand and production remain unverified. The source stays off until the external access gate is resolved.

Official sources: [project/API overview](https://github.com/NLNOG/irrexplorer), [prefix collection](https://github.com/NLNOG/irrexplorer/blob/main/irrexplorer/api/collectors.py), [JSON models](https://github.com/NLNOG/irrexplorer/blob/main/irrexplorer/api/interfaces.py), [scope limits](https://github.com/NLNOG/irrexplorer/blob/main/irrexplorer/settings.py), [operator contact](https://github.com/NLNOG/irrexplorer/blob/main/frontend/src/components/footer.jsx).

# IRR consistency

The optional `irr` check reads the private Subregator IRRd mirror and compares route/route6 objects with independently collected RIPE RIS prefix-overview observations. An IRR object is not proof of ownership or universal routing acceptance. RPKI-derived pseudo-objects, source scores and IRR-supplied BGP assertions are not used as our BGP evidence.

## Access and configuration

Collection stays **off by default**. `SUBREGATOR_IRR=false` / `-irr=false` suppresses jobs and prevents stored IRR evidence being published. Enable it only after confirming the original registries' public-use and retention conditions. The switch does not obtain or assert permission. `SUBREGATOR_NETWORK=false` prevents collection.

`SUBREGATOR_IRRD_URL` selects the server-controlled HTTP(S) GraphQL endpoint, defaulting to `http://subregator-irrd:8000/graphql/` on the private Docker network. Credentials, query strings, fragments and non-GraphQL paths are rejected. The endpoint is never accepted from a public request and never included in stored/public evidence. Configure it before collection starts; runtime reconfiguration is unsupported.

The mirror setup is in [deploy/irrd](../deploy/irrd/README.md). Supported sources are RIPE, RIPE-NONAUTH, ARIN, APNIC, LACNIC and AFRINIC. They are daily exports, not near-real-time observations. RADB and other registries are absent. Raw GraphQL remains private: no public proxy, DNS record or direct mirror MCP server is added.

NLNOG declined collection from its hosted IRRexplorer API and recommended an independent mirror. That collector has been replaced. There is no hosted-service fallback. The metric cache namespace is changed, and old compact reports are rejected, so previous hosted-service evidence cannot be relabelled as data from our mirror.

## Contract

Cached REST `/api/v1/network?resource=1.1.1.0/24&checks=irr` and MCP `inspect_network` return an additive `irr` explanation. Published offers expose the same result in `checks.irr.irr`. Public requests never fetch or refresh a source. Unsupported IP/ASN resources, IPv4 prefixes shorter than /9, IPv6 prefixes shorter than /29, historical/version parameters and proposed-ASN validation return `not_applicable` when the integration is configured. These bounds also keep the mirror query narrow. Proposed-ASN RPKI validation remains a separate check.

The explanation includes:

- Requested prefix, source coverage/completeness, truncation, public mirror provenance URL and metadata capture time.
- Every retained object's `class`, actual `prefix`, `origin`, `registry`, source primary key when supplied, and `relation`: `exact`, `covering` or `contained`. Duplicates and conflicting registrations remain separate objects, including across registries. Raw RPSL/contact text is excluded from storage and public responses.
- Per-registry `updated_at` values from IRRd `rpslDataUpdated`, separate from collection time. `timestamp_kind: mirror_data_updated` identifies the last local mirror data change; it is not an upstream object-modification date or a last-successful-poll timestamp. `url` links to the original registry or export index. Their `freshness` uses a conservative local 24-hour ceiling; old dates prevent passing. A last-update date is not proof of mirror health or an object creation date. Unknown/future/missing dates remain unknown and partial. The API does not establish that every world IRR is covered or that every configured mirror is healthy.
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

Each collection makes at most two GraphQL POST requests to the private mirror: prefix objects and registry metadata. Private mirror requests do not spend the external-source requests/minute allowance. They retain the shared four-slot HTTP concurrency, eight-second timeout, 1 MiB response bound, cancellation and persisted mirror Retry-After window. Common registry metadata is shared in memory for five minutes with concurrent refresh deduplication; its original capture timestamp is preserved. Failed metadata requests are retried on the next collection. GraphQL errors are failures even with HTTP 200; metadata-only failures retain objects with partial coverage. No source errors are interpreted as missing objects.

The object query uses explicit sources, route/route6 classes and all RPKI/scope/preference states to avoid silently suppressing conflicts. `ipAny` retains exact, covering and contained objects. A 201-row query detects the 200-object public bound; excess, malformed rows, unknown sources, invalid primary keys, incomplete metadata and missing class coverage make the result partial. No raw RPSL, contacts or upstream error details are stored or published. All six configured sources must have usable metadata before a comparison can pass.

Ordinary cache TTL is one hour. Partial evidence retries after one minute, subject to longer Retry-After limits. The BGP worker remains independent: IRR may complete with `bgp_unavailable` when RIS is down. Unsupported or unconfigured jobs are suppressed. Source diagnostics identify IRRd independently of other services, including when a custom endpoint is configured.

Existing PostgreSQL caches and compact offer reports persist normalized evidence; no database migration is needed. The shared cache has a 50,000-entry bound, including compact reports and raw metric entries; DROP reservations and source cooldowns remain outside eviction. This is not a historical archive: durable changes, corrections, historical queries and retention require separate work. Hidden prefixes remain ineligible. Public REST/MCP reads never query IRRd or trigger refreshes; unpublished/arbitrary prefixes remain pending without cached observations.

## Publication and validation

The original registry conditions still apply to an independent mirror. In particular, RIPE Database Terms article 4.5 restricts repackaging/redistribution beyond an insubstantial part without permission; APNIC's bulk-access policy requires an agreed operational purpose and an acceptable-use agreement. Permission for a public normalized service must be confirmed separately from technical access to public exports. No messages or agreements are sent automatically. Do not enable public collection based solely on an accessible mirror or a software license.

The deployment on 2026-11-26 loaded 2,871,297 unique route/route6 objects from the six selected sources. IPv4/IPv6 lookups for all six sources and data retention after restart were checked from the application network. Those counts are dated deployment evidence, not a permanent freshness or completeness guarantee.

Synthetic tests cover IPv4/IPv6, exact/covering/contained relationships, duplicates/conflicts, missing objects, malformed/truncated GraphQL data, metadata gaps, stale/future dates, HTTP errors/quotas/cancellation, private-address suppression, old-cache rejection, hidden prefixes, cached REST/MCP/OpenAPI and PostgreSQL restoration. Public publication rights and a full daily mirror-refresh cycle remain separate checks.

Sources: [IRRd GraphQL](https://irrd.readthedocs.io/en/stable/users/queries/graphql/), [IRRd mirroring](https://irrd.readthedocs.io/en/stable/users/mirroring/), [RIPE Database Terms](https://www.ripe.net/manage-ips-and-asns/db/support/documentation/terms/), [APNIC bulk access](https://www.apnic.net/manage-ip/using-whois/bulk-access/), [ARIN IRR](https://www.arin.net/resources/manage/irr/), [LACNIC IRR](https://irr.lacnic.net/), [AFRINIC IRR](https://afrinic.net/irr-guide).

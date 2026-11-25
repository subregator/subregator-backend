# Backend roadmap: subnet checks and history

[Back to README](../README.md)

Planning baseline: 2026-11-25. This roadmap covers backend collectors, storage, REST, OpenAPI and MCP. Frontend implementation is deferred and is not a dependency for completing these tasks. Deliver usable backend responses, documented examples and tests.

This document preserves the planning baseline. The [tracking issue and linked tasks](https://github.com/subregator/subregator-backend/issues/2) are the canonical backlog and current status; the table below is a planning snapshot. Priorities describe order, not dates. Implementation status does not authorize deployment.

## Existing foundation

The current local implementation already provides:

- Provider offer ingestion, normalized prices and conditions, source freshness and publication policies.
- Durable listing events and before/after changes, first/last observations, removal and reappearance tracking.
- Exact public-prefix identities and historical provider associations.
- Automatic prefix overview, routing status, RPKI, registration, RDAP and Spamhaus DROP collection; offers embed BGP, RPKI and blocklist summaries.
- Additional check definitions for routing/registration/allocation/transfer history, ASN data and optional IPinfo Lite. Definitions do not imply automatic collection: public network lookups read cached results, and the automatic worker collects only the basic set.

The bounded network cache is not a durable archive of checks. Existing history can support price history, but does not establish completed sales, ownership or events before tracking began. See the [current API and data reference](api.md) for implemented behavior. This baseline is from the local checkout; production configuration and coverage have not been verified.

## Delivery order

| ID | Priority | Task | Depends on | Status |
| --- | --- | --- | --- | --- |
| BE-01 | P0 | Confirm source access and publication terms | — | Merged in #21–#23; external verification limits remain |
| BE-02 | P0 | Measure coverage and collection capacity | — | Merged in #21–#23; external verification limits remain |
| BE-03 | P0 | Define normalized check results | — | Merged in #21–#23; external verification limits remain |
| BE-04 | P0 | Make scheduling source-aware | BE-01, BE-02 | Merged in #21–#23; external verification limits remain |
| BE-05 | P0 | Normalize RIR, registration and abuse contacts | BE-01, BE-03, BE-04 | Merged in #21–#23; external verification limits remain |
| BE-06 | P0 | Complete BGP and RPKI explanations | BE-03, BE-04 | Implemented locally; delivery pending |
| BE-07 | P0 | Add IRR consistency checks | BE-01, BE-03, BE-04, BE-06 | Implemented locally; source enablement and delivery pending |
| BE-08 | P0 | Add subnet abuse observations | BE-01, BE-03, BE-04 | Implemented locally; pilot verified; public-use terms and delivery pending |
| BE-09 | P0 | Extend blocklist coverage beyond DROP | BE-01, BE-03, BE-04 | Planned |
| BE-10 | P0 | Store durable check observations and changes | BE-01, BE-03 | Planned |
| BE-11 | P1 | Expose current sellers and price history by subnet | BE-03 | Planned |
| BE-12 | P1 | Collect historical network data and expose a timeline | BE-04, BE-05, BE-06, BE-10, BE-11 | Planned |
| BE-13 | P1 | Integrate additional marketplace inventory | BE-01, BE-02, BE-11 | Planned |
| BE-14 | P1 | Add completed-sale market benchmarks | BE-01 | Planned |
| BE-15 | P2 | Add geolocation and usage classification | BE-01, BE-03, BE-04, BE-10 | Planned |
| BE-16 | P2 | Import provider statements and publish reports | BE-01, BE-10, BE-12 | Planned |
| BE-17 | P2 | Relate containing and overlapping offers | BE-11 | Planned |
| BE-18 | Deferred | Investigate country/ISP restrictions | BE-01, BE-03 | Research only |

P0 acceptance: RIR/registration, BGP, RPKI, IRR, blocklist and abuse results are available through REST and MCP with honest coverage and failure states; collection is bounded and observations survive cache eviction. A source that cannot be enabled must remain explicitly unavailable with a recorded blocker, never count as a completed integration or a passing result.

Recommended first implementation slice: BE-01–BE-03, then BE-04–BE-06 and BE-10, then the independent integrations BE-07–BE-09. Build BE-11 from existing catalogue/history while external access is being resolved. Each integration writes durable observations once BE-10 lands.

## P0: minimum checks and reliable collection

### BE-01 — Confirm source access and publication terms

- [ ] Record authentication, quotas, supported families/prefix sizes, historical windows, attribution, refresh limits, caching, retention and public redistribution rights for each enabled or candidate source. Separate operator documentation from permissions actually granted to this service.
- [ ] Cover existing RIPEstat/RIR RDAP, Spamhaus DROP, CAIDA and IPinfo Lite, then AbuseIPDB, IRR and additional blocklist access. For CAIDA, retain the existing attribution/publication-report requirements.
- [ ] Keep credentials outside public results, logs, fixtures and documentation. Record an operational reference to credentials, never their values.
- **Done when:** every source has documented capabilities and restrictions; blocked integrations name the missing agreement, credential or capability. Registry publication policy remains enforced for current and historical data.
- **Next step:** assemble the source matrix from existing configuration and official terms; identify the access needed for a small pilot. Do not send provider messages as part of this planning task.

### BE-02 — Measure coverage and collection capacity

- [ ] Measure distinct eligible prefixes, fresh/stale/pending/failed results per source, observation age, queue lag, upstream calls, latency, quota exhaustion and persistence failures. Keep metric labels bounded; no per-IP labels or secrets.
- [ ] Exercise cold start, steady state and restart with representative local catalogues, including low request budgets and multiple origin ASNs.
- **Done when:** a reproducible report relates catalogue size and upstream quotas to achievable freshness; refresh targets are documented from measurements rather than promised from configured TTLs alone.
- **Next step:** inventory existing operational signals and add only the missing counters or structured summaries.

### BE-03 — Define normalized check results

- [ ] Reuse existing result structures; define additive typed fields for RIR, routing, RPKI, IRR, blocklists and abuse. Preserve existing clients and resource/listing identities.
- [ ] Carry source/link, scope and relationship to the requested network, source timestamp when available, collection time, expiry, freshness, completeness, result and failure reason. Separate lookup success from a source's finding.
- [ ] Distinguish pending, not configured, unsupported/not applicable, unknown/no data, stale, partial and failed. Missing fields or failed calls cannot imply a pass. Document how source states map to the public contract.
- **Done when:** examples and contract tests cover IPv4/IPv6, exact and covering ranges, unavailable sources and partial coverage. There is no invented aggregate safety score.
- **Next step:** map current structures to the required fields before proposing new endpoints or abstractions.

### BE-04 — Make scheduling source-aware

- [ ] Schedule work by source TTL, quota and cost; retain deduplication, fair rotation, bounded concurrency, cancellation, backoff and the single-writer boundary.
- [ ] Keep required attempt reservations across restart where source restrictions require it. Disabled or unsupported checks must not retry forever as transient failures.
- [ ] Do not infer or submit hidden prefixes. Public reads remain cached/local and never trigger upstream calls, arbitrary URL fetches or refresh spending. Do not retain observations longer than source policy permits.
- **Done when:** slow or quota-limited integrations do not starve basic checks; restart, low-budget and multi-origin tests pass; measured freshness targets remain achievable. Scaling to multiple workers is a separate decision, not required here.
- **Next step:** use BE-02 measurements to adjust the existing worker rather than introducing a new scheduler service.

### BE-05 — Normalize RIR, registration and abuse contacts

- [ ] Extract authoritative RIR, covering allocation/assignment, public organization identifier/name, status, dates and RDAP link from existing results. Preserve the distinction between registry holder, announcing ASN and seller.
- [ ] Extract public abuse-role contacts; use an additional contact lookup only when required. Missing or unverified contact information remains explicit.
- **Done when:** fixtures cover all five RIR response shapes, containing ranges, absent contacts and malformed responses; authoritative RDAP bootstrap/URL validation remains intact. Registration is never presented as proof of beneficial ownership or selling authority.
- **Next step:** inspect current registration/RDAP payloads and identify missing normalized fields.

### BE-06 — Complete BGP and RPKI explanations

- [x] Preserve exact-prefix, covering-route, not-announced and unavailable distinctions; include observed origins, collector visibility and observation dates when available.
- [x] Return per-origin RPKI findings, distinguishing invalid ASN, invalid length, not found, mixed and partial coverage. Include covering ROA, authorized ASN and maxLength where the source provides them.
- [x] If assessing a proposed customer ASN later, label it as a separate prefix/ASN validation; do not confuse it with the currently observed origin.
- **Done when:** all-origin and origin-limit/truncation cases remain honest, including origin changes and reordered origins. Not found is not invalid; BGP observation is not a reachability guarantee; current validation is not historical validation.
- **Next step:** expose existing distinctions before collecting extra upstream data.

Implementation: additive typed BGP/RPKI explanations, source-dated RIS visibility, per-origin findings and supplied ROAs; partial successes and four-origin truncation are preserved through cached REST/MCP reads and compact reports. See [routing contract](routing.md). Local validation and delivery evidence are tracked in issue #8. Live-source compatibility and production remain unverified; delivery requires approval.

### BE-07 — Add IRR consistency checks

- [x] Pilot private IRRd access after NLNOG declined hosted collection; retain a separate original-registry publication/retention gate.
- [x] Return route/route6, object origin and registry source; compare with observed BGP origins. Preserve exact/containing relationships, duplicates and conflicting objects across registries.
- **Done when:** missing objects, conflicts, BGP absence, unsupported scope and source failure have separate outcomes; IPv4 and IPv6 fixtures cover these cases. An IRR object is not proof of ownership or universal routing acceptance.
- **Next step:** confirm the original registries' public-use/retention conditions, then approve delivery and enablement of normalized REST/MCP observations.

The private IRRd mirror and normalized collector preserve comparison, cached REST/MCP/OpenAPI and persistence. Six-source IPv4/IPv6 mirror access is verified. Public redistribution/retention terms remain unconfirmed; collection is off by default. See [IRR contract](irr.md) and issue #9 for evidence and the enablement gate.

### BE-08 — Add subnet abuse observations

- [x] Pilot AbuseIPDB `check-block`; return reported-IP count, report count, latest report, query window and source findings. Retrieve per-IP categories/details only where supported and needed, using bounded work.
- [x] Treat prefix-size/time limits, pagination, incomplete responses and IPv6 limitations explicitly. Do not enumerate IPv6 space or silently sample a subnet and claim full coverage.
- [x] Preserve source report time and ingestion time. Zero reports in a window is not a clean bill of health; reports aging out do not establish resolution. Avoid automatically republishing raw complaint logs or personal data.
- **Done when:** tests cover quota/auth failures, size limits, empty results, truncation, bounded detail collection and missing timestamps. Past reports are not attributed to a new tenant without evidence.
- **Next step:** choose a plan/window from the pilot and BE-02 capacity results; confirm retention and public-display rights.

Local normalized collection, cached REST/MCP/OpenAPI, offer reports, configuration and persistence are implemented. The source is off pending public use/retention conditions. The authenticated pilot verified 100 block queries/day and bounded IPv4/IPv6 responses. Current local scope is IPv4 /24–/31 and IPv6 /120–/127, 30 days, one request and no complaint-detail calls; single hosts and larger ranges are not queried. See [abuse contract](abuse.md) and issue #10 for the open acceptance criterion and evidence.

### BE-09 — Extend blocklist coverage beyond DROP

- [ ] Retain complete DROP IPv4/IPv6 overlap checks, dataset validation, attribution, source dates and daily attempt limits.
- [ ] Pilot licensed Spamhaus SBL/XBL/PBL through agreed access, or a suitable alternative. Return separate list findings, reasons, affected ranges/IPs and coverage; record the limitations of each list.
- [ ] Separate positive, negative, DNS/API error, rate limit and access denial. PBL describes mail policy; it is not an abuse conviction. A sampled IP lookup cannot establish whole-subnet status.
- **Done when:** tests cover containing and contained entries, partial coverage, multiple return codes and source errors. Additional lists retain independent findings and do not turn DROP absence into universal reputation approval.
- **Next step:** confirm product access/display terms and a feasible range-query or bounded IP-query strategy.

### BE-10 — Store durable check observations and changes

- [ ] Add minimal PostgreSQL storage alongside existing history: source/check, resource/scope, source and ingestion times, completeness, normalized evidence and stable event identity. Keep the latest cache disposable.
- [ ] Record BGP origin changes, RPKI transitions, registry changes and blocklist presence/absence observations. Preserve abuse-report identities when available; deduplicate repeat collection without erasing distinct source reports.
- [ ] Emit delisting only after a successful complete comparable check establishes absence. TTL expiry, cache eviction, malformed data, source failure and a rolling abuse window cannot establish delisting or resolution.
- [ ] Track observation gaps and first/last seen bounds; never invent an exact event date between polls. Define retention, storage estimates, migration and backup/restore behavior under source terms. Do not delete existing history as an incidental cleanup.
- **Done when:** real-PostgreSQL tests cover restart, eviction, duplicate/replayed observations, ordering, interrupted persistence, gaps and failure-to-success recovery. Current and historical publication policies remain consistent.
- **Next step:** define the smallest migration and event identity needed by the first collector; reuse current persistence patterns.

## P1: market and network history

### BE-11 — Expose current sellers and price history by subnet

- [ ] Reuse exact canonical public-prefix identities and existing listing before/after events. Return current observed offers separately from historical provider associations, with availability and freshness.
- [ ] Provide comparable price history by provider, listing, model, currency and billing term. Preserve setup fees, deposits, taxes, conditional charges, minimum term and unknown amounts. Derive first-period/renewal totals only when inputs permit it; do not invent exchange rates.
- [ ] Keep source failures distinct from complete empty inventories; disappearance is not a sale. Changed listing IDs, changed resources and reappearances must remain traceable without exposing hidden CIDRs.
- **Done when:** REST/MCP examples show multiple offers for one exact subnet and a reproducible price series with tracking start and gaps. No conclusion about ownership, fraud or a completed transfer is inferred from multiple sellers.
- **Next step:** build queries/projections over existing offers and history before adding storage or new routes.

### BE-12 — Collect historical network data and expose a timeline

- [ ] Enable bounded background collection of existing routing, allocation, transfer and registration-history checks; define supported windows and pagination/truncation behavior. Historical RIPE Database coverage is not worldwide registry coverage.
- [ ] Combine listing/price events, BGP/RPKI/registration observations, blocklist events and abuse reports in a paginated resource timeline with source, scope, source time, ingestion time and coverage boundaries.
- [ ] Distinguish imported historical records from local observations; a containing-block transfer is not automatically a transfer of every child offer. Preserve corrections and uncertainty rather than inventing ownership chains.
- **Done when:** pagination and same-time ordering are deterministic, each event links to evidence, tracking/import boundaries and gaps are visible, and imports are repeatable without duplication. Include a read-only REST/MCP example usable without a frontend.
- **Next step:** define timeline event mappings using BE-10 and current listing history; enable only the historical collectors required by the first slice.

### BE-13 — Integrate additional marketplace inventory

- [ ] Prioritize IPXO's documented authenticated inventory search after publication rights are agreed. Reuse the existing provider/feed contract and policy gate; keep ordering, cart and checkout outside scope.
- [ ] Recheck the existing provider registry for feeds that are actually available, including interested providers awaiting endpoints. A registry entry or advertised API is not a connected inventory.
- [ ] Preserve pagination completeness, stable listing IDs, source timestamps, reserved/waitlisted/upcoming states, prices/fees and prefix visibility. Respect per-provider attempt intervals across restarts.
- **Done when:** each enabled adapter has source-specific fixtures and a small authorized live pilot; incomplete feeds cannot erase stock; terms and operational configuration are documented without credentials.
- **Next step:** resolve IPXO access and inventory redistribution conditions; retain other candidates as blocked until a usable source exists.

### BE-14 — Add completed-sale market benchmarks

- [ ] Investigate a supported IPv4.Global data/feed access path and reuse rights. Preserve transaction date, RIR, block size, price, currency and disclosed bundle/fee limitations.
- [ ] Keep asking prices, lease prices and completed-sale benchmarks separate. Aggregate only comparable observations; expose sample counts, period, provenance and missing data.
- **Done when:** anonymous transactions cannot be attached to an exact CIDR without an explicit identifier; sparse or bundled observations do not produce misleading valuations. Document the actual supported ingestion method before implementation.
- **Next step:** verify access and data granularity; do not assume that a public ticker implies an unrestricted API.

## P2: additional context and reports

### BE-15 — Add geolocation and usage classification

- [ ] Compare provider geography, registry country, geofeed and independent GeoIP observations with separate provenance. An RIR or seller country does not establish physical location.
- [ ] Evaluate IPinfo privacy tiers for VPN/proxy/Tor/relay/hosting flags; Lite does not supply the full privacy dataset. Preserve source timestamp, scope and supported family; IP findings cannot silently become subnet-wide findings.
- **Done when:** disagreement is visible rather than automatically a failure; paid/unconfigured/partial results remain explicit and historical changes retain evidence. Classifications are not equivalent to abuse or guaranteed service restrictions.
- **Next step:** choose one source and bounded lookup strategy from a representative pilot, avoiding redundant providers until needed.

### BE-16 — Import provider statements and publish reports

- [ ] Start with read-only structured statements from agreed feeds: provider identity, subnet/listing scope, publication/collection times, statement type, text, evidence link and revision/correction identity.
- [ ] Keep claims such as “delisting requested,” “geolocation updated,” “LOA available,” “rDNS supported,” or permitted-use restrictions separate from independently verified outcomes. Apply publication policy and safe handling of external text/links.
- [ ] Provide a machine-readable report/export containing observations, coverage, dates and evidence. Reuse REST/MCP data; a PDF generator is not required for the first version.
- **Done when:** statement origin is attributable, revisions remain traceable, imported text cannot inject markup or expose private abuse logs, and exported reports preserve unknown/stale states. Provider credentials and private documents stay private.
- **Next step:** define a minimal feed extension and an example report. Public write endpoints and user comments wait for separate authorization, authentication, moderation, spam protection and dispute handling.

### BE-17 — Relate containing and overlapping offers

- [ ] Add explicitly typed exact/parent/child/overlap relationships for public prefixes without merging distinct listings or inventing common ownership. Bound queries, pagination and address-count arithmetic for IPv6.
- **Done when:** a /22 offer and its /24 child remain distinct; price comparisons disclose scope; hidden prefixes cannot be recovered through relationships, counts or history.
- **Next step:** confirm that exact-prefix comparison from BE-11 is useful before expanding matching.

### BE-18 — Investigate country/ISP restrictions

- [ ] Distinguish published restriction records, source reputation findings and measured accessibility. Evaluate OONI as contextual evidence for specific targets, not a blacklist of arbitrary CIDRs.
- [ ] Any later measurement must retain destination, port, protocol/SNI, vantage country/ASN, time and method. A timeout alone does not prove censorship; a test from another source IP does not prove a service accepts traffic from the offered subnet.
- **Done when:** a research note identifies usable evidence, coverage, permissions and limits; no universal “unblocked” status is proposed without appropriate measurements. Implementation requires a separately scoped decision.
- **Next step:** keep this outside the minimum backend release. Arbitrary probes, subnet scanning and active IPv6 enumeration are deferred.

## Completion checklist for every implementation task

- [ ] Update collector, normalized models, persistence and queries wherever affected; reuse existing components and avoid unnecessary dependencies or services.
- [ ] Update REST/OpenAPI, MCP tools, fixtures, examples, source attribution and configuration documentation together. Prefer additive contracts and existing read operations; document a migration for any required incompatibility.
- [ ] Test relevant IPv4/IPv6, hidden-prefix, partial/truncated-response, quota/auth/error, stale-data and restart cases. Unsupported cases must be documented rather than represented as passing.
- [ ] Use real PostgreSQL for storage/migration tests. Run the project's required checks and preserve regression guarantees; for fixes, show the regression fails before the fix and rerun relevant checks against both versions.
- [ ] Verify bounded upstream work, request budgets, response sizes, timeouts and cancellation. Secrets and external error payloads must not leak into public responses or logs.
- [ ] Update this roadmap with status, evidence, issue/PR links, blockers and next step. Test results establish only the environment actually tested; stand/production validation remains a separate approval-gated delivery step.

Frontend screens, accounts, checkout, purchase automation, public user comments, notifications/watchlists and distributed ingestion are outside this backend roadmap's implementation scope. Backend API/MCP usability is a deliverable in its own right.

## Source references

Reviewed during planning on 2026-11-25. Recheck capability and terms before enabling an integration; this list does not establish permission or current production behavior.

| Source | Relevant documentation | Planning use |
| --- | --- | --- |
| RIPEstat | [API](https://stat.ripe.net/docs/data-api/ripestat-data-api), [routing history](https://stat.ripe.net/docs/data-api/api-endpoints/routing-history), [abuse contacts](https://stat.ripe.net/docs/data-api/api-endpoints/abuse-contact-finder), [commercial-use notice](https://stat.ripe.net/docs/getting-started/what-is-ripestat) | Existing checks, historical coverage, contact lookup and access review |
| RIR RDAP | [IANA bootstrap](https://data.iana.org/rdap/) | Authoritative discovery; retain trusted endpoint validation |
| Spamhaus | [DROP requirements](https://www.spamhaus.org/faqs/do-not-route-or-peer-drop/), [datasets](https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/030-datasets.html), [DQS responses](https://docs.spamhaus.com/datasets/docs/source/70-access-methods/data-query-service/040-dqs-queries.html) | Separate lists, attribution, refresh limits and error semantics |
| AbuseIPDB | [API v2](https://docs.abuseipdb.com/) | CIDR abuse queries, report windows, plan limits and per-IP details |
| IRRd | [GraphQL](https://irrd.readthedocs.io/en/stable/users/queries/graphql/) | Private route/route6 mirror and independent RIS consistency; original-registry public-use conditions remain separate |
| IPXO | [Marketplace API example](https://developer.ipxo.com/api-example), [reputation history example](https://www.ipxo.com/kb/ip-management/ip-management-ip-reputation-feature/) | Inventory integration and competitor reference; access/redistribution not yet confirmed |
| IPv4.Global | [Completed-transaction ticker](https://www.ipv4.global/news/chrome-extension/) | Anonymous market benchmarks; supported ingestion/reuse still need confirmation |
| IPinfo | [Privacy options](https://ipinfo.io/developers/privacy-standard-api) | Optional paid privacy/usage context |
| CAIDA | [ASRank](https://catalog.caida.org/dataset/as_rank), [Public AUA](https://www.caida.org/about/legal/aua/public_aua/) | Existing topology data and attribution/publication obligations |
| OONI | [Explorer](https://explorer.ooni.org/) | Deferred research on target- and network-specific censorship evidence |

No new source was enabled while writing this roadmap. Authenticated pilots, current production coverage, contractual approvals and frontend behavior remain unverified.

### BE-09 local adapter and outstanding pilot — 2026-11-25

The optional Spamhaus HTTPS ZEN adapter adds independent SBL/XBL/PBL findings, explicit queried-IP scope, partial prefix sampling, source access/errors/quota states and cached REST/MCP/offer contracts. DROP remains a separate complete overlap dataset with its existing daily attempt reservation; exact duplicate source records are rejected. PostgreSQL JSON persistence, configuration and documentation are updated together without a dependency or migration.

Licensed product access, quota and public-display/retention rights are unconfirmed. The authenticated pilot acceptance criterion in #11 remains open; the source defaults off. Whole-subnet SBL/XBL/PBL coverage is not claimed. SSLBL's probed IP CSV was deprecated and was not integrated. See [blocklist contract](blocklists.md). BE-10 remains the next implementation item after this local slice, with frontend deferred and delivery approval still required.

### BE-11 and BE-17 local implementation — 2026-11-25

Implemented independently from the current merged main `e1963cb` on `feat/subnet-market-history`; this branch does not require the unpublished BE-10 archive. BE-11 (#13) exposes current observed sellers separately from historical exact-prefix provider associations, listing before/after price projections and complete/failed provider polls. BE-17 (#19) adds explicit exact/parent/child filtering and overlap union for current offers, without merging listings or scaling parent/child prices. Historical streams always remain exact-prefix. Source disclosure rules, Peaktera expiry/private history, quote terms, unknowns and attribution are preserved. See [market contract and synthetic examples](subnet-market.md).

REST `/api/v1/market` and MCP `subnet_market` make no upstream requests. Existing catalogue/history storage is reused with one additive polls index, without a schema-version change or data migration. No source, gate or external collection permission is changed. Integer quoted totals include initial setup/deposit and recurring fees only when all relevant inputs permit it; they do not invent tax, FX, conditional charges, minimum-commitment totals or missing fees.

Local `make check build` with race and PostgreSQL 18.6 passed on unchanged main, pre-review-fix `27ecfd0` and corrected implementation `43710b4`. Synthetic tests cover multiple sellers, filtered quote series, fees/unknowns/precision, failures versus empty imports, changed/reappeared/moved listings, tracking bounds, independent cursors, restart, v4/v6 including /0 counts, hidden/pending policies, Peaktera boundaries and REST/MCP parity. OpenAPI regressions were shown failing before correction and passing after: closed-base schema extension and calculated amounts above the source-price limit. The existing schema validator module is reused at its existing version; no dependency version was added or upgraded. Follow-up source review found no regression and ran the contract tests; its full API run was blocked by loopback restrictions, so the full suite was verified independently with localhost access.

Final local container smoke on `43710b4` passed: non-root/read-only runtime, PostgreSQL, market REST/MCP, admission limits, history-preserving restart and image healthcheck. Fixtures are synthetic; no live-provider, hosted-CI or production result is implied. Both issues are implementation-complete locally and remain open pending explicit push/PR/merge approval and hosted verification. No branch was pushed, no release/deploy occurred, and original dirty checkouts/worktrees remain preserved.

### BE-10 local archive implementation — 2026-11-25

Implemented on a clean branch from `e1963cb` (after Peaktera publication compliance). Additive PostgreSQL schema v2 stores normalized check observations, independent of disposable caches, with immutable identity, source/attempt/ingestion times, actual scope, gaps and conservative change bounds. BGP origin changes, per-origin RPKI transitions, scoped registry changes and DROP presence/absence use existing collectors. REST `/api/v1/network/history` and MCP `network_history` remain cached-only, enforce current public-prefix policy and filter every row by the separate history approval allowlist. See [archive contract and operations](observation-history.md).

`SUBREGATOR_HISTORY_CHECKS` is empty by default: archival/public-history rights remain unconfirmed even for existing RIPEstat/RDAP/DROP sources. IRR, AbuseIPDB and ZEN histories are unsupported and rejected; their collection gates remain off. Stable individual abuse-report identities cannot be retained from the currently available summary-only adapter. Finite-duration retention is unsupported; do not enable a source whose agreement requires it. No existing history is deleted or backfilled from cache.

Local evidence: `make check build` with race and PostgreSQL 18.6 passed on the unchanged base and implementation. Real-database synthetic tests cover migration v1→v2 without changing legacy state, restart, actual cache eviction, replay/deduplication, ordering/conflicts, atomic interrupted persistence, expiry, gaps, recovery, publication policies and REST/MCP parity. Review regressions fail before their fixes and pass afterward: registry ordering, replayed failures and comparison with older stored states. No live provider fixture or authenticated pilot was repeated. The existing writer-lease test failed once during a full run, then passed; 30 unchanged-main repetitions passed, so the transient cause remains unconfirmed and that unrelated test is unchanged.

Delivery remains local: no push, PR, merge, release, hosted CI or deployment is claimed. Source rights, production migration/capacity, backup/restore verification and live operation remain external gates. Next: obtain delivery approval and source-specific archival/publication terms before enabling history in a deployed runtime.

Final local validation: the final source review reported no findings in the correction diff; its PostgreSQL checks were skipped by the review environment. The full suite with PostgreSQL and race was run independently and passed after the final correction. Container smoke on implementation commit `ae87b45` passed: non-root/read-only runtime, default-off REST/MCP archive, request admission limits, restart and image healthcheck. These results are local synthetic evidence only.

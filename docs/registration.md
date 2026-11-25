# Current registration and abuse contacts

[API reference](api.md) · [BE-05](https://github.com/subregator/subregator-backend/issues/7)

The `rdap` and `registration` network metrics expose an additive `registration` object through cached REST `GET /api/v1/network` and MCP `inspect_network`. Existing raw `data` and source notices remain available. Offer summaries still contain BGP, RPKI and DROP only. Public reads perform no upstream lookup; older raw cache entries acquire their normalized fields locally when read.

## Registry evidence

`rir` identifies the authoritative RIR from the trusted RDAP service, or a single recognized WHOIS authority. Unknown or multiple authorities do not become an invented RIR. `records` include public handles, network names, allocation/assignment type, statuses, country, published dates, source URL and actual IP/ASN range. A network label is separate from an entity's organization name. Only direct RDAP `registrant` entities describe the network registrant; nested registrant roles are not promoted to that relationship. WHOIS organization references remain distinct; linked entities are not fetched or joined into inferred owners.

Each range has `relation`: `exact`, `covering`, `contained` or `overlap`. RDAP IP lookup returns the record containing the requested IP or the first address of a prefix; it does not enumerate all registrations within a prefix. Contained or overlapping records mark completeness partial. Unrelated, reversed, missing or wrong-family RDAP ranges are rejected. `completeness` describes this source projection, not worldwide registry coverage. Optional malformed or bounded-out fields add issue codes and mark it partial. Unrecognized WHOIS record shapes remain unknown.

`observed_at` remains collection time. Published event dates are preserved as RFC3339 timestamps or calendar dates. Only a genuine root record `last changed` timestamp supplies `source_updated_at`; calendar dates do not acquire an invented time. A registry record is not proof of beneficial ownership, selling authority or the identity of an announcing ASN.

## Abuse contacts

Only explicit RDAP `abuse` entities and WHOIS `abuse-mailbox` fields become abuse contacts. Technical or administrative emails are not substituted. Each contact carries its source, source URL and resource scope. Syntax validation does not establish deliverability or ownership: `verification` is always `not_verified`.

When a fresh RDAP lookup has no usable abuse contact, the background collector makes at most one RIPEstat abuse-contact-finder lookup. It shares the existing request budget, concurrency, timeout, response-size and source Retry-After limits. Partial-prefix RDAP results use the first IP for this lookup, and contacts retain that narrower scope. Reported RIR/resource mismatches are rejected. No entity-reference crawling, DNS/SMTP probes or contact messages are performed.

`abuse_status` is `published_unverified`, `not_published` or `unavailable`. Lookup failure preserves valid primary registration and marks the projection partial. No returned contact does not prove no abuse department exists. Cached reads never retry this lookup. Collection uses the existing six-hour registration/RDAP TTL and bounded disposable cache; this is not a durable ownership or abuse-history archive.

Projection limits are 32 records, registrants, statuses, events and contacts; nested RDAP traversal is capped at 128 entities and eight levels, jCards/WHOIS records at 128 properties, and normalized text at 512 bytes. Upstream responses retain the existing 1 MiB limit. Truncation is explicit through partial completeness and issue codes.

## Verification and source scope

Synthetic fixtures exercise all five RIR service identities, scalar/structured organization names, nested contacts, missing contacts, malformed and unrelated ranges, IPv4/IPv6 and ASN coverage, fallback failure, and legacy cache projection. PostgreSQL-backed REST/MCP tests validate the OpenAPI contract. These checks do not establish current live RIR payload compatibility or permission for bulk archival/public redistribution; see the [source inventory](source-access.md).

References: [RDAP response format](https://www.rfc-editor.org/rfc/rfc9083.html), [jCard](https://www.rfc-editor.org/rfc/rfc7095.html), [RIPEstat WHOIS](https://stat.ripe.net/docs/data-api/api-endpoints/whois), [RIPEstat abuse contacts](https://stat.ripe.net/docs/data-api/api-endpoints/abuse-contact-finder).

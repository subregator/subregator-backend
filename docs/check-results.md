# Network observation contract

[API reference](api.md) · [BE-03](https://github.com/subregator/subregator-backend/issues/5)

Every network metric and embedded offer check now includes an additive `observation` envelope. Existing `status`, `data`, timestamps, source links, reasons and finding fields remain available. REST and MCP serialize the same structures. Cached observations from earlier versions acquire the envelope when read; no database migration is required.

## Collection state and findings

`observation.collection_status` describes evidence collection, independently of the existing finding:

| State | Meaning |
| --- | --- |
| `pending` | No observation is currently available; collection may still be queued |
| `succeeded` | A timestamped source observation exists; this does not mean the finding passes |
| `failed` | Collection was unavailable or invalid |
| `disabled` | External collection is switched off and no usable cached result was selected |
| `not_configured` | A required optional credential is absent |
| `not_applicable` | The check does not support the requested resource kind |
| `no_data` | The source returned no observation in its scope |
| `rate_limited` | A source quota or the shared local request budget prevented collection |
| `unknown` | No reliable collection state can be established |

Examples: legacy RPKI `invalid` and DROP `listed` can both have collection state `succeeded`. Their findings remain adverse. Retained observations can also have collection state `succeeded` with freshness `stale`; the failed refresh does not erase their earlier evidence. The envelope does not claim to be a full last-attempt audit log.

`freshness` is `fresh`, `stale` or `unknown`. It is recalculated at read time from the observation and expiry dates; retained stale responses remain stale even when a retry-cache expiry lies in the future. Missing, future or inconsistent timestamps cannot establish freshness. `observed_at` is collection time. Optional `source_updated_at` is the source's own date and is not synthesized from collection time.

`completeness` is `complete`, `partial` or `unknown`, always bounded to the named source and scope. A successful HTTP request or syntactically valid JSON does not by itself establish completeness. Prefix-overview filtering metadata can establish source-result completeness; RPKI offer summaries establish complete coverage only when every observed origin was validated. An invalid origin can be detected in an otherwise incomplete result, so `invalid` alone does not establish completeness. A validated complete DROP dataset establishes coverage of DROP only, not all reputation lists. Other unnormalized payloads conservatively retain unknown completeness.

## Typed scope

`observation.scope` carries:

- `requested`: canonical requested IP, prefix or ASN; `kind`: `ip`, `prefix` or `asn`.
- Optional `resource`: the actual source-returned resource where identifiable.
- `relation`: `exact`, `covering`, `contained`, `overlap`, `origin_asns` or `unknown`. Unknown is not automatically exact. A covering BGP result is not an exact-prefix announcement.
- Optional `asn`, `start_time`, `end_time`, `version`: validated query qualifiers. Cached variants do not lose their requested window or ASN context.

`failure_reason`, when present, contains a sanitized collection explanation; no credential or raw upstream error body is included. Source and source URL remain in the existing outer result. Missing source-specific fields remain absent/unknown, never false or zero by default.

| Check family | Existing finding/payload | Scope and normalization boundary |
| --- | --- | --- |
| Registration / RIR / RDAP | Existing `data` and notices plus typed `registration` records and abuse contacts | [Registration contract](registration.md): actual range, explicit registrant/reference roles, published dates and unverified contacts; registry holder, seller and origin remain separate |
| BGP | Offer finding distinguishes announced, covering route and not announced; metric retains collector data | Scope identifies exact/covering resource when available; richer collector explanations are BE-06 |
| RPKI | Existing per-origin metric data and offer valid/invalid/not-found/mixed/partial findings | Explicit ASN qualifier is retained; ROA details and invalid-reason expansion are BE-06 |
| IRR | No adapter enabled by this contract | BE-07 must provide route/route6, origin and registry evidence through the same envelope |
| Blocklists | DROP matches include range/reference and source attribution | Overlap scope and complete validated dataset; additional lists are BE-09 |
| Abuse | No adapter enabled by this contract | BE-08 must preserve report window, affected-IP counts, report dates and bounded detail coverage |

This foundation defines and implements common typed evidence metadata. It does not preimplement the source-specific integrations assigned to BE-05–BE-09 or turn a check definition into a collector. `/api/v1/network/checks` and MCP `network_checks` expose `automatic` for each defined metric; DROP remains a separate automatic offer check.

## Examples

An IPv4 registration lookup with no cached observation:

```json
{
  "collection_status": "pending",
  "freshness": "unknown",
  "completeness": "unknown",
  "scope": {"requested": "1.1.1.0/24", "kind": "prefix", "relation": "unknown"}
}
```

A successful IPv6 BGP source result can describe a covering prefix:

```json
{
  "collection_status": "succeeded",
  "freshness": "fresh",
  "completeness": "complete",
  "scope": {"requested": "2001:4860:4860::/48", "kind": "prefix", "resource": "2001:4860::/32", "relation": "covering"}
}
```

Completeness in the second example describes an unfiltered source result, not global BGP visibility or packet reachability. A source failure, missing credential, unknown coverage or old observation must never become a safety verdict.

See [durable observation history](observation-history.md) for the separate default-off retention/publication allowlist, source restrictions, conservative change bounds and PostgreSQL migration.

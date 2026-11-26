# Network evidence API

Use `GET /api/v1/network/lookup?resource=163.5.251.0%2F24&checks=all` to collect every available check. `GET /api/v1/network` reads existing observations; MCP offers `lookup_network` and `inspect_network` with the same inputs. Capabilities at `/api/v1/network/checks` list applicable kinds, TTLs, source names and automatic collection. This branch adds topology and measurement checks to the current registration, IRR, abuse and blocklist implementation.

Every report can be partial. Read each metric's `status`, `observation.collection_status`, `observation.freshness`, `observation.completeness`, timestamps, source URL, coverage and `data`. Unsupported, pending and unconfigured checks remain visible. Unknown does not mean passing.

| Check | Information | Coverage |
|---|---|---|
| `prefix_overview`, `routing_status`, `looking_glass` | Origins, visibility, collector paths, first/last observations | Public BGP collector views; no packet-delivery guarantee |
| `rpki`, `irr` | ROA validation and registry route objects compared with BGP | Origin authorization and registry consistency, not ownership |
| `registration`, `rdap`, history checks | Registered ranges, organizations, maintainers, abuse contacts, registry events | Registry statements and published events, not private title or transfer contracts |
| `asn_relationships`, `asn_rank`, `asn_neighbours` | Inferred upstream/customer/peer relationships, cone rank, observed adjacency | CAIDA classifications and RIS left/right/uncertain positions remain distinct; 500-link topology limit is explicit |
| `announced_prefixes` | IPv4/IPv6 announcements and timelines | Source two-week default window, at most four origin ASNs |
| `geolocation` | Country, city, coordinates, resource ranges and source dataset time | GeoLite2 estimate; city can be absent, coordinates do not verify a physical server location |
| `dns_blocklists` | Every returned list with operator, URL, result and source query time | Current RIPEstat list catalogue; no claim to cover every blocklist on the internet |
| `spamhaus_zen` | Licensed SBL/XBL/PBL HTTPS observations | Configured product/key required; source-specific IP sample for prefix requests |
| `abuse` | AbuseIPDB source reports in its documented window | Existing account/key and supported scope required; no source reports does not prove no abuse |
| `ping` | Packet counts, loss, RTT statistics and raw results per probe | Three requested Globalping probes from Europe, North America and Asia; actual probe country/ASN returned |
| `traceroute` | Hops, per-hop RTT, raw output and probe locations | Same selected address; filtered ICMP or missing hops are inconclusive |
| `throughput` | Bytes, body-transfer seconds, Mbps, sample limits and backend vantage | Explicit HTTP test endpoint; measured goodput, not subnet/ASN/link capacity |

Spamhaus DROP continues to cover complete feed overlap in the offer `checks.blocklist` result. PBL describes mail-sending policy; it is not an abuse conviction. Licensed sources retain their existing configuration and access/error statuses.

## Active measurements

For a prefix, `address` selects the public IP to measure and must be inside that prefix. The default is its first usable address. A measurement of one address never establishes availability of every host. ASN requests do not silently choose a host: query a specific address or prefix.

```sh
curl 'http://localhost:8080/api/v1/network/lookup?resource=163.5.251.0%2F24&address=163.5.251.1&checks=geolocation,ping,traceroute'
```

Globalping measurement IDs are saved before result retrieval. In-progress jobs return `pending` with an ID and public measurement link; retry after 15 seconds to resume the same job. The source's free quota and Retry-After window apply, along with the backend request budget and inspection limits. Measurement targets and results are public. Completed collection does not mean successful delivery: a finished ping with 100% loss remains visible as such.

## Whole-prefix DNSBL collection

IPv4 `/24` or longer and IPv6 `/120` or longer contain at most 256 addresses. The API returns an entry for every address and collects at most eight fresh address lookups per call, sharing individual-IP cache entries across requests. `processed_addresses` counts addresses with stored source responses, `completed_addresses` counts fully completed addresses, and `total_addresses` gives the requested size. Local budget denials do not count as source responses. Each list's status shows the remaining gaps. Retry after 15 seconds while results are partial. A completed address requires all source-named lists to return `listed` or `notlisted` with usable timestamps. Failed, unknown, unsupported, rate-limited and pending lists remain incomplete. Source failures may prevent completion; they do not become negative results. Larger prefixes return `not_applicable` rather than launching an unbounded scan.

```sh
curl 'http://localhost:8080/api/v1/network/lookup?resource=163.5.251.0%2F24&checks=dns_blocklists'
```

## Throughput

Supply an operator-provided public test file with `test_url`. The URL must use HTTP(S), an IP-literal hostname inside the requested resource and port 80 or 443; credentials, queries, fragments and redirects are refused. IPv6 URL hosts use brackets. DNS names are intentionally unsupported so the target cannot be rebound outside the requested range. TLS verification remains enabled.

```sh
curl --get 'http://localhost:8080/api/v1/network/lookup' \
  --data-urlencode 'resource=163.5.251.0/24' \
  --data-urlencode 'checks=throughput' \
  --data-urlencode 'test_url=http://163.5.251.1/test.bin'
```

The example requires an actual test file at that URL; the API does not install one. Downloads stop at 8 MiB or eight seconds. The result measures body goodput from the backend, including that vantage's own connectivity. Small or interrupted samples are partial. Without a test endpoint, the check is `not_configured` and no speed is invented. End-to-end link-capacity measurement requires cooperating endpoints and cannot be derived from BGP or ping.

## Evidence limits

The API exposes public registry data, inferred topology, measured paths and source-specific security observations. Commercial transit contracts, legal title and verified physical installation are not public protocol facts. They require operator documentation or an independently verified on-site source; no result here certifies them. Database geolocation and probe location remain separate fields.

Sources: [Globalping API](https://api.globalping.io/v1/spec.yaml), [RIPEstat DNS Blocklists](https://stat.ripe.net/docs/data-api/api-endpoints/dns-blocklists), [RIPEstat GeoLite2](https://stat.ripe.net/docs/data-api/api-endpoints/maxmind-geo-lite), [CAIDA relationships](https://www.caida.org/catalog/datasets/as-relationships/).

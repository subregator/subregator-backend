# Subregator Backend

Read-only IP resource comparison service in Go. Go backend with PostgreSQL storage. Provider polling is isolated from requests; readers use immutable snapshots. Public service: https://subregator.com.

## Run

Requires Go 1.26 or newer and PostgreSQL 18 or newer. Set `SUBREGATOR_DATABASE_URL` in your shell before running the native binary; Compose provisions PostgreSQL automatically.

```sh
go run ./cmd/subregator
```

Open http://localhost:8080 for API links. The default listener is loopback only. `-addr 0.0.0.0:8080` enables container/network access; put a TLS proxy with request limits in front of an internet-facing deployment.

```sh
TEST_DATABASE_URL="$SUBREGATOR_DATABASE_URL" go test -race ./...
go vet ./...
go test ./internal/api -run '^$' -bench . -benchmem
go build -o bin/subregator ./cmd/subregator
```

Options: `-snapshot var/catalog.json`, `-network=false`, `-feeds-dir /path/to/feeds`, `-providers /path/to/providers.json`, `-cors-origin http://localhost:3000`. CORS accepts one exact origin and no credentials. One ingestion process holds a PostgreSQL advisory lease; a second writer fails startup. PostgreSQL is authoritative for the current snapshot, listing history and bounded network-result cache. Updates commit before publication to the in-memory catalogue. The legacy JSON path is only used for one-time import into a new database and is never overwritten or removed by the new runtime. A corrupt database or legacy import fails startup.

## Configuration

Settings are read from process environment; an explicit CLI flag wins. The native binary does not load `.env` files. Docker Compose automatically uses `.env` for interpolation; `.env.example` lists its supported settings.

| Environment | CLI flag | Native default |
| --- | --- | --- |
| `SUBREGATOR_ADDR` | `-addr` | `127.0.0.1:8080` |
| `SUBREGATOR_SNAPSHOT` | `-snapshot` | `var/catalog.json` (legacy import) |
| `SUBREGATOR_DATABASE_URL` | environment only | `postgresql://subregator@127.0.0.1:5432/subregator?sslmode=disable` |
| `SUBREGATOR_REQUESTS_RPS` | `-requests-rps` | `100` (burst 100) |
| `SUBREGATOR_MAX_CONCURRENT` | `-max-concurrent` | `32` |
| `SUBREGATOR_CHECKS_RPM` | `-checks-rpm` | `120` |
| `SUBREGATOR_IPINFO_LITE_TOKEN` | environment only | optional free Lite token |
| `SUBREGATOR_FEEDS_DIR` | `-feeds-dir` | disabled |
| `SUBREGATOR_PROVIDERS` | `-providers` | embedded registry |
| `SUBREGATOR_NETWORK` | `-network` | `true` |
| `SUBREGATOR_CORS_ORIGIN` | `-cors-origin` | disabled |
| `SUBREGATOR_LOG_FORMAT` | `-log-format` | `text` |
| `SUBREGATOR_LOG_LEVEL` | `-log-level` | `info` |

The container defaults to `0.0.0.0:8080`, `/var/lib/subregator/catalog.json` and JSON logs. An origin must be a scheme and hostname with optional port, without paths, credentials, queries or fragments. Invalid configuration fails startup. `SUBREGATOR_NETWORK=false` disables external polling and network lookups while local feeds and already cached results remain usable. IPinfo tokens are only sent in the Authorization header to the free `/lite` endpoint; they are never included in URLs or public results. Supported log levels are `debug`, `info`, `warn`, `error`.

```sh
SUBREGATOR_NETWORK=false SUBREGATOR_LOG_FORMAT=json go run ./cmd/subregator
./bin/subregator version
./bin/subregator healthcheck -addr 127.0.0.1:8080
```

## Containers

The default Compose file pulls ready images from GHCR; it has no build contexts or host source/config mounts. GitHub Actions publishes both architectures (`linux/amd64`, `linux/arm64`) only after tests and container smoke checks pass. Backend images are `ghcr.io/subregator/subregator-backend`; frontend images are `ghcr.io/subregator/subregator-frontend`. Both use `edge`, immutable `sha-<full commit>` and version tags. Pin each image by digest for a reviewed rollout and retain the previous digests for rollback.

```sh
cp -n .env.example .env
# Set POSTGRES_PASSWORD; retain existing POSTGRES_USER, POSTGRES_DB and database URL on upgrades.
docker compose pull
docker compose up -d --no-build --wait
docker compose logs -f backend frontend
```

Compose starts PostgreSQL 18 with a persistent `postgres` volume and no published database port. The `catalog` volume remains mounted to preserve legacy import files; `checks` persists the frontend's DROP refresh lease and dataset. No catalogue or check data is stored in the container root filesystem. Credentials stay in the untracked `.env` or the process environment. URL-encode special password characters in an external database URL.

The API binds to `127.0.0.1:8080` and the website to `127.0.0.1:8081` by default. The frontend uses `http://backend:8080` through the private Compose network for catalogue and network checks, with no loop through the public website. Both containers run as UID/GID 65532 with read-only roots, dropped capabilities and resource limits. There are no host feeds or provider overrides in this image-only configuration; the backend uses its bundled registry.

### Existing netcup deployment

`compose.production.yaml` is a complete, standalone file for the existing `coolify` Traefik network. Copy it to `/opt/subregator/compose.yaml`; no second Compose file, source checkout, Caddyfile, feed or config directory is needed. TLS, HTTPS redirects and routes for `subregator.com`, `api.subregator.com` and `mcp.subregator.com` are Compose labels. The existing shared Traefik installation and its certificate resolver remain prerequisites.

Keep project name `subregator` and existing volumes `subregator_postgres` and `subregator_catalog`. The live database and role are named `subreggator`; retain those existing values rather than accepting the fresh-install defaults. Preserve the current `.env`, take a database backup and record running image digests before replacing the Compose file. Archive the previous checkout and routing file for rollback; remove the old Subregator dynamic routing file from Traefik's watched directory only after the Compose routes pass direct and public checks. Do not change other applications' routing.

```sh
cd /opt/subregator
docker compose -p subregator config --quiet
docker compose -p subregator pull
docker compose -p subregator up -d --no-build --wait
```

A failed rollout can restore the archived Compose/routing files and prior image digests without recreating PostgreSQL. Never run `down -v`. Image publication and production rollout are separate steps; this repository does not automatically SSH into the server.

For a local backend build, run `make image VERSION=dev` first and set `SUBREGATOR_IMAGE=subregator-backend:local`. Build the frontend separately in its repository when needed; deployment Compose never builds it.

The image's built-in healthcheck uses `/healthz` and needs no shell or curl. `/readyz` separately reports whether a successful source snapshot exists; an empty newly started service can be healthy while not yet ready. Do not add custom server CLI flags in Compose without also updating the healthcheck target if the listener changes.

```sh
# Use a dedicated development/test database, never production.
export TEST_DATABASE_URL="$SUBREGATOR_DATABASE_URL"
make check build
make image VERSION=dev
make smoke
```

The smoke test starts a disposable PostgreSQL service and backend on an isolated Docker network, with a synthetic local feed and public polling disabled. It checks environment configuration, the non-root/read-only runtime, durable history, REST and MCP output, restart recovery, the version command and the image's automatic healthcheck. It cleans up its own disposable container and temporary feed directory. `docker compose down` stops the service and keeps its data volume; do not use `down -v` unless intentionally discarding the catalogue.

## Migrating an existing SQLite database

Stop the old catalogue writer, take a consistent backup and retain the original SQLite database. Start PostgreSQL without starting the backend, then import the complete SQLite file rather than the legacy JSON snapshot; the JSON snapshot does not contain history.

```sh
docker compose stop backend
docker compose up -d postgres
docker compose run --rm --no-deps backend migrate-sqlite -source /var/lib/subregator/existing-catalog.db
docker compose up -d backend
```

Replace `existing-catalog.db` with the actual filename of the preserved SQLite database. Changing the volume mount path does not rename files inside it; keep the original source file unchanged.

For a native binary with `SUBREGATOR_DATABASE_URL` already exported: `./bin/subregator migrate-sqlite -source var/existing-catalog.db`. The URL is environment-only to keep credentials out of command arguments. `SUBREGATOR_DATABASE` and `-database` are retired; no SQLite runtime fallback is used.

Migration opens SQLite read-only, checks its schema/integrity, and copies all seven application tables in one PostgreSQL transaction. It verifies row counts and SHA-256 digests of logical row contents, preserving IDs, timestamps, tracking start, payload bytes, history, cache and cursor high-water marks. SQLite TEXT/BLOB representations of JSON are normalized to the same bytes. New event and poll sequences start above both the maximum IDs and SQLite AUTOINCREMENT high-water marks.

A nonempty target is rejected. Repeating a successfully recorded import of the same source snapshot returns `already_imported` without replacing newer PostgreSQL data. An error rolls back the whole copy; the source is never modified or removed. Keep the migration report and original backup for rollback. Only restart the old binary against SQLite if PostgreSQL has received no new observations, or reconcile those newer observations first.

## Request limits and load checks

The runtime shares one request budget across REST and MCP: 100 HTTP requests per second with a burst of 100, and at most 32 simultaneous handlers per process. Excess rate returns JSON HTTP 429; exhausted handler capacity returns JSON HTTP 503. Both include `Retry-After: 1`; clients should retry with backoff and jitter. Requests are rejected immediately instead of joining an unbounded handler queue. GET/HEAD health and readiness probes and CORS preflight remain available during overload. MCP accepts one JSON-RPC message per POST; legacy batch arrays are rejected with 400.

Tune `SUBREGATOR_REQUESTS_RPS` (1–10000) and `SUBREGATOR_MAX_CONCURRENT` (1–1024) to the deployment hardware. These process-wide limits do not trust client IP headers, allocate per-IP state or provide user quotas. Several replicas have separate budgets; retain edge connection/body limits and add per-user quotas when accounts are introduced. Upstream free-source requests remain separately limited by `SUBREGATOR_CHECKS_RPM`. Provider ingestion does not consume the incoming HTTP budget.

```sh
# TEST_DATABASE_URL must point to a dedicated test database with CREATE SCHEMA permission.
make load-test
# Compare without admission limits, still on an isolated local fixture:
SUBREGATOR_LOADTEST=1 go test ./internal/api -run '^TestLocalLoad$' -v -count=1 -timeout=5m
```

Integration tests use isolated randomly named PostgreSQL schemas and clean up only those schemas. `make check` requires `TEST_DATABASE_URL`; direct `go test` skips database integration tests when it is unset. CI always provides a real PostgreSQL service. The opt-in load test creates 10000 synthetic offers and 50000 history events, binds a temporary loopback HTTP listener, uses the configured PostgreSQL test server and calls no external providers. It exercises sorted search, history (including prefix filters), known resources and MCP at 1/8/32/128 concurrent clients. Output includes HTTP status counts and latency percentiles; successful-response latency is reported separately from fast overload rejections. The normal test suite skips this hardware-dependent run.

## Public endpoints

Public endpoint addresses:

- REST API: `https://api.subregator.com/api/v1/`.
- OpenAPI: `https://api.subregator.com/openapi.json`.
- MCP Streamable HTTP: `https://mcp.subregator.com/` (`/mcp` also works).

`config/Caddyfile.example` routes both hosts to one backend. Run Caddy on the same host as the default Compose loopback binding, or set `SUBREGATOR_UPSTREAM` to the backend address reachable from Caddy. The MCP host rewrites its root internally to `/mcp`, streams responses without buffering. It sends a loopback Host to retain the SDK DNS-rebinding protection, and maps only the exact public MCP Origin to that internal origin; other origins still go through backend validation; other paths return 404. See the [Caddy reverse proxy documentation](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).

Point both DNS records at the deployment host and allow ports 80/443 for Caddy certificate provisioning. Set `SUBREGATOR_CORS_ORIGIN=https://subregator.com` when the frontend uses that exact origin. Keep connection and request-size limits at the public edge in addition to the runtime admission limits. This example does not provision DNS, register the domain or deploy services.

## Continuous integration and image publishing

Pull requests and pushes run formatting checks, vet, race tests, a native binary build, Compose validation, an amd64 container build and the container smoke test. Only after both jobs pass, pushes to `main` and `v*` tags can publish a multi-platform `linux/amd64` + `linux/arm64` image to `ghcr.io/subregator/subregator-backend`. A manual run on `main` follows the same gates. Pull requests never publish and receive no package-write permission.

- `edge`: latest successful build from the default branch.
- `sha-<full-commit>`: a commit-specific tag; use the registry digest when immutable deployment selection is required.
- Semver release tags: `1.2.3`, `1.2`, and `latest` for stable releases. Prerelease tags do not move `latest`.

Actions and the Go base image are pinned to commit hashes/digests; Dependabot proposes weekly updates. Builds include OCI source/revision labels, provenance and an SBOM. Publishing uses the repository's built-in `GITHUB_TOKEN` with package-write permission only in the publishing job; no personal access token is needed.

The first GHCR package may need to be made public in GitHub package settings before anonymous pulls work. Before a first push, neither workflow execution nor registry permissions are verified. Publishing images does not deploy the service.

To run a published image, set `SUBREGATOR_IMAGE=ghcr.io/subregator/subregator-backend:sha-<full-commit>` in `.env`, then:

```sh
docker compose pull
docker compose up -d --no-build
```

## API

- `GET /api/v1/offers`: filters, deterministic sorting, pagination and facets.
- `GET /api/v1/offers/{id}`: complete normalized resource and its quotes.
- `GET /api/v1/providers`: registry, publication restrictions, attempts and last successful refresh.
- `GET /openapi.json`: versioned contract.
- `GET /healthz`: process liveness.
- `GET /readyz`: successful source snapshot exists; inspect source freshness separately.

```sh
curl 'http://localhost:8080/api/v1/offers?country=DE,NL&family=4&currency=USD&sort=price_asc&limit=20'
curl 'http://localhost:8080/api/v1/offers?provider=prefix-broker&currency=EUR&model=purchase'
```

Copy the response `snapshot` into subsequent page requests with `offset`. A refresh returns 409 for an old snapshot; restart pagination. An ID is stable for the provider's external resource ID. There is no CIDR-based deduplication across providers: these may be distinct commercial offers.

Price sorting compares the cheapest matching base quote as an exact rational value: cycle amount divided by billing months for leases, full amount for purchases. Currency must be specified; no exchange rates are assumed. `min_price_minor`/`max_price_minor` use hundredths of that currency, independent of the source's `minor_unit`. Never combine purchase and lease prices into a recommendation; filter `model`. Fees, taxes and deposits remain separate, with unknown costs represented as null. Every quote is returned, with `matching_quote_ids` identifying which quotes matched the query.

`country` refers to provider geolocation/registry data by default. A seller's country only matches with `geography_basis=seller_country`; it is not the subnet's location. IPv6 counts are decimal strings to avoid integer overflow or browser precision loss. Prefixes can be hidden while size, price and conditions remain available. Empty inventory is distinct from a failed or incomplete import.

## Sources and permissions

ONIE public API and Peaktera structured public catalogue are polled every 15 minutes. OBHost public IPv4 inventory is collected daily, retaining exact prefixes, published monthly prices and reserved/leased availability; unpriced ranges require a quote. Explicit redistribution permission has been requested; their policies say `public_source`, not `approved`. Prefix Broker permits anonymous public-page collection at most daily and prohibits displaying prefixes. The adapter imports its purchase listings without prefixes and preserves seller-country semantics. Leasing listings need a separate adapter.

Four providers have enabled built-in collectors. Other providers remain disconnected until a usable feed and display terms are agreed. In particular, ip4.market and ELISTEKA have expressed interest but supplied no endpoints or credentials. The registry contains 27 providers; this does not imply 27 connected inventories. No private API credentials are required or included.

Failures, invalid rows, duplicate IDs, changed pagination totals and incomplete feeds retain the last complete provider snapshot. Source status and per-offer freshness disclose this. Staleness also takes effect after two refresh intervals even without a reported failure. A provider becoming successfully empty removes its old offers. Refresh intervals apply to attempts, including across restarts after a persisted failure. Do not run multiple replicas polling the same restricted provider without a shared scheduler.

## Provider feed contract

`examples/feed.schema.json` and `examples/elisteka.json` describe canonical JSON v1. The example is synthetic, waitlisted, and not loaded by default. Drop a complete feed at `<feeds-dir>/<provider-id>.json` using an atomic file replacement. Enable its registry policy in a separate providers JSON only after agreeing permission; copying `internal/catalog/providers.json` is the starting point. Every feed offer must contain the provider observation timestamp `observed_at`; rereading an old file does not make its offers fresh. File feeds take precedence over built-in polling. No arbitrary URL fetching or public ingestion endpoint is exposed.

Each offer can carry IPv4 or IPv6, purchase or lease model, available/waitlisted/upcoming/unavailable/unknown state, RIR and transfer registries, geography with provenance, multiple billing terms, money and conditional fees, routing capabilities, permitted/prohibited use, notice period, source timestamps and product URL. Missing capabilities do not mean unsupported. Unstructured raw source payloads are deliberately excluded from the public contract.

## Durable history

A successful complete provider catalogue is committed in one PostgreSQL transaction with its current snapshot, listing lifecycle and change events. Readers still use an immutable in-memory view; a database failure prevents publication of an undurable catalogue. Source failures and incomplete/invalid imports retain the last successful inventory and create no disappearance events.

- `GET /api/v1/history`: append-only `baseline`, `listed`, `changed`, `removed`, `relisted`, `resource_changed` events. Filters: provider, listing_id, resource (IP/CIDR), resource_id, type, since, until, after_id, limit.
- `GET /api/v1/listings/{id}`: first/last observations, active state, removal time, appearance count and last offer, including listings no longer in the current catalogue.
- `GET /api/v1/resources`: exact public-prefix identities and the providers that listed them. Filters: provider, resource, after_id, limit.

`resource_reappeared` records a network returning after an observed complete-catalogue absence, including a new listing ID. A changed listing ID without an intervening absence is not a reappearance. A changed CIDR under the same listing ID remains linked to both the previous and new resource histories. Appearance counts belong to the listing identity; the resource flag captures network-level reappearance.

`observed_at` on an event is collection time; the embedded offer retains the source observation timestamp. An active listing means present in the latest successful catalogue, not a guarantee of current inventory or fresh data. Resource active-offer counts have the same observation semantics. The provider list exposes freshness independently.

Public CIDRs correlate only by exact canonical prefix. Masked offers remain individual listing histories; they cannot be linked to an inferred prefix or another provider. Current publication policy also applies to historical responses. A network being seen at two sellers does not establish ownership or prove a transfer. Provider associations and registry/ASN ownership data remain separate.

Follow `next_after_id` for event pagination and polling. Event IDs are append-only; catalogue snapshot pagination remains independent. `tracking_started_at` bounds local coverage. A one-time legacy import produces baseline observations rather than invented earlier events. Observations before collection began are unavailable unless an external historical source provides them.

PostgreSQL stores networks as `cidr` with a GiST index; durable JSON payloads remain byte-preserved. A 16-connection pool separates concurrent history reads from ingestion. Catalogue transactions are serialized with an advisory transaction lock so committed event cursors retain their order; the process writer lease prevents stale in-memory snapshots from competing across processes. This release still runs one ingestion process. The pool uses a 5-second connection timeout, a 30-second statement timeout and a 60-second idle-transaction timeout. Listing history has no automatic expiry. Network cache data is disposable and bounded to 2,000 entries; it is not a complete archive of every lookup. Back up PostgreSQL with supported PostgreSQL tools and retain WAL archives for point-in-time recovery where required; filesystem copies of a running database are not a backup procedure. Database role permissions, TLS and backup retention must be configured for the deployment.

## Automatic offer checks

The Go backend continuously checks each distinct published public prefix, shared across providers. The default inspection collects prefix overview, routing status, RPKI, registration and authoritative RDAP. A single background worker rotates fairly through active prefixes, reuses per-source TTLs and duplicate-request suppression, and paces work against `SUBREGATOR_CHECKS_RPM`. Withheld prefixes are never inferred or submitted to sources. Removed prefixes leave the live result map.

Offer list and detail responses include `checks`: exact-prefix BGP visibility, all-observed-origin RPKI validation, and overlap with the complete Spamhaus DROP IPv4 or IPv6 dataset. Results are read from memory, with no upstream calls or database reads on the offer request path. Each result exposes its own status, freshness, timestamps, source and coverage. New prefixes are explicitly pending until collected; expired observations become stale immediately. Source failures never establish a passing result. RPKI and DROP are source-scoped risk signals, not a universal reputation score or safety guarantee.

Reports and metric observations survive restart through the bounded PostgreSQL cache. Up to 2,000 recent report/metric entries are retained, plus two DROP feed records in a separate table that older cache eviction cannot remove. Evicted reports are rebuilt automatically; a restart can temporarily show pending for them. DROP is downloaded at most once per day per address family, with the next attempt persisted before download, including failed attempts. Metadata, source date, copyright, complete record count and canonical prefixes are validated before publication. A failed refresh retains explicitly stale prior data. Failed completion writes are retried without another download or a new daily reservation; stopping before a successful retry can still lose the unsaved dataset. The background collector waits for request-budget windows so multi-origin RPKI can complete even at one request per minute, publishing completed checks as it progresses. See the [Spamhaus DROP usage requirements](https://www.spamhaus.org/faqs/do-not-route-or-peer-drop/).

`GET /api/v1/network` and MCP `inspect_network` now read existing cached observations only. Visitors cannot trigger basic checks, force a refresh or consume the upstream budget. Arbitrary IP/ASN queries, advanced checks and historical parameter combinations without stored results remain pending. The updated frontend consumes the checks embedded in offers and removes per-row check requests and manual check buttons. Deploy that frontend separately. Keep the legacy frontend check-cache volume mounted in Compose until its image has been updated; the previous image requires this writable path during startup.

Collection throughput is bounded by source quotas, independently of fast catalogue reads. A large cold catalogue needs time to populate; the five-minute routing TTL can exceed the refresh capacity at the default 120 requests/minute. Measure source coverage and freshness before increasing budgets or adding sources. There is one scheduler per process; the existing database writer lease enforces a single ingestion process.

## Free network checks

```sh
curl 'http://localhost:8080/api/v1/network/checks'
curl 'http://localhost:8080/api/v1/network?resource=1.1.1.0/24&checks=prefix_overview,routing_status,rpki,rdap'
curl 'http://localhost:8080/api/v1/network?resource=AS13335&checks=asn_neighbours,asn_rank'
curl 'http://localhost:8080/api/v1/network?resource=193.0.20.0/24&checks=registration_history&version=2020-01-01T00:00:00Z'
```

Available checks include BGP overview/status, collector AS paths, routing history, current registration, historical registration versions, allocation and transfer history, RPKI prefix/ASN validation, ASN overview/neighbours, authoritative RIR RDAP and CAIDA ASRank. IPinfo Lite optionally supplies free country/ASN data for a specific IP when a free token is configured. No paid endpoints, subscriptions, synthetic reputation scores or active ping/traceroute jobs are used.

Stored metrics carry their source URL, capture time, cache expiry, status and coverage. An unavailable check stays unknown. Failed refreshes can return explicitly stale cached observations. Cache TTLs range from one minute for Looking Glass to one day for infrequently changing records; the capabilities endpoint reports each TTL. Concurrent identical checks are deduplicated. Inspections and upstream requests have bounded concurrency and a shared configurable budget of 1..600 upstream requests/minute. Each upstream response is limited to 1 MiB; a truncated/invalid response is not accepted as complete data.

Routing-history windows accept start_time/end_time, up to 366 days per request; the default is seven days. Historical Whois accepts version number or timestamp and covers RIPE Database objects only. It is not a worldwide ownership ledger. RIR transfer records may describe a containing block and omit non-public transfers. BGP visibility and ASN adjacency are collector observations, not a packet-delivery guarantee. RPKI validates an explicit prefix/origin pair; it is not a reputation score. Origin-derived checks cover at most four ASNs.

CAIDA ASRank is an ASN customer-cone topology ranking, not a per-subnet reputation score. Responses carry attribution and date of use. Before publicly displaying CAIDA-derived results, follow the [Public AUA](https://www.caida.org/about/legal/aua/public_aua/), including its citation and publication-report requirements. This release does not send any publication reports automatically.

Sources: [RIPEstat API](https://stat.ripe.net/docs/data-api/ripestat-data-api), [historical Whois coverage](https://stat.ripe.net/docs/data-api/api-endpoints/historical-whois), [IANA RDAP bootstrap](https://data.iana.org/rdap/), [CAIDA ASRank](https://catalog.caida.org/dataset/as_rank), [IPinfo Lite](https://ipinfo.io/developers).

## MCP Streamable HTTP

The `/mcp` endpoint implements Streamable HTTP using the official Go SDK. It is stateless, uses SSE responses, negotiates the protocol and requires no sticky sessions. It exposes the same service operations and validation as REST:

`search_offers`, `get_offer`, `list_providers`, `get_listing`, `listing_history`, `known_resources`, `inspect_network`, `network_checks`, `get_api_schema`.

Filter tools accept a `filters` object containing the normal REST parameter names and values. Cached network observation lookup accepts resource, checks, start_time, end_time, version and asn; it never triggers external work. Results use structured content, with protocol-standard tool errors for invalid operations. Browser clients must use the allowed origin; JSON-RPC bodies are limited to 1 MiB.

Public client connection after deployment (use `http://localhost:8080/mcp` locally):

```json
{
  "mcpServers": {
    "subregator": {
      "url": "https://mcp.subregator.com/"
    }
  }
}
```

The public API is read-only and does not provide administrative feed imports or purchasing operations. Place TLS and appropriate public request limits in front of a deployed service.

## Scope

This release remains a single-writer catalogue and history service. There is no account system, checkout, purchase automation, currency conversion or distributed scheduler. Current listing queries stay in memory; PostgreSQL stores durable observations and a bounded external-result cache. Multiple ingestion writers or independent API replicas require coordinated scheduling and cache refresh before enabling them; sharing PostgreSQL alone does not synchronize each process's in-memory catalogue.

## Upgrading an existing deployment

Before deploying this naming change, update the application environment variable prefix to `SUBREGATOR_` and any binary or internal catalogue paths in deployment overrides. Keep the current Compose project name and existing `postgres` and `catalog` volumes. Do not recreate or rename the database or role: explicitly set `POSTGRES_USER` and `POSTGRES_DB` to their existing values in the untracked `.env`, and retain the complete current connection URL as `SUBREGATOR_DATABASE_URL`. PostgreSQL initialization variables do not alter an initialized volume. Build and publish the renamed image before changing the deployment image reference.

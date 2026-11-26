# Configuration and development

[Back to README](../README.md)

Run commands from the repository root.

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

Settings are read from process environment; an explicit CLI flag wins. The native binary does not load `.env` files. Docker Compose automatically uses `.env` for interpolation; [.env.example](../.env.example) lists its supported settings.

| Environment                    | CLI flag          | Native default                                                      |
| ------------------------------ | ----------------- | ------------------------------------------------------------------- |
| `SUBREGATOR_ADDR`              | `-addr`           | `127.0.0.1:8080`                                                    |
| `SUBREGATOR_SNAPSHOT`          | `-snapshot`       | `var/catalog.json` (legacy import)                                  |
| `SUBREGATOR_DATABASE_URL`      | environment only  | `postgresql://subregator@127.0.0.1:5432/subregator?sslmode=disable` |
| `SUBREGATOR_REQUESTS_RPS`      | `-requests-rps`   | `100` (burst 100)                                                   |
| `SUBREGATOR_MAX_CONCURRENT`    | `-max-concurrent` | `32`                                                                |
| `SUBREGATOR_CHECKS_RPM`        | `-checks-rpm`     | `120`                                                               |
| `SUBREGATOR_IPINFO_LITE_TOKEN` | environment only  | optional free Lite token                                            |
| `SUBREGATOR_FEEDS_DIR`         | `-feeds-dir`      | disabled                                                            |
| `SUBREGATOR_PROVIDERS`         | `-providers`      | embedded registry                                                   |
| `SUBREGATOR_IRR` | `-irr` | `false`; public normalized IRR collection needs registry-use approval |
| `SUBREGATOR_IRRD_URL` | environment only | `http://subregator-irrd:8000/graphql/` |
| `SUBREGATOR_NETWORK`           | `-network`        | `true`                                                              |
| `SUBREGATOR_CORS_ORIGIN`       | `-cors-origin`    | disabled                                                            |
| `SUBREGATOR_LOG_FORMAT`        | `-log-format`     | `text`                                                              |
| `SUBREGATOR_LOG_LEVEL`         | `-log-level`      | `info`                                                              |

The container defaults to `0.0.0.0:8080`, `/var/lib/subregator/catalog.json` and JSON logs. An origin must be a scheme and hostname with optional port, without paths, credentials, queries or fragments. Invalid configuration fails startup. `SUBREGATOR_NETWORK=false` disables external polling and network lookups while local feeds and already cached results remain usable. IPinfo tokens are only sent in the Authorization header to the free `/lite` endpoint; they are never included in URLs or public results. Supported log levels are `debug`, `info`, `warn`, `error`.

```sh
SUBREGATOR_NETWORK=false SUBREGATOR_LOG_FORMAT=json go run ./cmd/subregator
./bin/subregator version
./bin/subregator healthcheck -addr 127.0.0.1:8080
```

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

### Optional Spamhaus ZEN

`SUBREGATOR_SPAMHAUS=false` / `-spamhaus=false` keeps the licensed HTTPS source off. After product/quota/public-use approval, set `SUBREGATOR_SPAMHAUS_KEY` in the environment and enable the flag. A key alone does not enable collection. No key flag is provided. This product is distinct from DQS DNS/SIA. One first-address sample per prefix always has partial subnet coverage except single-host prefixes. See [blocklist contract and access gate](blocklists.md).

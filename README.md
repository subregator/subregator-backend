<p>
  <img src="docs/assets/subregator-icon.svg" width="80" height="80" alt="Subregator logo">
</p>

# Subregator Backend

**IP address offers, price history and routing observations — through REST and MCP.**

[Website](https://subregator.com) · [OpenAPI](https://api.subregator.com/openapi.json) · [Frontend](https://github.com/subregator/subregator-frontend) · [Report an issue](https://github.com/subregator/subregator-backend/issues)

Subregator brings IP lease and purchase offers from multiple providers into one searchable catalogue. This repository contains the Go service, PostgreSQL storage and background collectors behind [subregator.com](https://subregator.com).

## What it does

- Normalizes provider offers while preserving prices, billing terms, fees and source freshness.
- Tracks listing changes and the history of published prefixes.
- Collects BGP, RPKI and Spamhaus DROP observations in the background.
- Serves the same data through a read-only REST API and MCP tools.

Source observations are not a safety or ownership guarantee. Hidden prefixes stay hidden; unknown or stale checks never count as passing.

## Quick start

Requires **Go 1.26+** and a running **PostgreSQL 18+** database. From the repository root, set the URL for your development database and start the service:

```sh
export SUBREGATOR_DATABASE_URL='postgresql://USER:PASSWORD@localhost:5432/subregator?sslmode=disable'
go run ./cmd/subregator
```

Replace the example credentials and database name with your own. The native binary reads environment variables; it does not load `.env` files.

Open [localhost:8080](http://localhost:8080) for endpoint links, or query the catalogue:

```sh
curl 'http://localhost:8080/api/v1/offers?family=4&currency=USD&limit=20'
```

Provider collection runs in the background, so a fresh database may initially return an empty catalogue. Run one ingestion process per database.

The optional [IRR consistency check](docs/irr.md) uses a [private IRRd mirror](deploy/irrd/README.md) and serves normalized cached observations through REST/MCP.

Prefer Docker? Follow the [Compose setup](docs/deployment.md#containers) to run PostgreSQL, the backend and the frontend together.

## REST and MCP

| Interface            | Local address                                                     |
| -------------------- | ----------------------------------------------------------------- |
| REST API             | `http://localhost:8080/api/v1/`                                   |
| OpenAPI schema       | [localhost:8080/openapi.json](http://localhost:8080/openapi.json) |
| MCP Streamable HTTP  | `http://localhost:8080/mcp`                                       |
| Liveness / readiness | `/healthz` / `/readyz`                                            |

See the [API and data reference](docs/api.md) for filters, pagination, history, source policies and MCP configuration. Use `/api/v1/network` for cached observations or `/api/v1/network/lookup?resource=163.5.251.0%2F24&checks=all` for on-demand collection. The [network evidence contract](docs/network-checks.md) covers topology, geolocation, whole-prefix DNSBL progress, active ping/traceroute and bounded HTTP throughput.

## Development

Use a dedicated test database with permission to create schemas. Integration tests create and remove isolated schemas within it.

```sh
export TEST_DATABASE_URL='postgresql://USER:PASSWORD@localhost:5432/subregator_test?sslmode=disable'
make check build
```

`make check` runs formatting checks, vet and race tests. See [configuration and development](docs/configuration.md) for settings, benchmarks and load checks, and [deployment and upgrades](docs/deployment.md) for containers and migrations.

## Contributing

Bug reports and pull requests are welcome. Include steps to reproduce a bug; for a new provider, include its public feed or API details and display terms. Keep changes focused and run the relevant checks before opening a PR.

Follow the [backend roadmap issues](https://github.com/subregator/subregator-backend/issues/2) for subnet checks, provider integrations, price history and network observations, with dependencies and acceptance criteria.

## License

[MIT](LICENSE). Third-party software notices are listed in [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt). Provider data remains subject to its source terms.

See [subnet market and price history](docs/subnet-market.md) for exact-prefix seller comparison, quoted costs, provider gaps, REST/MCP pagination and explicit parent/child relationships.

[Durable observation history](docs/observation-history.md): opt-in normalized check storage, conservative change bounds and cached-only REST/MCP queries.

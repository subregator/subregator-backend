# Deployment and upgrades

[Back to README](../README.md)

Run commands from the repository root.

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

[compose.production.yaml](../compose.production.yaml) is a complete, standalone file for the existing `coolify` Traefik network. Copy it to `/opt/subregator/compose.yaml`; no second Compose file, source checkout, Caddyfile, feed or config directory is needed. TLS, HTTPS redirects and routes for `subregator.com`, `api.subregator.com` and `mcp.subregator.com` are Compose labels. The existing shared Traefik installation and its certificate resolver remain prerequisites.

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

## Public endpoints

Public endpoint addresses:

- REST API: `https://api.subregator.com/api/v1/`.
- OpenAPI: `https://api.subregator.com/openapi.json`.
- MCP Streamable HTTP: `https://mcp.subregator.com/` (`/mcp` also works).

[config/Caddyfile.example](../config/Caddyfile.example) routes both hosts to one backend. Run Caddy on the same host as the default Compose loopback binding, or set `SUBREGATOR_UPSTREAM` to the backend address reachable from Caddy. The MCP host rewrites its root internally to `/mcp`, streams responses without buffering. It sends a loopback Host to retain the SDK DNS-rebinding protection, and maps only the exact public MCP Origin to that internal origin; other origins still go through backend validation; other paths return 404. See the [Caddy reverse proxy documentation](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).

Point both DNS records at the deployment host and allow ports 80/443 for Caddy certificate provisioning. Set `SUBREGATOR_CORS_ORIGIN=https://subregator.com` when the frontend uses that exact origin. Keep connection and request-size limits at the public edge in addition to the runtime admission limits. This example does not provision DNS, register the domain or deploy services.

## Continuous integration and image publishing

Pull requests and pushes run formatting checks, vet, race tests, a native binary build, Compose validation, an amd64 container build and the container smoke test. Only after both jobs pass, pushes to `main` and `v*` tags can publish a multi-platform `linux/amd64` + `linux/arm64` image to `ghcr.io/subregator/subregator-backend`. A manual run on `main` follows the same gates. Pull requests never publish and receive no package-write permission.

- `edge`: latest successful build from the default branch.
- `sha-<full-commit>`: a commit-specific tag; use the registry digest when immutable deployment selection is required.
- Semver release tags: `1.2.3`, `1.2`, and `latest` for stable releases. Prerelease tags do not move `latest`.

Actions and the Go base image are pinned to commit hashes/digests; Dependabot proposes weekly updates. Builds include OCI source/revision labels, provenance and an SBOM. Publishing uses the repository's built-in `GITHUB_TOKEN` with package-write permission only in the publishing job; no personal access token is needed.

The first GHCR package may need to be made public in GitHub package settings before anonymous pulls work. Publishing images does not deploy the service.

To run a published image, set `SUBREGATOR_IMAGE=ghcr.io/subregator/subregator-backend:sha-<full-commit>` in `.env`, then:

```sh
docker compose pull
docker compose up -d --no-build
```

## Upgrading an existing deployment

Before deploying this naming change, update the application environment variable prefix to `SUBREGATOR_` and any binary or internal catalogue paths in deployment overrides. Keep the current Compose project name and existing `postgres` and `catalog` volumes. Do not recreate or rename the database or role: explicitly set `POSTGRES_USER` and `POSTGRES_DB` to their existing values in the untracked `.env`, and retain the complete current connection URL as `SUBREGATOR_DATABASE_URL`. PostgreSQL initialization variables do not alter an initialized volume. Build and publish the renamed image before changing the deployment image reference.

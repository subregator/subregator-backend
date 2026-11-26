# Private IRRd mirror

Standalone Compose project for `/opt/subregator-irrd` on `netcup-main`. Requires the existing `subregator_default` Docker network. It does not recreate Subregator containers or reuse their database, Redis, volumes or credentials.

IRRd 4.5.5 stores only `route` and `route6` objects from daily HTTPS exports of RIPE, RIPE-NONAUTH, ARIN, APNIC, LACNIC and AFRINIC. RIPE and APNIC supply split route files; other exports are filtered on import. This is partial IRR coverage: RADB and other independent registries are absent. Downloads and queries do not use NLNOG/IRRexplorer.

Each source refreshes every 86400 seconds; upstream snapshots have their own publication times. This is not near-real-time mirroring. RPKI suppression, scope filtering and source preference are disabled so conflicting registrations remain queryable. RPKI observations belong to Subregator's independent collector. No authoritative sources or outbound notifications are enabled.

## Install

Copy this directory, excluding `.env`, to `/opt/subregator-irrd`. Create independent credentials there without printing them:

```sh
cd /opt/subregator-irrd
python3 - <<'PY'
import os, secrets
fd = os.open('.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as f:
    f.write('IRRD_POSTGRES_PASSWORD=' + secrets.token_hex(32) + '\n')
PY
docker compose config --quiet
docker compose --dry-run up -d --build
docker compose build irrd
docker compose up -d --wait irrd-postgres irrd-redis
docker compose run --rm --no-deps irrd irrd_database_upgrade --config=/etc/irrd.yaml
docker compose up -d --no-build --wait irrd
```

Do not print the rendered Compose config: it includes the database password. The dry run checks the intended container operations, but does not execute migrations, import data, check upstream access or measure resource usage. Run the checks below after the real start. Schedule builds separately from imports and observe host memory.

The sum of runtime memory limits is 6.75 GiB: IRRd 3 GiB, PostgreSQL 1.5 GiB, Redis 2.25 GiB. CPU limits are 1.5, 1 and 0.5 respectively. These limits are for this filtered mirror, not a full general-purpose IRR server. Check available host memory before importing or expanding sources. Container logs rotate at 3 × 10 MiB per service. PostgreSQL persists in its own volume; Redis is rebuilt from PostgreSQL. Temporary imports use the work volume, not memory-backed `/tmp`.

## Access and checks

The application endpoint is `http://subregator-irrd:8000/graphql/` on `subregator_default`. The host endpoint is `http://127.0.0.1:18084/graphql/` and requires `Host: subregator-irrd`, matching IRRd's trusted-host validation. There is no public proxy route. PostgreSQL and Redis have no published ports; Whois binds only inside IRRd's loopback interface.

```sh
docker compose ps
docker compose logs --tail 100 irrd
curl --fail-with-body -H 'Host: subregator-irrd' -H 'Content-Type: application/json' \
  --data '{"query":"{databaseStatus{source authoritative objectClassFilter rpslDataUpdated}}"}' \
  http://127.0.0.1:18084/graphql/
docker compose exec -T irrd-postgres psql -U irrd -d irrd -c \
  'SELECT source, object_class, count(*) FROM rpsl_objects GROUP BY source, object_class ORDER BY source, object_class;'
docker stats --no-stream
docker compose exec -T irrd cat /sys/fs/cgroup/memory.events
```

All six sources must have nonempty route data after initial import. GraphQL HTTP 200 can still contain an `errors` array: check it. The container healthcheck verifies API/database availability, not successful import or source freshness. Compare source update times with upstream publication times and inspect import errors; a failed refresh must not be presented as a current observation. Query all origins with `rpslObjects`, not a query that selects one preferred result. Object `last-modified`, mirror ingestion time and BGP observation time have different meanings.

Check that `oom_kill` did not increase during imports. A 2 GiB limit killed an import worker during the initial concurrent load while the API remained healthy; the configured 3 GiB limit must be reassessed before expanding sources. To retry a failed source without restarting every import, run the installed `RPSLMirrorImportUpdateRunner` for that source in the existing container, after confirming that no importer for the same source is still running.

For local validation use a separate Compose project, independent volumes and a separate client network. Override the configuration with file-based synthetic `route`, `route6`, conflicting origins across two sources, and an excluded `aut-num`. Check exact IPv4/IPv6 matches, all conflicting origins, class filtering, healthchecks, restart recovery and retention of committed objects after a failed source download. Never run fixture imports against this production database.

## Operation and rollback

`docker compose stop` stops only the mirror and preserves its volumes. Subregator continues running independently. To change config, archive the old YAML first, validate the new config using the installed IRRd package, then restart only `irrd`. Back up this mirror's PostgreSQL database before upgrading IRRd or its schema; retain the previous image for rollback. Never remove the volumes to perform an upgrade.

This database is a rebuildable current mirror. Daily full imports do not provide an object-change journal or a complete historical archive. An offsite backup schedule and public publication of normalized findings are separate work. Keep the raw API private; verify each source's terms before enabling public redistribution or historical retention. In particular, RIPE's NRTM documentation requires prior written permission for third-party sharing; switching from daily exports to NRTM also needs a terms review.

Sources: [IRRd deployment](https://irrd.readthedocs.io/en/stable/admins/deployment/), [configuration](https://irrd.readthedocs.io/en/stable/admins/configuration/), [mirroring](https://irrd.readthedocs.io/en/stable/users/mirroring/), [RIPE exports](https://ftp.ripe.net/ripe/dbase/split/), [RIPE NRTM conditions](https://docs.db.ripe.net/RIPE-Database-Mirror/Near-Real-Time-Mirroring-v3), [ARIN IRR](https://www.arin.net/resources/manage/irr/), [APNIC exports](https://ftp.apnic.net/apnic/whois/), [LACNIC mirroring](https://www.lacnic.net/5009/2/lacnic/update-on-lacnics-irr%3A-near-real-time-mirroring-now-available), [AFRINIC mirroring](https://afrinic.net/irr-guide).

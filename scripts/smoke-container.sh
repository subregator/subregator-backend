#!/usr/bin/env bash
set -euo pipefail

image=${1:-subregator-backend:local}
name="subregator-smoke-$$"
container=""
postgres=""
network="${name}-network"
fixture=$(mktemp -d)
trap '
  smoke_exit=$?
  if (( smoke_exit != 0 )); then
    if [[ -n "$container" ]]; then docker logs "$container" >&2 || true; fi
    if [[ -n "$postgres" ]]; then docker logs "$postgres" >&2 || true; fi
  fi
  if [[ -n "$container" ]]; then docker stop "$container" >/dev/null 2>&1 || true; fi
  if [[ -n "$postgres" ]]; then docker stop "$postgres" >/dev/null 2>&1 || true; fi
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$fixture"
' EXIT
mkdir "$fixture/feeds"
python3 - "$fixture/feeds/onie.json" <<'PYTHON'
import datetime, json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1, "provider_id": "onie", "complete": True,
    "offers": [{
        "external_id": "container-smoke", "provider_id": "onie",
        "model": "lease", "availability": "available",
        "resource": {"family": 4, "prefix": "1.1.1.0/24", "prefix_length": 24, "rir": "ARIN"},
        "geography": {"country": "US", "basis": "provider_geolocation"},
        "quotes": [{"id": "monthly", "price": {"currency": "USD", "amount_minor": 1000, "minor_unit": 2}, "billing_months": 1, "fees": [], "taxes": "unknown"}],
        "url": "https://onie.net/ip-subnets",
        "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }]
}))
PYTHON

python3 - "$fixture" <<'PYTHON'
import pathlib, secrets, sys
p = pathlib.Path(sys.argv[1]); password = secrets.token_hex(24) + ":@/?!%"
(p / "postgres.env").write_text("POSTGRES_USER=subregator\nPOSTGRES_DB=subregator\nPOSTGRES_PASSWORD=" + password + "\n")
(p / "backend.env").write_text("SUBREGATOR_DATABASE_URL=postgresql://postgres:5432/?sslmode=disable\nPGUSER=subregator\nPGDATABASE=subregator\nPGPASSWORD=" + password + "\n")
for name in ("postgres.env", "backend.env"):
    (p / name).chmod(0o600)
PYTHON
docker network create "$network" >/dev/null
postgres=$(docker run -d --rm --network "$network" --network-alias postgres --env-file "$fixture/postgres.env" postgres:18.6@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336)
# The initialization server accepts Unix sockets before the final TCP listener exists.
for ((attempt=0; attempt<60; attempt++)); do
  if docker exec "$postgres" pg_isready -h 127.0.0.1 -U subregator >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$postgres" pg_isready -h 127.0.0.1 -U subregator >/dev/null

container=$(docker run -d --rm --name "$name" \
  --network "$network" --env-file "$fixture/backend.env" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 512m \
  -e SUBREGATOR_NETWORK=false -e SUBREGATOR_FEEDS_DIR=/feeds -e SUBREGATOR_REQUESTS_RPS=20 -e SUBREGATOR_MAX_CONCURRENT=8 \
  --mount "type=bind,src=$fixture/feeds,dst=/feeds,readonly" \
  -p 127.0.0.1::8080 "$image")
port=$(docker port "$container" 8080/tcp | head -n 1)
test "$(docker inspect --format '{{.Config.User}}' "$container")" = '65532:65532'
docker exec "$container" /subregator version
python3 - "$port" <<'PYTHON'
import json, sys, time, urllib.request
base = "http://" + sys.argv[1]
for attempt in range(100):
    try:
        with urllib.request.urlopen(base + "/readyz", timeout=1) as response:
            assert response.status == 200
        break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("Catalog did not become ready")
with urllib.request.urlopen(base + "/api/v1/offers", timeout=2) as response:
    data = json.load(response)
assert data["total"] == 1
assert data["items"][0]["resource"]["prefix"] == "1.1.1.0/24"
assert data["items"][0]["freshness"] == "fresh"
with urllib.request.urlopen(base + "/api/v1/history", timeout=2) as response:
    history = json.load(response)
assert len(history["items"]) == 1 and history["items"][0]["type"] == "listed"
with urllib.request.urlopen(base + "/api/v1/listings/" + data["items"][0]["id"], timeout=2) as response:
    listing = json.load(response)
assert listing["active"] and listing["appearances"] == 1
with urllib.request.urlopen(base + "/api/v1/resources", timeout=2) as response:
    resources = json.load(response)
assert resources["items"][0]["provider_ids"] == ["onie"]
with urllib.request.urlopen(base + "/api/v1/market?resource=1.1.1.0/24", timeout=2) as response:
    market = json.load(response)
assert market["current"]["total"] == 1
assert market["current"]["items"][0]["relation"] == "exact"
assert len(market["history"]["items"]) == 1
assert market["polls"]["items"][0]["complete"]
with urllib.request.urlopen(base + "/api/v1/network/history?resource=1.1.1.0/24", timeout=2) as response:
    assert json.load(response)["items"] == []
with urllib.request.urlopen(base + "/api/v1/timeline?resource=1.1.1.0/24", timeout=2) as response:
    assert json.load(response)["items"] == []

def rpc(payload, version=None):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if version:
        headers["MCP-Protocol-Version"] = version
    request = urllib.request.Request(base + "/mcp", json.dumps(payload).encode(), headers)
    with urllib.request.urlopen(request, timeout=5) as response:
        body = response.read().decode()
        if "text/event-stream" in response.headers.get("Content-Type", ""):
            return next(json.loads(line[5:].strip()) for line in body.splitlines() if line.startswith("data:") and '"result"' in line)
        return json.loads(body)
initialized = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "container-smoke", "version": "1.0.0"}}})
result = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "search_offers", "arguments": {"filters": {"limit": "1"}}}}, initialized["result"]["protocolVersion"])
assert result["result"]["structuredContent"]["total"] == 1
market_rpc = rpc({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "subnet_market", "arguments": {"filters": {"resource": "1.1.1.0/24"}}}}, initialized["result"]["protocolVersion"])
assert market_rpc["result"]["structuredContent"]["current"]["total"] == 1
archive = rpc({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "network_history", "arguments": {"filters": {"resource": "1.1.1.0/24"}}}}, initialized["result"]["protocolVersion"])
assert archive["result"]["structuredContent"]["items"] == []
timeline = rpc({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "resource_timeline", "arguments": {"filters": {"resource": "1.1.1.0/24"}}}}, initialized["result"]["protocolVersion"])
assert timeline["result"]["structuredContent"]["items"] == []
with urllib.request.urlopen(base + "/api/v1/report?resource=1.1.1.0/24", timeout=2) as response:
    report = json.load(response)
assert report["market"]["data"]["total"] == 1
assert report["network_history"] == "disabled" and report["timeline"]["data"]["items"]
report_rpc = rpc({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "subnet_report", "arguments": {"filters": {"resource": "1.1.1.0/24"}}}}, initialized["result"]["protocolVersion"])
assert report_rpc["result"]["structuredContent"]["market"]["data"] == report["market"]["data"]
with urllib.request.urlopen(base + "/api/v1/network/status", timeout=2) as response:
    status = json.load(response)
assert isinstance(status["work"], list) and status["request_budget_rpm"] == 120
print("Non-root read-only container: feed, report REST/MCP, collection counters, timeline and default-off archive passed")

import concurrent.futures, urllib.error
payload = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "network_checks", "arguments": {}}}).encode()
def burst(index):
    path = "/mcp" if index % 2 else "/api/v1/offers"
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"}
    request = urllib.request.Request(base + path, payload if index % 2 else None, headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        assert error.code in (429, 503), error.code
        assert error.headers["Retry-After"] == "1"
        assert json.load(error)["error"]["code"] in ("rate_limited", "server_busy")
        return error.code
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
    statuses = list(executor.map(burst, range(120)))
assert 429 in statuses, statuses
with urllib.request.urlopen(base + "/healthz", timeout=2) as response:
    assert response.status == 200
print("Runtime admission limits: REST/MCP overload rejected; health probe available")
PYTHON
docker exec "$container" /subregator healthcheck
docker restart "$container" >/dev/null
port=$(docker port "$container" 8080/tcp | head -n 1)
python3 - "$port" <<'PYTHON'
import json, sys, time, urllib.request
base = "http://" + sys.argv[1]
for attempt in range(100):
    try:
        with urllib.request.urlopen(base + "/api/v1/history", timeout=1) as response:
            data = json.load(response)
        assert len(data["items"]) == 1
        assert data["items"][0]["type"] == "listed"
        print("Restart preserved history without duplicating baseline events")
        break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("Container restart failed")
PYTHON
# The automatic healthcheck must also work without a shell or curl.
for ((attempt=0; attempt<40; attempt++)); do
  status=$(docker inspect --format '{{.State.Health.Status}}' "$container")
  if [[ "$status" == healthy ]]; then
    echo 'Image HEALTHCHECK passed'
    exit 0
  fi
  if [[ "$status" == unhealthy ]]; then break; fi
  sleep 1
done
docker logs "$container"
echo 'Image HEALTHCHECK did not become healthy' >&2
exit 1

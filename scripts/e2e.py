"""End-to-end check of the whole pipeline against a running stack (docker compose or local processes).

traffic -> gateway(sim probe) -> detector(BOLA) -> control plane(redaction, ClickHouse, PostgreSQL)
        -> drift -> red team -> WAF sync -> enforcement at the gateway
"""
import base64
import json
import os
import sys
import time

import httpx

CONTROL = os.environ.get("CONTROL_URL", "http://localhost:8000")
GATEWAY = os.environ.get("GATEWAY_URL", "http://localhost:9000")
CH = os.environ.get("CLICKHOUSE_URL", "")
TARGET = os.environ.get("REDTEAM_TARGET", GATEWAY)
KEY = {"X-API-Key": os.environ.get("API_KEY", "")} if os.environ.get("API_KEY") else {}
SPEC = os.environ.get("SPEC", "gateway/openapi.yaml")


def jwt(sub: str) -> str:
    e = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    return f"Bearer {e(b'{\"alg\":\"none\"}')}.{e(json.dumps({'sub': sub}).encode())}.x"


def check(cond: bool, msg: str) -> None:
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)


def wait_for(fn, what: str, timeout: float = 40):
    end = time.time() + timeout
    while time.time() < end:
        try:
            v = fn()
            if v:
                return v
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    check(False, f"timeout waiting for {what}")


cp = httpx.Client(base_url=CONTROL, headers=KEY, timeout=30)
gw = httpx.Client(base_url=GATEWAY, timeout=10)

wait_for(lambda: cp.get("/healthz").status_code == 200, "control plane")
wait_for(lambda: gw.get("/health").status_code == 200, "gateway")

# 1. official catalog (PostgreSQL)
r = cp.put("/catalog/demo", content=open(SPEC, "rb").read())
check(r.status_code == 200 and r.json()["operations"] == 3, "official OpenAPI catalog stored")

# 2. traffic through the simulation probe
alice = {"Authorization": jwt("1")}
gw.get("/health")
gw.get("/users/1", headers=alice)          # own profile (contains PII in the response)
gw.get("/users/2", headers=alice)          # BOLA: alice reads Beto
for _ in range(3):
    gw.get("/admin/debug")                 # undocumented
gw.get("/legacy/accounts/1")               # undocumented

# 3. drift
def drift_ready():
    d = cp.get("/drift").json()
    paths = {s["path"] for s in d["shadow"]}
    return d if {"/admin/debug", "/legacy/accounts/{id}"} <= paths else None

d = wait_for(drift_ready, "shadow endpoints to appear in /drift")
paths = {s["path"] for s in d["shadow"]}
check("/users/{id}" not in paths and "/health" not in paths, "documented endpoints are not reported as shadow")
check(d["summary"]["shadow"] >= 2, f"drift reports {d['summary']['shadow']} shadow endpoints")

# 4. BOLA detection
alerts = wait_for(lambda: cp.get("/alerts").json(), "BOLA alert")
check(all(a["path"] == "/users/{id}" for a in alerts) and len(alerts) >= 1, "BOLA alert raised for /users/{id} only")

# 5. PII never reaches storage
if CH:
    ch = httpx.Client(auth=("default", os.environ["CLICKHOUSE_PASSWORD"]) if os.environ.get("CLICKHOUSE_PASSWORD") else None)
    rows = ch.post(CH, params={"query": "SELECT * FROM api_events FORMAT JSON"}).json()["data"]
    blob = json.dumps(rows)
    check(len(rows) >= 7, f"{len(rows)} events stored in ClickHouse")
    leaks = [s for s in ("ana@example.cl", "12.345.678-5", "4111 1111 1111 1111", "4111111111111111", "hunter2", "Bearer ", "eyJ") if s in blob]
    check(not leaks, "no PII/secrets in ClickHouse" + (f" (leaked: {leaks})" if leaks else ""))
    check("REDACTED" in blob, "redaction markers present in stored payloads")

# 6. red team on drifted endpoints
if "REDTEAM_ALLOWED_HOSTS" in os.environ or TARGET:
    res = cp.post("/redteam/scan", json={"target": TARGET}).json()
    found = {(f["path"], f["check"]) for f in res["findings"]}
    check(("/admin/debug", "unauthenticated_access") in found, "red team: /admin/debug reachable without credentials")
    check(("/admin/debug", "pii_exposure") in found, "red team: PII exposure on /admin/debug")
    check(("/legacy/accounts/{id}", "idor_enumeration") in found, "red team: IDOR enumeration on /legacy/accounts/{id}")
    check(("/legacy/accounts/{id}", "injection_error") in found, "red team: error disclosure on injection payload")

time.sleep(2)  # let the scanner's own traffic flow through the pipeline
shadow_after = {x["path"] for x in cp.get("/drift").json()["shadow"]}
check(shadow_after == {"/admin/debug", "/legacy/accounts/{id}"}, f"fuzzing noise does not pollute drift ({sorted(shadow_after)})")

# 7. WAF sync and enforcement
check(gw.get("/admin/debug").status_code == 200, "before sync the shadow endpoint is still exposed")
s = cp.post("/waf/sync").json()
check(s["synced"], f"WAF rules {s['version']} synced to the gateway")
check(gw.get("/admin/debug").status_code == 403, "WAF blocks /admin/debug")
check(gw.get("/legacy/accounts/1").status_code == 403, "WAF blocks /legacy/accounts/{id}")
body = gw.get("/users/1", headers=alice).text
check("ana@example.cl" not in body and "4111" not in body, "WAF masks PII in documented responses")
check(gw.get("/health").status_code == 200, "documented endpoints keep working")
print("\nE2E OK")

"""End-to-end check of the whole pipeline against a running stack (docker compose or local processes).

traffic -> gateway(sim probe) -> detector(BOLA) -> control plane(redaction, ClickHouse, PostgreSQL)
        -> drift -> red team -> WAF sync -> enforcement at the gateway
"""
import base64
import hashlib
import hmac
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


JWT_SECRET = os.environ.get("JWT_SECRET", "")
DETECTOR = os.environ.get("DETECTOR_URL", "")


def jwt(sub: str) -> str:
    """HS256 when JWT_SECRET is set (the detector then verifies signatures), unsigned otherwise."""
    e = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    alg = "HS256" if JWT_SECRET else "none"
    head, body = e(json.dumps({"alg": alg}).encode()), e(json.dumps({"sub": sub}).encode())
    sig = e(hmac.new(JWT_SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()) if JWT_SECRET else "x"
    return f"Bearer {head}.{body}.{sig}"


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
check(r.status_code == 200 and r.json()["operations"] == 4, "official OpenAPI catalog stored")

# 2. traffic through the simulation probe
alice = {"Authorization": jwt("1")}
for i in range(24):                        # 3 users reading their own statements -> ownership rule is learned
    u = i % 3 + 1
    gw.get(f"/accounts/{u}/statements", headers={"Authorization": jwt(str(u))})
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

# 3b. schema drift: the demo API returns email/rut/card that the official spec does not document
sd = wait_for(lambda: cp.get("/drift").json()["schema_drift"], "schema drift")
check({"EMAIL", "RUT", "CARD"} <= set(sd[0]["pii"]), f"schema drift flags undocumented PII fields ({sd[0]['pii']})")

# 4. BOLA detection: static rule on /users/{id}, learned rule on /accounts/{id}/statements
alerts = wait_for(lambda: cp.get("/alerts").json(), "BOLA alert")
check(any(a["path"] == "/users/{id}" for a in alerts), "BOLA alert raised for /users/{id} (static rule)")
if DETECTOR:
    learned = httpx.get(DETECTOR + "/rules").json()["learned"]
    check(any(r["Claim"] == "sub" for r in learned), f"detector learned an ownership rule ({learned[0]['Template'] if learned else ''})")
    gw.get("/accounts/2/statements", headers=alice)     # alice reads Beto's statements
    la = wait_for(lambda: [a for a in cp.get("/alerts").json() if a["path"] == "/accounts/{id}/statements"], "learned-rule BOLA alert")
    check("learned rule" in la[0]["detail"], "BOLA detected through the learned rule")

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
    # bandit B105 accepted: synthetic placeholders, not credentials
    identities = [
        {"token": "id-a", "owned_ids": ["1"]},  # nosec B105
        {"token": "id-b", "owned_ids": ["2"]},  # nosec B105
    ]
    res = cp.post("/redteam/scan", json={"target": TARGET, "identities": identities}).json()
    found = {(f["path"], f["check"]) for f in res["findings"]}
    check(("/admin/debug", "unauthenticated_access") in found, "red team: /admin/debug reachable without credentials")
    check(("/admin/debug", "pii_exposure") in found, "red team: PII exposure on /admin/debug")
    check(("/legacy/accounts/{id}", "idor_enumeration") in found, "red team: IDOR enumeration on /legacy/accounts/{id}")
    check(("/legacy/accounts/{id}", "bola_confirmed") in found, "red team: cross-identity BOLA confirmed on /legacy/accounts/{id}")
    check(("/legacy/accounts/{id}", "injection_error") in found, "red team: error disclosure on injection payload")

time.sleep(2)  # let the scanner's own traffic flow through the pipeline
shadow_after = {x["path"] for x in cp.get("/drift").json()["shadow"]}
check(shadow_after == {"/admin/debug", "/legacy/accounts/{id}"}, f"fuzzing noise does not pollute drift ({sorted(shadow_after)})")

# 6b. exports
draft = cp.get("/openapi/draft").json()
check("/admin/debug" in draft["paths"] and "/users/{id}" not in draft["paths"], "OpenAPI draft lists shadow endpoints only")
nginx = cp.get("/waf/rules", params={"format": "nginx"}).text
check("shadowapi_block" in nginx, "WAF rules exported as nginx config")
check("ShadowAPI Guard" in httpx.get(CONTROL + "/dashboard").text, "dashboard served")
check("shadowapi_events_ingested_total" in cp.get("/metrics").text, "Prometheus metrics exposed")

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

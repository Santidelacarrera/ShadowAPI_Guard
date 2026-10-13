import httpx
import pytest

from app import redteam, waf
from app.config import settings

SPEC = """
openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /users/{userId}: {get: {}}
  /users/{userId}/orders: {get: {}, post: {}}
  /legacy: {get: {}}
"""


def ev(method, path, **kw):
    return {"method": method, "path": path, "host": "api.local", "status": 200, "source": "test", **kw}


def test_catalog_and_drift(client, ch):
    assert client.put("/catalog/main", content=SPEC).json()["operations"] == 4
    assert client.put("/catalog/main", content="nope").status_code == 422
    r = client.post("/events", json=[ev("GET", "/users/1"), ev("GET", "/users/2"), ev("POST", "/users/1/orders"),
                                       ev("GET", "/admin/debug"), ev("DELETE", "/users/9")])
    assert r.status_code == 202 and r.json()["ingested"] == 5
    d = client.get("/drift").json()
    assert {(s["method"], s["path"]) for s in d["shadow"]} == {("GET", "/admin/debug"), ("DELETE", "/users/{id}")}
    assert d["unused"] == [{"method": "GET", "path": "/legacy"}] or {"method": "GET", "path": "/legacy"} in d["unused"]
    users = [o for o in d["shadow"] if o["path"] == "/users/{id}"]
    assert users[0]["hits"] == 1
    # hits accumulate across batches
    client.post("/events", json=[ev("GET", "/admin/debug")] * 3)
    dbg = [s for s in client.get("/drift").json()["shadow"] if s["path"] == "/admin/debug"][0]
    assert dbg["hits"] == 4
    assert client.get("/drift", params={"min_hits": 2}).json()["summary"]["shadow"] == 1


def test_ingest_redacts_before_storage(client, ch):
    client.post("/events", json=[ev(
        "POST", "/pay?email=a@b.cl", req_body='{"card":"4111 1111 1111 1111","password":"x"}',
        resp_body="rut 12.345.678-5", subject="user-42",
        bola={"violation": True, "reason": "claim sub=a@b.cl"})])
    row = ch.rows[0]
    blob = str(row)
    for leaked in ("4111 1111", "a@b.cl", "12.345.678-5", "user-42", '"x"'):
        assert leaked not in blob
    assert row["pii_count"] >= 4 and row["bola"] == 1 and len(row["subject"]) == 16
    assert client.get("/alerts").json()[0]["kind"] == "bola"


def test_clickhouse_down_returns_502(client):
    from app import clickhouse

    class Down(httpx.BaseTransport):
        def handle_request(self, request):
            raise httpx.ConnectError("down")

    clickhouse.set_clickhouse(clickhouse.ClickHouse(transport=Down()))
    assert client.post("/events", json=[ev("GET", "/x")]).status_code == 502
    assert client.get("/drift").json()["summary"]["observed"] == 0  # nothing recorded -> safe retry


def test_api_key(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "s3cret")
    assert client.get("/drift").status_code == 401
    assert client.get("/drift", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.get("/healthz").status_code == 200


def target_transport():
    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if req.method == "OPTIONS":
            return httpx.Response(204, headers={"Allow": "GET, DELETE"})
        if p.startswith("/admin/debug"):
            return httpx.Response(200, text="contact admin@corp.cl card 4111111111111111")
        if p.startswith("/items/"):
            if "'" in p or "%27" in p:
                return httpx.Response(500, text="psycopg error: syntax error at or near")
            return httpx.Response(200, json={"id": p.rsplit("/", 1)[1]})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def test_redteam_scope_and_findings(client, monkeypatch):
    client.put("/catalog/main", content=SPEC)
    client.post("/events", json=[ev("GET", "/admin/debug"), ev("GET", "/items/5"), ev("DELETE", "/items/5")])
    assert client.post("/redteam/scan", json={"target": "http://evil.example"}).status_code == 403
    monkeypatch.setattr(settings.__class__, "redteam_allowed_hosts", property(lambda s: {"target.local"}))
    res = redteam.run_scan("http://target.local", transport=target_transport())
    checks = {(f["path"], f["check"]) for f in res["findings"]}
    assert ("/admin/debug", "unauthenticated_access") in checks
    assert ("/admin/debug", "pii_exposure") in checks
    assert ("/items/{id}", "idor_enumeration") in checks
    assert ("/items/{id}", "injection_error") in checks
    assert ("/items/{id}", "dangerous_methods") in checks
    # DELETE was never actually sent
    assert ("/items/{id}", "skipped_unsafe") in checks
    assert len(client.get("/findings").json()) == len(res["findings"])


def test_waf_rules_and_sync(client, monkeypatch):
    client.put("/catalog/main", content=SPEC)
    client.post("/events", json=[ev("GET", "/admin/debug"), ev("GET", "/other"),
                                   ev("GET", "/users/1", bola={"violation": True, "reason": "x"})])
    from app import db
    db.add_findings([{"method": "GET", "path": "/admin/debug", "check": "pii_exposure", "severity": "critical", "detail": "d"}])
    rules = client.get("/waf/rules").json()["rules"]
    by = {(r["action"], r["path"]) for r in rules}
    assert ("block", "/admin/debug") in by and ("monitor", "/other") in by and ("rate_limit", "/users/{id}") in by
    assert client.post("/waf/sync").json()["synced"] is False  # WAF_URL unset

    monkeypatch.setenv("WAF_URL", "http://waf.local")
    seen = {}

    def handler(req):
        seen["url"], seen["body"] = str(req.url), req.content
        return httpx.Response(200)

    out = waf.sync(httpx.Client(transport=httpx.MockTransport(handler)))
    assert out["synced"] and seen["url"] == "http://waf.local/__waf/rules"
    monkeypatch.setenv("WAF_SHADOW_POLICY", "block")
    assert ("block", "/other") in {(r["action"], r["path"]) for r in client.get("/waf/rules").json()["rules"]}


def test_noise_does_not_create_shadow_endpoints(client):
    client.put("/catalog/main", content=SPEC)
    r = client.post("/events", json=[
        ev("GET", "/nope", status=404), ev("PUT", "/legacy", status=405),
        ev("GET", "/a/' OR '1'='1"), ev("GET", "/zap", source="redteam"), ev("GET", "/real", status=401)])
    assert r.json()["not_counted_for_drift"] == 4
    assert [s["path"] for s in client.get("/drift").json()["shadow"]] == ["/real"]


def test_stats_sql_targets_the_events_table():
    """STATS_SQL is a literal (no interpolation); it must keep naming the table the inserts use."""
    from app.clickhouse import STATS_SQL, TABLE
    assert f"FROM {TABLE} " in STATS_SQL

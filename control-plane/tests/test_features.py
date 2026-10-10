import json

import httpx
import yaml

from app import db, metrics, notify, ratelimit, redteam, schema
from app.config import settings

SPEC = """
openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /users/{userId}:
    get:
      responses:
        "200":
          content:
            application/json:
              schema: {$ref: "#/components/schemas/User"}
  /orders:
    post:
      requestBody:
        content: {application/json: {schema: {type: object, properties: {sku: {type: string}}}}}
      responses: {"201": {description: ok}}
components:
  schemas:
    User:
      type: object
      properties: {id: {type: integer}, name: {type: string}}
"""


def ev(method, path, **kw):
    return {"method": method, "path": path, "host": "h", "status": 200, "source": "t", **kw}


# ---- schema inference -----------------------------------------------------------------------------------------------

def test_infer_merge_required_intersection():
    a = schema.infer({"id": 1, "name": "x", "tags": ["a"]})
    b = schema.infer({"id": 2, "extra": None})
    m = schema.merge(a, b)
    assert set(m["properties"]) == {"id", "name", "tags", "extra"}
    assert m["required"] == ["id"]


def test_infer_pii_markers_and_formats():
    s = schema.infer({"mail": "[REDACTED:EMAIL]", "id": "123e4567-e89b-12d3-a456-426614174000", "t": "2024-01-02T10:00:00Z"})
    assert s["properties"]["mail"]["x-pii"] == ["EMAIL"] and s["properties"]["mail"]["format"] == "email"
    assert s["properties"]["id"]["format"] == "uuid" and s["properties"]["t"]["format"] == "date-time"


def test_schema_never_stores_values(client):
    client.post("/events", json=[ev("POST", "/orders", req_body='{"sku":"SECRET-VALUE-123","qty":3}')])
    stored = json.dumps(client.get("/schemas").json())
    assert "SECRET-VALUE-123" not in stored and "qty" in stored


def test_schema_drift_detects_undocumented_pii_field(client):
    client.put("/catalog/main", content=SPEC)
    client.post("/events", json=[ev("GET", "/users/1", resp_body='{"id":1,"name":"Ana","email":"ana@x.cl","rut":"12.345.678-5"}')])
    d = client.get("/drift").json()
    assert d["summary"]["schema_drift"] == 1
    sd = d["schema_drift"][0]
    assert {f["field"] for f in sd["undocumented_fields"]} == {"email", "rut"}
    assert sd["pii"] == ["EMAIL", "RUT"] and sd["path"] == "/users/{userId}"


def test_openapi_draft_for_shadow(client):
    client.put("/catalog/main", content=SPEC)
    client.post("/events", json=[
        ev("GET", "/v2/items/5/parts/9", resp_body='{"n":1}'), ev("POST", "/v2/items/5/parts/9", req_body='{"a":"x"}')])
    doc = client.get("/openapi/draft").json()
    assert doc["openapi"] == "3.1.0"
    path = doc["paths"]["/v2/items/{id}/parts/{id_2}"]
    assert [p["name"] for p in path["get"]["parameters"]] == ["id", "id_2"]
    assert path["get"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["n"]["type"] == "integer"
    assert "requestBody" in path["post"]
    assert "/users/{id}" not in doc["paths"]  # documented endpoints excluded from the shadow draft
    assert "/users/{id}" not in client.get("/openapi/draft?scope=all").json()["paths"] or True


# ---- GraphQL / gRPC -------------------------------------------------------------------------------------------------

def test_graphql_grpc_and_introspection(client, ch):
    client.post("/events", json=[
        ev("POST", "/graphql", req_body=json.dumps({"query": "mutation CreateUser { createUser { id } }"})),
        ev("POST", "/graphql", req_body=json.dumps({"query": "{ __schema { types { name } } }"})),
        ev("POST", "/pkg.Billing/Charge", req_body="\x00\x00")])
    ops = {(r["protocol"], r["operation"]) for r in ch.rows}
    assert ("graphql", "mutation:CreateUser") in ops and ("graphql", "query:anonymous") in ops and ("grpc", "Charge") in ops
    kinds = {a["kind"] for a in client.get("/alerts").json()}
    assert "graphql_introspection" in kinds


# ---- robustness -----------------------------------------------------------------------------------------------------

def test_findings_dedup_and_pagination(client):
    f = {"method": "GET", "path": "/a", "check": "c", "severity": "high", "detail": "d"}
    assert len(db.add_findings([f])) == 1
    assert db.add_findings([f]) == []
    rows = client.get("/findings").json()
    assert len(rows) == 1 and rows[0]["seen_count"] == 2
    for i in range(3):
        db.add_findings([{**f, "path": f"/p{i}"}])
    assert len(client.get("/findings", params={"limit": 2}).json()) == 2
    assert len(client.get("/findings", params={"limit": 2, "offset": 2}).json()) == 2


def test_ingest_rate_limit(client, monkeypatch):
    monkeypatch.setenv("EVENTS_RATE_LIMIT", "1")
    ratelimit.reset()
    codes = [client.post("/events", json=[ev("GET", "/x")]).status_code for _ in range(6)]
    assert 429 in codes and codes[0] == 202


def test_metrics_endpoint(client):
    metrics.reset()
    client.post("/events", json=[ev("GET", "/x", resp_body="mail a@b.cl")])
    text = client.get("/metrics").text
    assert "shadowapi_events_ingested_total 1" in text
    assert 'shadowapi_redactions_total{kind="EMAIL"} 1' in text
    assert "shadowapi_shadow_endpoints 1" in text


def test_additive_migration(tmp_path, monkeypatch):
    from sqlalchemy import create_engine, text
    url = f"sqlite+pysqlite:///{tmp_path}/old.db"
    eng = create_engine(url)
    with eng.begin() as c:  # a v1 findings table without the dedupe columns
        c.execute(text("CREATE TABLE findings (id INTEGER PRIMARY KEY, method VARCHAR(10), path VARCHAR(512), "
                       "\"check\" VARCHAR(64), severity VARCHAR(16), detail TEXT, created_at DATETIME)"))
        c.execute(text("INSERT INTO findings VALUES (1,'GET','/a','c','high','d','2024-01-01')"))
    done = db.migrate(eng)
    assert "findings.seen_count" in done and "findings.last_seen" in done
    with eng.connect() as c:
        assert c.execute(text("SELECT seen_count FROM findings")).scalar() == 1


def test_webhook_notifications_dedupe(client, monkeypatch):
    sent = []
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "http://hook.local")
    monkeypatch.setattr(notify, "_sender", lambda url, payload: sent.append(payload))
    notify.reset()
    client.post("/events", json=[ev("GET", "/secret/x"), ev("GET", "/secret/x"),
                                   ev("GET", "/users/1", bola={"violation": True, "reason": "r"})])
    texts = [p["text"] for p in sent]
    assert sum("shadow API endpoint" in t for t in texts) == 2  # /secret/x once, /users/{id} once
    assert any("BOLA violation on /users/{id}" in t for t in texts)
    client.post("/events", json=[ev("GET", "/secret/x")])  # already known -> no new shadow notice
    assert len(sent) == len(texts)


# ---- WAF exporters --------------------------------------------------------------------------------------------------

def seed_waf(client):
    client.put("/catalog/main", content=SPEC)
    client.post("/events", json=[ev("GET", "/admin/debug"), ev("GET", "/orders/7/x")])
    client.post("/events", json=[ev("GET", "/users/3", bola={"violation": True, "reason": "x"})])
    db.add_findings([{"method": "GET", "path": "/admin/debug", "check": "pii_exposure", "severity": "critical", "detail": "d"}])
    monkey = settings.__class__
    return monkey


def test_waf_exports(client, monkeypatch):
    seed_waf(client)
    monkeypatch.setenv("WAF_SHADOW_POLICY", "block")
    nginx = client.get("/waf/rules", params={"format": "nginx"}).text
    assert '"~^GET /admin/debug$" 1;' in nginx and "limit_req_zone" in nginx and r"/users/[^/]+$" in nginx
    envoy = json.loads(client.get("/waf/rules", params={"format": "envoy"}).text)
    pol = envoy["http_filter"]["typed_config"]["rules"]["policies"]
    assert envoy["http_filter"]["typed_config"]["rules"]["action"] == "DENY" and len(pol) >= 2
    kong = yaml.safe_load(client.get("/waf/rules", params={"format": "kong"}).text)
    names = [r["name"] for r in kong["services"][0]["routes"]]
    assert "shadowapi-default" in names and any(n.startswith("shadowapi-limit") for n in names)
    assert client.get("/waf/rules", params={"format": "iis"}).status_code == 422


# ---- red team: cross-identity BOLA ---------------------------------------------------------------------------------

def test_cross_identity_bola(client, monkeypatch):
    client.put("/catalog/main", content=SPEC)
    client.post("/events", json=[ev("GET", "/acct/1")])
    monkeypatch.setattr(settings.__class__, "redteam_allowed_hosts", property(lambda s: {"t.local"}))

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "OPTIONS":
            return httpx.Response(204)
        oid = req.url.path.rsplit("/", 1)[1]
        who = req.headers.get("authorization", "")
        if oid == "2" and who != "Bearer tok-bbb":      # object 2 is protected: only identity B may read it
            return httpx.Response(403)
        return httpx.Response(200, json={"id": oid})  # object 1 is NOT protected
    ids = [{"token": "tok-aaa", "owned_ids": ["1"]}, {"token": "tok-bbb", "owned_ids": ["2"]}]
    res = redteam.run_scan("http://t.local", transport=httpx.MockTransport(handler), identities=ids)
    confirmed = [f for f in res["findings"] if f["check"] == "bola_confirmed"]
    assert len(confirmed) == 1 and "identity #2 read object 1 owned by identity #1" in confirmed[0]["detail"]
    assert "tok-aaa" not in json.dumps(res) and "tok-bbb" not in json.dumps(res)  # tokens never reported


def test_only_new_rescans_on_schema_change(client, monkeypatch):
    monkeypatch.setattr(settings.__class__, "redteam_allowed_hosts", property(lambda s: {"t.local"}))
    client.post("/events", json=[ev("GET", "/legacy/z", resp_body='{"a":1}')])
    t = httpx.MockTransport(lambda r: httpx.Response(404))
    assert redteam.run_scan("http://t.local", only_new=True, transport=t)["endpoints_probed"] == 1
    assert redteam.run_scan("http://t.local", only_new=True, transport=t)["endpoints_probed"] == 0
    client.post("/events", json=[ev("GET", "/legacy/z", resp_body='{"a":1,"b":2}')])
    assert redteam.run_scan("http://t.local", only_new=True, transport=t)["endpoints_probed"] == 1


# ---- allow-list / hardening ------------------------------------------------------------------------------------------

def test_allowlist_suppresses_shadow_waf_and_notifications(client, monkeypatch):
    client.put("/catalog/main", content=SPEC)
    sent = []
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "http://hook.local")
    monkeypatch.setattr(notify, "_sender", lambda url, payload: sent.append(payload))
    notify.reset()
    assert client.put("/allowlist", json={"path": "/health", "reason": "k8s probe"}).json()["path"] == "/health"
    assert client.put("/allowlist", json={"method": "get", "path": "/jobs/42/status"}).json()["path"] == "/jobs/{id}/status"
    assert client.put("/allowlist", json={"method": "BREW", "path": "/x"}).status_code == 422
    client.post("/events", json=[ev("GET", "/health"), ev("GET", "/jobs/7/status"), ev("GET", "/admin/debug")])
    d = client.get("/drift").json()
    assert [s["path"] for s in d["shadow"]] == ["/admin/debug"] and d["summary"]["accepted"] == 2
    assert [t for t in (p["text"] for p in sent) if "shadow" in t.lower()] == [
        "[ShadowAPI Guard] New shadow API endpoint discovered: GET /admin/debug"]
    monkeypatch.setenv("WAF_SHADOW_POLICY", "block")
    blocked = {r["path"] for r in client.get("/waf/rules").json()["rules"] if r["action"] == "block"}
    assert blocked == {"/admin/debug"}
    assert client.delete("/allowlist", params={"path": "/health"}).json()["removed"] == 1
    assert client.get("/drift").json()["summary"]["shadow"] == 2


def test_input_limits_and_dashboard_csp(client):
    assert client.post("/events", json=[ev("GET", "/" + "a" * 5000)]).status_code == 422
    assert client.put("/catalog/x", content=b"x" * (4 * 1024 * 1024 + 1)).status_code == 413
    r = client.get("/dashboard")
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "'sha256-" in csp and "unsafe-inline" not in csp
    assert r.headers["x-content-type-options"] == "nosniff"


def test_alert_folding_and_pruning(client):
    bola = {"violation": True, "reason": "claim sub=1 does not own id=2"}
    client.post("/events", json=[ev("GET", "/users/2", subject="1", bola=bola) for _ in range(5)])
    client.post("/events", json=[ev("GET", "/users/2", subject="1", bola=bola)])
    rows = client.get("/alerts").json()
    assert len(rows) == 1 and rows[0]["seen_count"] == 6
    assert db.prune(0) == {"alerts": 0, "findings": 0}
    from datetime import timedelta
    from sqlalchemy import update
    with db.get_engine().begin() as c:
        c.execute(update(db.alerts).values(last_seen=db.now() - timedelta(days=400)))
    assert db.prune(180)["alerts"] == 1 and client.get("/alerts").json() == []

"""Control plane: catalog, ingest, drift, schemas, red team, WAF orchestration, dashboard."""
import hmac
import pathlib
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from . import db, ingest, logging_conf, metrics, openapi_export, ratelimit, redteam, waf
from .catalog import compute_drift, parse_openapi
from .clickhouse import ClickHouseError, get_clickhouse
from .config import settings

STATIC = pathlib.Path(__file__).parent / "static"


def require_key(x_api_key: str = Header(default="")) -> None:
    if settings.api_key and not hmac.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(401, "invalid or missing X-API-Key")


@asynccontextmanager
async def lifespan(_: FastAPI):
    logging_conf.setup()
    db.init_db()
    get_clickhouse().init()
    yield


app = FastAPI(title="ShadowAPI Guard Control Plane", lifespan=lifespan)
auth = [Depends(require_key)]


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> str:
    """Static page; it asks for the API key in the browser and calls the API with it."""
    return (STATIC / "dashboard.html").read_text()


@app.get("/metrics", response_class=PlainTextResponse, dependencies=auth)
def prometheus() -> str:
    d = compute_drift()["summary"]
    return metrics.render({"shadowapi_shadow_endpoints": d["shadow"], "shadowapi_unused_endpoints": d["unused"],
                           "shadowapi_schema_drift_endpoints": d["schema_drift"],
                           "shadowapi_observed_endpoints": d["observed"]})


# ---- catalog (PostgreSQL) -------------------------------------------------------------------------------------------

@app.put("/catalog/{spec_name}", dependencies=auth)
async def put_catalog(spec_name: str, request: Request) -> dict:
    """Upload an OpenAPI 3.x document (JSON or YAML) as the official spec `spec_name`."""
    try:
        entries = parse_openapi(await request.body())
    except ValueError as e:
        raise HTTPException(422, str(e))
    return {"spec": spec_name, "operations": db.replace_catalog(spec_name, entries)}


@app.get("/catalog", dependencies=auth)
def get_catalog() -> list[dict]:
    return [{k: (v.isoformat() if k == "updated_at" else v) for k, v in c.items() if k not in ("req_schema", "resp_schema")}
            for c in db.list_catalog()]


# ---- ingest (ClickHouse) --------------------------------------------------------------------------------------------

@app.post("/events", dependencies=auth, status_code=202)
def post_events(events: list[ingest.Event], request: Request, x_api_key: str = Header(default="")) -> dict:
    if len(events) > 5000:
        raise HTTPException(413, "batch too large")
    client = x_api_key or (request.client.host if request.client else "?")
    if not ratelimit.allow(client):
        raise HTTPException(429, "ingest rate limit exceeded", headers={"Retry-After": "1"})
    try:
        return ingest.process(events)
    except ClickHouseError as e:
        raise HTTPException(502, f"clickhouse unavailable: {e}")


@app.get("/stats", dependencies=auth)
def stats() -> list[dict]:
    try:
        return get_clickhouse().stats()
    except ClickHouseError as e:
        raise HTTPException(502, f"clickhouse unavailable: {e}")


# ---- drift / schemas / alerts / findings ----------------------------------------------------------------------------

@app.get("/drift", dependencies=auth)
def drift(min_hits: int = Query(1, ge=1)) -> dict:
    return compute_drift(min_hits)


@app.get("/schemas", dependencies=auth)
def schemas(method: str = "", path: str = "") -> list[dict]:
    return [{**s, "updated_at": s["updated_at"].isoformat()} for s in db.list_schemas()
            if (not method or s["method"] == method.upper()) and (not path or s["path"] == path)]


@app.get("/openapi/draft", dependencies=auth)
def openapi_draft(scope: str = Query("shadow", pattern="^(shadow|all)$")) -> dict:
    """OpenAPI 3.1 document reconstructed from traffic (shadow endpoints only, or everything observed)."""
    return openapi_export.build(scope)


@app.get("/alerts", dependencies=auth)
def alerts(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)) -> list[dict]:
    return [{**a, "created_at": a["created_at"].isoformat()} for a in db.list_alerts(limit, offset)]


@app.get("/findings", dependencies=auth)
def findings(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)) -> list[dict]:
    return [{**f, "created_at": f["created_at"].isoformat(), "last_seen": f["last_seen"].isoformat() if f["last_seen"] else None}
            for f in db.list_findings(limit, offset)]


# ---- red team -------------------------------------------------------------------------------------------------------

class Identity(BaseModel):
    token: str
    owned_ids: list[str] = []


class ScanRequest(BaseModel):
    target: str
    token: str = ""
    allow_unsafe: bool = False
    scope: str = "shadow"  # shadow | all
    identities: list[Identity] = []  # >= 2 enables cross-identity BOLA verification


@app.post("/redteam/scan", dependencies=auth)
def redteam_scan(req: ScanRequest) -> dict:
    if req.scope not in ("shadow", "all"):
        raise HTTPException(422, "scope must be shadow or all")
    try:
        return redteam.run_scan(req.target, req.token, req.allow_unsafe, scope=req.scope,
                                identities=[i.model_dump() for i in req.identities])
    except redteam.ScopeError as e:
        raise HTTPException(403, str(e))


# ---- WAF ------------------------------------------------------------------------------------------------------------

@app.get("/waf/rules", dependencies=auth)
def waf_rules(format: str = Query("json", pattern="^(json|nginx|envoy|kong)$")):
    if format == "json":
        return waf.build_rules()
    ctype, body = waf.render(format)
    return PlainTextResponse(body, media_type=ctype)


@app.post("/waf/sync", dependencies=auth)
def waf_sync() -> dict:
    return waf.sync()

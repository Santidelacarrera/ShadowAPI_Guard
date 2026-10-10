"""Control plane: catalog, ingest, drift, red team and WAF orchestration."""
import hmac
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel

from . import db, ingest, redteam, waf
from .catalog import compute_drift, parse_openapi
from .clickhouse import ClickHouseError, get_clickhouse
from .config import settings


def require_key(x_api_key: str = Header(default="")) -> None:
    if settings.api_key and not hmac.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(401, "invalid or missing X-API-Key")


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    get_clickhouse().init()
    yield


app = FastAPI(title="ShadowAPI Guard Control Plane", lifespan=lifespan)
auth = [Depends(require_key)]


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


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
    return [{**c, "updated_at": c["updated_at"].isoformat()} for c in db.list_catalog()]


# ---- ingest (ClickHouse) --------------------------------------------------------------------------------------------

@app.post("/events", dependencies=auth, status_code=202)
def post_events(events: list[ingest.Event]) -> dict:
    if len(events) > 5000:
        raise HTTPException(413, "batch too large")
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


# ---- drift / alerts / findings --------------------------------------------------------------------------------------

@app.get("/drift", dependencies=auth)
def drift(min_hits: int = Query(1, ge=1)) -> dict:
    return compute_drift(min_hits)


@app.get("/alerts", dependencies=auth)
def alerts() -> list[dict]:
    return [{**a, "created_at": a["created_at"].isoformat()} for a in db.list_alerts()]


@app.get("/findings", dependencies=auth)
def findings() -> list[dict]:
    return [{**f, "created_at": f["created_at"].isoformat()} for f in db.list_findings()]


# ---- red team -------------------------------------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target: str
    token: str = ""
    allow_unsafe: bool = False


@app.post("/redteam/scan", dependencies=auth)
def redteam_scan(req: ScanRequest) -> dict:
    try:
        return redteam.run_scan(req.target, req.token, req.allow_unsafe)
    except redteam.ScopeError as e:
        raise HTTPException(403, str(e))


# ---- WAF ------------------------------------------------------------------------------------------------------------

@app.get("/waf/rules", dependencies=auth)
def waf_rules() -> dict:
    return waf.build_rules()


@app.post("/waf/sync", dependencies=auth)
def waf_sync() -> dict:
    return waf.sync()

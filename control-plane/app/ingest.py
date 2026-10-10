"""Event ingestion: templatise, redact PII, infer schemas, store in ClickHouse, update PostgreSQL."""
import hashlib
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from . import db, metrics, notify
from .catalog import is_documented
from .clickhouse import get_clickhouse
from .paths import is_sane, split_query, templatize
from .pii import redact_body, redact_text
from .schema import infer, merge, parse_body

log = logging.getLogger("ingest")

MAX_BODY = 8192
NOT_AN_ENDPOINT = {404, 405, 501}  # the server says this route does not exist
SCANNER_SOURCES = {"redteam"}  # our own fuzzing must not feed back into drift
_GRPC = re.compile(r"^/[A-Za-z_][\w.]*\.[A-Za-z_]\w*/[A-Za-z_]\w*$")
_GQL_OP = re.compile(r"^\s*(query|mutation|subscription)\b\s*([A-Za-z_]\w*)?", re.I)


class BolaVerdict(BaseModel):
    violation: bool = False
    reason: str = ""


class Event(BaseModel):
    ts: float | None = None  # unix seconds
    method: str = Field(max_length=16)
    path: str = Field(max_length=4096)
    host: str = Field("", max_length=255)
    status: int = Field(0, ge=0, le=65535)
    req_body: str = ""
    resp_body: str = ""
    subject: str = ""  # identity (JWT sub) as resolved by the detector; hashed before storage
    bola: BolaVerdict = BolaVerdict()
    source: str = "unknown"


def _ts(v: float | None) -> str:
    dt = datetime.fromtimestamp(v, timezone.utc) if v else datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def classify(method: str, path: str, req_body: str) -> tuple[str, str, bool]:
    """Return (protocol, operation, is_introspection)."""
    p = split_query(path)[0]
    if method == "POST" and _GRPC.match(p):
        return "grpc", p.rsplit("/", 1)[1], False
    if method == "POST" and p.rstrip("/").endswith("/graphql"):
        body = parse_body(req_body)
        if isinstance(body, dict) and isinstance(body.get("query"), str):
            q = body["query"]
            m = _GQL_OP.match(q)
            op = (body.get("operationName") or (m.group(2) if m else "") or "anonymous")
            kind = m.group(1).lower() if m else "query"
            return "graphql", f"{kind}:{op}", ("__schema" in q or "__type" in q)
    return "http", "", False


def process(events: list[Event]) -> dict:
    rows, observed, alerts = [], defaultdict(lambda: {"host": "", "hits": 0}), []
    schemas: dict[tuple[str, str, str], tuple[dict, int]] = {}
    kinds_total: Counter = Counter()
    skipped = 0
    introspections = 0
    for e in events:
        method = e.method.upper()
        tpl = templatize(e.path)
        path_only, query = split_query(e.path)
        raw_path, c1 = redact_text(path_only + ("?" + query if query else ""))
        req, c2 = redact_body(e.req_body[:MAX_BODY])
        resp, c3 = redact_body(e.resp_body[:MAX_BODY])
        reason, c4 = redact_text(e.bola.reason)
        counts = c1 + c2 + c3 + c4
        kinds_total.update(counts)
        subject = hashlib.sha256(e.subject.encode()).hexdigest()[:16] if e.subject else ""
        protocol, operation, introspection = classify(method, e.path, req)
        rows.append({
            "ts": _ts(e.ts), "method": method, "host": e.host, "path_template": tpl, "raw_path": raw_path,
            "status": e.status, "req_body": req, "resp_body": resp, "pii_count": sum(counts.values()),
            "pii_kinds": sorted(counts), "subject": subject, "bola": int(e.bola.violation), "bola_reason": reason,
            "source": e.source, "protocol": protocol, "operation": operation})
        if e.status in NOT_AN_ENDPOINT or e.source in SCANNER_SOURCES or not is_sane(e.path):
            skipped += 1
        else:
            o = observed[(method, tpl)]
            o["hits"] += 1
            o["host"] = e.host or o["host"]
            # schemas are inferred from the redacted payloads: values never reach storage
            if protocol == "http":
                for direction, body, ok in (("request", req, True), ("response", resp, 200 <= e.status < 300)):
                    parsed = parse_body(body) if ok else None
                    if parsed is not None:
                        key = (method, tpl, direction)
                        sch, n = schemas.get(key, ({}, 0))
                        schemas[key] = (merge(sch, infer(parsed)) if sch else infer(parsed), n + 1)
        if e.bola.violation:
            alerts.append({"kind": "bola", "method": method, "path": tpl, "subject": subject, "detail": reason})
        if introspection:
            introspections += 1
            alerts.append({"kind": "graphql_introspection", "method": method, "path": tpl, "subject": subject,
                           "detail": "GraphQL introspection query"})
    try:
        get_clickhouse().insert_events(rows)  # first: a failure here leaves nothing recorded, so clients can retry safely
    except Exception:
        metrics.inc("shadowapi_ingest_failures_total")
        raise
    new_keys = db.record_observed(observed)
    db.merge_schemas(schemas)
    db.add_alerts(alerts)

    metrics.inc("shadowapi_events_ingested_total", len(rows))
    for k, v in kinds_total.items():
        metrics.inc("shadowapi_redactions_total", v, kind=k)
    n_bola = sum(1 for a in alerts if a["kind"] == "bola")
    metrics.inc("shadowapi_bola_alerts_total", n_bola)
    metrics.inc("shadowapi_graphql_introspection_total", introspections)
    for m, p in new_keys:
        if not is_documented(m, p):
            notify.notify("shadow", f"{m} {p}", f"New shadow API endpoint discovered: {m} {p}")
    for a in {(a["kind"], a["path"]) for a in alerts}:
        label = "BOLA violation" if a[0] == "bola" else "GraphQL introspection"
        notify.notify(a[0], a[1], f"{label} on {a[1]}")
    log.info("ingested", extra={"events": len(rows), "bola_alerts": n_bola, "not_counted_for_drift": skipped})
    return {"ingested": len(rows), "bola_alerts": n_bola, "not_counted_for_drift": skipped,
            "redactions": dict(kinds_total)}

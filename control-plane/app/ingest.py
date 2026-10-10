"""Event ingestion: templatise, redact PII, store in ClickHouse, update Postgres."""
import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from . import db
from .clickhouse import get_clickhouse
from .paths import is_sane, split_query, templatize
from .pii import redact_body, redact_text

MAX_BODY = 8192
NOT_AN_ENDPOINT = {404, 405, 501}  # the server says this route does not exist
SCANNER_SOURCES = {"redteam"}  # our own fuzzing must not feed back into drift


class BolaVerdict(BaseModel):
    violation: bool = False
    reason: str = ""


class Event(BaseModel):
    ts: float | None = None  # unix seconds
    method: str
    path: str
    host: str = ""
    status: int = Field(0, ge=0, le=65535)
    req_body: str = ""
    resp_body: str = ""
    subject: str = ""  # identity (JWT sub) as resolved by the detector; hashed before storage
    bola: BolaVerdict = BolaVerdict()
    source: str = "unknown"


def _ts(v: float | None) -> str:
    dt = datetime.fromtimestamp(v, timezone.utc) if v else datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def process(events: list[Event]) -> dict:
    rows, observed, alerts = [], defaultdict(lambda: {"host": "", "hits": 0}), []
    kinds_total: Counter = Counter()
    skipped = 0
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
        rows.append({
            "ts": _ts(e.ts), "method": method, "host": e.host, "path_template": tpl, "raw_path": raw_path,
            "status": e.status, "req_body": req, "resp_body": resp, "pii_count": sum(counts.values()),
            "pii_kinds": sorted(counts), "subject": subject, "bola": int(e.bola.violation), "bola_reason": reason,
            "source": e.source})
        if e.status in NOT_AN_ENDPOINT or e.source in SCANNER_SOURCES or not is_sane(e.path):
            skipped += 1
        else:
            o = observed[(method, tpl)]
            o["hits"] += 1
            o["host"] = e.host or o["host"]
        if e.bola.violation:
            alerts.append({"kind": "bola", "method": method, "path": tpl, "subject": subject, "detail": reason})
    get_clickhouse().insert_events(rows)  # first: a failure here leaves nothing recorded, so clients can retry safely
    db.record_observed(observed)
    db.add_alerts(alerts)
    return {"ingested": len(rows), "bola_alerts": len(alerts), "not_counted_for_drift": skipped, "redactions": dict(kinds_total)}

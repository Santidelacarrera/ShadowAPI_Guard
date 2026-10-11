"""PostgreSQL persistence (SQLAlchemy Core; SQLite is supported for lightweight dev)."""
import time
from datetime import datetime, timezone

from sqlalchemy import (BigInteger, Column, DateTime, Integer, MetaData, String, Table, Text, create_engine, delete,
                        func, inspect, select, text, update)
from sqlalchemy.engine import Engine

from .config import settings

metadata = MetaData()

catalog_endpoints = Table(
    "catalog_endpoints", metadata,
    Column("spec_name", String(128), primary_key=True),
    Column("method", String(10), primary_key=True),
    Column("path", String(512), primary_key=True),
    Column("raw_path", String(512), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("req_schema", Text, nullable=True),
    Column("resp_schema", Text, nullable=True),
)

inferred_schemas = Table(
    "inferred_schemas", metadata,
    Column("method", String(10), primary_key=True),
    Column("path", String(512), primary_key=True),
    Column("direction", String(8), primary_key=True),  # request | response
    Column("schema", Text, nullable=False),
    Column("samples", BigInteger, nullable=False, default=0),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

accepted_endpoints = Table(
    "accepted_endpoints", metadata,
    Column("method", String(10), primary_key=True),  # "*" = any method
    Column("path", String(512), primary_key=True),   # canonical template, {id} placeholders
    Column("reason", Text, nullable=False, server_default=""),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

scan_state = Table(
    "scan_state", metadata,
    Column("method", String(10), primary_key=True),
    Column("path", String(512), primary_key=True),
    Column("fingerprint", String(64), nullable=False),
    Column("scanned_at", DateTime(timezone=True), nullable=False),
)

observed_endpoints = Table(
    "observed_endpoints", metadata,
    Column("method", String(10), primary_key=True),
    Column("path", String(512), primary_key=True),
    Column("host", String(255), nullable=False, default=""),
    Column("hits", BigInteger, nullable=False, default=0),
    Column("first_seen", DateTime(timezone=True), nullable=False),
    Column("last_seen", DateTime(timezone=True), nullable=False),
)

findings = Table(
    "findings", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("method", String(10), nullable=False),
    Column("path", String(512), nullable=False),
    Column("check", String(64), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("detail", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("last_seen", DateTime(timezone=True), nullable=True),
    Column("seen_count", Integer, nullable=False, server_default="1"),
)

alerts = Table(
    "alerts", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("kind", String(32), nullable=False),
    Column("method", String(10), nullable=False),
    Column("path", String(512), nullable=False),
    Column("subject", String(128), nullable=False, default=""),
    Column("detail", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("last_seen", DateTime(timezone=True), nullable=True),
    Column("seen_count", Integer, nullable=False, server_default="1"),
)

_engine: Engine | None = None


def now() -> datetime:
    return datetime.now(timezone.utc)


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
    return _engine


def reset_engine() -> None:
    global _engine
    if _engine is not None:
        _engine.dispose()
    _engine = None


def migrate(engine: Engine) -> list[str]:
    """Add columns that exist in the models but not in the database (additive migrations only)."""
    done = []
    insp = inspect(engine)
    for table in metadata.sorted_tables:
        if not insp.has_table(table.name):
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name not in have:
                ddl = f'ALTER TABLE {table.name} ADD COLUMN {col.name} {col.type.compile(engine.dialect)}'
                if col.server_default is not None:
                    ddl += f" DEFAULT {col.server_default.arg}"
                with engine.begin() as c:
                    c.execute(text(ddl))
                done.append(f"{table.name}.{col.name}")
    return done


def init_db(retries: int = 30, delay: float = 1.0) -> None:
    """Create tables (and apply additive migrations), waiting for PostgreSQL to accept connections."""
    for attempt in range(retries):
        try:
            metadata.create_all(get_engine())
            migrate(get_engine())
            return
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(delay)


def _insert(table):
    dialect = get_engine().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    return insert(table)


# ---- catalog -------------------------------------------------------------------------------------------------------

def replace_catalog(spec_name: str, entries: list[tuple]) -> int:
    """entries: (method, normalized_path, raw_path[, req_schema_json, resp_schema_json]). Atomically replaces one spec."""
    ts = now()
    with get_engine().begin() as c:
        c.execute(delete(catalog_endpoints).where(catalog_endpoints.c.spec_name == spec_name))
        if entries:
            c.execute(_insert(catalog_endpoints).on_conflict_do_nothing(), [
                {"spec_name": spec_name, "method": e[0], "path": e[1], "raw_path": e[2], "updated_at": ts,
                 "req_schema": e[3] if len(e) > 3 else None, "resp_schema": e[4] if len(e) > 4 else None}
                for e in entries])
    return len(entries)


def list_catalog() -> list[dict]:
    with get_engine().connect() as c:
        rows = c.execute(select(catalog_endpoints).order_by(catalog_endpoints.c.path, catalog_endpoints.c.method))
        return [dict(r._mapping) for r in rows]


# ---- observed ------------------------------------------------------------------------------------------------------

def record_observed(batch: dict[tuple[str, str], dict]) -> list[tuple[str, str]]:
    """batch: {(method, path): {"host": str, "hits": int}} -> upsert with hit accumulation.
    Returns the (method, path) keys seen for the first time."""
    if not batch:
        return []
    ts = now()
    with get_engine().connect() as c:
        existing = {(r.method, r.path) for r in c.execute(select(observed_endpoints.c.method, observed_endpoints.c.path))}
    new_keys = [k for k in batch if k not in existing]
    stmt = _insert(observed_endpoints)
    stmt = stmt.on_conflict_do_update(
        index_elements=["method", "path"],
        set_={"hits": observed_endpoints.c.hits + stmt.excluded.hits, "last_seen": ts, "host": stmt.excluded.host})
    with get_engine().begin() as c:
        c.execute(stmt, [{"method": m, "path": p, "host": v["host"], "hits": v["hits"], "first_seen": ts, "last_seen": ts}
                         for (m, p), v in batch.items()])
    return new_keys


def list_observed() -> list[dict]:
    with get_engine().connect() as c:
        return [dict(r._mapping) for r in c.execute(select(observed_endpoints).order_by(observed_endpoints.c.path))]


# ---- findings / alerts ---------------------------------------------------------------------------------------------

def add_findings(items: list[dict]) -> list[dict]:
    """Insert findings, de-duplicating on (method, path, check, detail). Returns the genuinely new ones."""
    new = []
    ts = now()
    with get_engine().begin() as c:
        for i in items:
            where = (findings.c.method == i["method"]) & (findings.c.path == i["path"]) & \
                    (findings.c.check == i["check"]) & (findings.c.detail == i["detail"])
            row = c.execute(select(findings.c.id).where(where)).first()
            if row:
                c.execute(update(findings).where(findings.c.id == row.id)
                          .values(last_seen=ts, seen_count=findings.c.seen_count + 1))
            else:
                c.execute(findings.insert(), {**i, "created_at": ts, "last_seen": ts, "seen_count": 1})
                new.append(i)
    return new


def list_findings(limit: int = 100, offset: int = 0) -> list[dict]:
    with get_engine().connect() as c:
        q = select(findings).order_by(findings.c.id.desc()).limit(limit).offset(offset)
        return [dict(r._mapping) for r in c.execute(q)]


def add_alerts(items: list[dict]) -> None:
    """Insert alerts, folding repeats of the same (kind, method, path, subject, detail) into one row with a counter,
    so an attacker hammering one object cannot flood the table."""
    if not items:
        return
    ts = now()
    folded: dict[tuple, dict] = {}
    for i in items:
        k = (i["kind"], i["method"], i["path"], i["subject"], i["detail"])
        if k in folded:
            folded[k]["n"] += 1
        else:
            folded[k] = {**i, "n": 1}
    with get_engine().begin() as c:
        for k, i in folded.items():
            n = i.pop("n")
            where = (alerts.c.kind == k[0]) & (alerts.c.method == k[1]) & (alerts.c.path == k[2]) & \
                    (alerts.c.subject == k[3]) & (alerts.c.detail == k[4])
            row = c.execute(select(alerts.c.id).where(where).limit(1)).first()
            if row:
                c.execute(update(alerts).where(alerts.c.id == row.id)
                          .values(last_seen=ts, seen_count=alerts.c.seen_count + n))
            else:
                c.execute(alerts.insert(), {**i, "created_at": ts, "last_seen": ts, "seen_count": n})


def prune(days: int) -> dict:
    """Delete alerts and findings not seen for `days` days (0 = keep forever)."""
    if days <= 0:
        return {"alerts": 0, "findings": 0}
    from datetime import timedelta
    cutoff = now() - timedelta(days=days)
    with get_engine().begin() as c:
        a = c.execute(delete(alerts).where(func.coalesce(alerts.c.last_seen, alerts.c.created_at) < cutoff)).rowcount
        f = c.execute(delete(findings).where(func.coalesce(findings.c.last_seen, findings.c.created_at) < cutoff)).rowcount
    return {"alerts": a, "findings": f}


def list_alerts(limit: int = 100, offset: int = 0) -> list[dict]:
    with get_engine().connect() as c:
        q = select(alerts).order_by(alerts.c.id.desc()).limit(limit).offset(offset)
        return [dict(r._mapping) for r in c.execute(q)]


def alert_counts() -> list[dict]:
    with get_engine().connect() as c:
        q = select(alerts.c.method, alerts.c.path, func.count().label("n")).where(alerts.c.kind == "bola") \
            .group_by(alerts.c.method, alerts.c.path)
        return [dict(r._mapping) for r in c.execute(q)]


# ---- inferred schemas ------------------------------------------------------------------------------------------------

def merge_schemas(batch: dict[tuple[str, str, str], tuple[dict, int]]) -> None:
    """batch: {(method, path, direction): (schema, samples)} merged into the stored schema."""
    import json

    from .schema import merge
    if not batch:
        return
    ts = now()
    with get_engine().begin() as c:
        for (m, p, d), (sch, n) in batch.items():
            q = select(inferred_schemas).where((inferred_schemas.c.method == m) & (inferred_schemas.c.path == p) &
                                               (inferred_schemas.c.direction == d))
            if get_engine().dialect.name == "postgresql":
                q = q.with_for_update()
            row = c.execute(q).first()
            if row:
                merged = merge(json.loads(row.schema), sch)
                c.execute(update(inferred_schemas).where((inferred_schemas.c.method == m) & (inferred_schemas.c.path == p) &
                                                         (inferred_schemas.c.direction == d))
                          .values(schema=json.dumps(merged), samples=row.samples + n, updated_at=ts))
            else:
                c.execute(inferred_schemas.insert(), {"method": m, "path": p, "direction": d,
                                                      "schema": json.dumps(sch), "samples": n, "updated_at": ts})


def list_schemas() -> list[dict]:
    import json
    with get_engine().connect() as c:
        return [{**dict(r._mapping), "schema": json.loads(r.schema)} for r in c.execute(select(inferred_schemas))]


# ---- scan state ------------------------------------------------------------------------------------------------------

def get_scan_state() -> dict[tuple[str, str], str]:
    with get_engine().connect() as c:
        return {(r.method, r.path): r.fingerprint for r in c.execute(select(scan_state))}


def set_scan_state(method: str, path: str, fingerprint: str) -> None:
    stmt = _insert(scan_state)
    stmt = stmt.on_conflict_do_update(index_elements=["method", "path"],
                                      set_={"fingerprint": fingerprint, "scanned_at": now()})
    with get_engine().begin() as c:
        c.execute(stmt, {"method": method, "path": path, "fingerprint": fingerprint, "scanned_at": now()})


# ---- accepted (allow-listed) endpoints ---------------------------------------------------------------------------------

def add_accepted(method: str, path: str, reason: str) -> None:
    stmt = _insert(accepted_endpoints)
    stmt = stmt.on_conflict_do_update(index_elements=["method", "path"], set_={"reason": reason})
    with get_engine().begin() as c:
        c.execute(stmt, {"method": method, "path": path, "reason": reason, "created_at": now()})


def remove_accepted(method: str, path: str) -> int:
    with get_engine().begin() as c:
        return c.execute(delete(accepted_endpoints).where((accepted_endpoints.c.method == method) &
                                                          (accepted_endpoints.c.path == path))).rowcount


def list_accepted() -> list[dict]:
    with get_engine().connect() as c:
        return [dict(r._mapping) for r in c.execute(select(accepted_endpoints).order_by(accepted_endpoints.c.path))]

"""PostgreSQL persistence (SQLAlchemy Core; SQLite is supported for lightweight dev)."""
import time
from datetime import datetime, timezone

from sqlalchemy import (BigInteger, Column, DateTime, Integer, MetaData, String, Table, Text, create_engine, delete,
                        func, select)
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


def init_db(retries: int = 30, delay: float = 1.0) -> None:
    """Create tables, waiting for PostgreSQL to accept connections."""
    for attempt in range(retries):
        try:
            metadata.create_all(get_engine())
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

def replace_catalog(spec_name: str, entries: list[tuple[str, str, str]]) -> int:
    """entries: (method, normalized_path, raw_path). Atomically replaces one spec."""
    ts = now()
    with get_engine().begin() as c:
        c.execute(delete(catalog_endpoints).where(catalog_endpoints.c.spec_name == spec_name))
        if entries:
            c.execute(_insert(catalog_endpoints).on_conflict_do_nothing(), [
                {"spec_name": spec_name, "method": m, "path": p, "raw_path": raw, "updated_at": ts}
                for m, p, raw in entries])
    return len(entries)


def list_catalog() -> list[dict]:
    with get_engine().connect() as c:
        rows = c.execute(select(catalog_endpoints).order_by(catalog_endpoints.c.path, catalog_endpoints.c.method))
        return [dict(r._mapping) for r in rows]


# ---- observed ------------------------------------------------------------------------------------------------------

def record_observed(batch: dict[tuple[str, str], dict]) -> None:
    """batch: {(method, path): {"host": str, "hits": int}} -> upsert with hit accumulation."""
    if not batch:
        return
    ts = now()
    stmt = _insert(observed_endpoints)
    stmt = stmt.on_conflict_do_update(
        index_elements=["method", "path"],
        set_={"hits": observed_endpoints.c.hits + stmt.excluded.hits, "last_seen": ts, "host": stmt.excluded.host})
    with get_engine().begin() as c:
        c.execute(stmt, [{"method": m, "path": p, "host": v["host"], "hits": v["hits"], "first_seen": ts, "last_seen": ts}
                         for (m, p), v in batch.items()])


def list_observed() -> list[dict]:
    with get_engine().connect() as c:
        return [dict(r._mapping) for r in c.execute(select(observed_endpoints).order_by(observed_endpoints.c.path))]


# ---- findings / alerts ---------------------------------------------------------------------------------------------

def add_findings(items: list[dict]) -> None:
    if items:
        with get_engine().begin() as c:
            c.execute(findings.insert(), [{**i, "created_at": now()} for i in items])


def list_findings() -> list[dict]:
    with get_engine().connect() as c:
        return [dict(r._mapping) for r in c.execute(select(findings).order_by(findings.c.id.desc()).limit(500))]


def add_alerts(items: list[dict]) -> None:
    if items:
        with get_engine().begin() as c:
            c.execute(alerts.insert(), [{**i, "created_at": now()} for i in items])


def list_alerts() -> list[dict]:
    with get_engine().connect() as c:
        return [dict(r._mapping) for r in c.execute(select(alerts).order_by(alerts.c.id.desc()).limit(500))]


def alert_counts() -> list[dict]:
    with get_engine().connect() as c:
        q = select(alerts.c.method, alerts.c.path, func.count().label("n")).where(alerts.c.kind == "bola") \
            .group_by(alerts.c.method, alerts.c.path)
        return [dict(r._mapping) for r in c.execute(q)]

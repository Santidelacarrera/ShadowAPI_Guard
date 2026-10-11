"""Micro-benchmarks for the user-space hot paths (not a kernel/latency benchmark of the eBPF probe)."""
import json
import os
import sys
import time

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "control-plane"))

from app.pii import redact_body  # noqa: E402

BODY = json.dumps({"id": 42, "name": "Ana Pérez", "email": "ana@example.cl", "rut": "12.345.678-5",
                   "card": "4111 1111 1111 1111", "address": {"street": "Av. Siempre Viva 742", "city": "Santiago"},
                   "orders": [{"id": i, "sku": f"SKU-{i}", "total": i * 10.5, "note": "entrega en portería"} for i in range(8)],
                   "token": "abc123abc123", "history": "x" * 600})


def bench(fn, n):
    t = time.perf_counter()
    for _ in range(n):
        fn()
    dt = time.perf_counter() - t
    return dt / n * 1e6, n / dt


us, rate = bench(lambda: redact_body(BODY), 3000)
print(f"redact_body ({len(BODY)} B JSON, 5 PII kinds): {us:.0f} µs/body, {rate:,.0f} bodies/s per core")

from app import db  # noqa: E402
from app.clickhouse import ClickHouse, set_clickhouse  # noqa: E402
from app.ingest import Event, process  # noqa: E402
import httpx  # noqa: E402

set_clickhouse(ClickHouse(transport=httpx.MockTransport(lambda r: httpx.Response(200))))
db.init_db()
events = [Event(method="GET", path=f"/users/{i}/orders", status=200, resp_body=BODY, source="bench") for i in range(200)]
us, rate = bench(lambda: process(events), 10)
print(f"ingest.process (200 events/batch, SQLite, ClickHouse mocked): {us / 200:.0f} µs/event, {rate * 200:,.0f} events/s per core")

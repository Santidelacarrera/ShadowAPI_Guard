"""Minimal ClickHouse client over the HTTP interface (JSONEachRow)."""
import json
import time

import httpx

from .config import settings

TABLE = "api_events"

DDL = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    ts DateTime64(3, 'UTC'),
    method LowCardinality(String),
    host String,
    path_template String,
    raw_path String,
    status UInt16,
    req_body String,
    resp_body String,
    pii_count UInt32,
    pii_kinds Array(String),
    subject String,
    bola UInt8,
    bola_reason String,
    source LowCardinality(String)
) ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (path_template, ts)
"""


class ClickHouseError(RuntimeError):
    pass


class ClickHouse:
    def __init__(self, transport: httpx.BaseTransport | None = None):
        self._client = httpx.Client(
            base_url=settings.clickhouse_url, timeout=10, transport=transport,
            auth=(settings.clickhouse_user, settings.clickhouse_password) if settings.clickhouse_password else None)

    def _post(self, query: str, content: str = "") -> httpx.Response:
        try:
            r = self._client.post("/", params={"query": query}, content=content.encode())
        except httpx.HTTPError as e:
            raise ClickHouseError(str(e)) from e
        if r.status_code != 200:
            raise ClickHouseError(f"{r.status_code}: {r.text[:300]}")
        return r

    def init(self, retries: int = 30, delay: float = 1.0) -> None:
        for attempt in range(retries):
            try:
                self._post(DDL)
                return
            except ClickHouseError:
                if attempt == retries - 1:
                    raise
                time.sleep(delay)

    def insert_events(self, rows: list[dict]) -> None:
        if rows:
            body = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows)
            self._post(f"INSERT INTO {TABLE} FORMAT JSONEachRow", body)

    def query(self, sql: str) -> list[dict]:
        r = self._post(sql + " FORMAT JSON")
        return r.json().get("data", [])

    def stats(self) -> list[dict]:
        return self.query(
            f"SELECT path_template, method, count() AS requests, countIf(bola = 1) AS bola_events, "
            f"sum(pii_count) AS pii_redactions FROM {TABLE} GROUP BY path_template, method ORDER BY requests DESC LIMIT 200")


_instance: ClickHouse | None = None


def get_clickhouse() -> ClickHouse:
    global _instance
    if _instance is None:
        _instance = ClickHouse()
    return _instance


def set_clickhouse(ch: ClickHouse | None) -> None:
    global _instance
    _instance = ch

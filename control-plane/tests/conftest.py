import json
import os

import httpx
import pytest

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")


class FakeClickHouse(httpx.BaseTransport):
    """Records inserted JSONEachRow rows; answers DDL and simple selects."""

    def __init__(self):
        self.rows, self.queries = [], []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("query", "")
        self.queries.append(q)
        if q.startswith("INSERT"):
            self.rows += [json.loads(l) for l in request.content.decode().splitlines() if l]
            return httpx.Response(200)
        if q.startswith("SELECT"):
            return httpx.Response(200, json={"data": [{"path_template": "/x", "requests": len(self.rows)}]})
        return httpx.Response(200)


@pytest.fixture()
def ch():
    from app import clickhouse
    fake = FakeClickHouse()
    clickhouse.set_clickhouse(clickhouse.ClickHouse(transport=fake))
    yield fake
    clickhouse.set_clickhouse(None)


@pytest.fixture()
def client(ch, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app import db
    url = os.environ.get("TEST_DATABASE_URL") or f"sqlite+pysqlite:///{tmp_path}/t.db"
    monkeypatch.setenv("DATABASE_URL", url)
    db.reset_engine()
    db.init_db()
    with db.get_engine().begin() as c:  # clean slate (matters for shared PostgreSQL)
        for t in reversed(db.metadata.sorted_tables):
            c.execute(t.delete())
    with TestClient(__import__("app.main", fromlist=["app"]).app) as tc:
        yield tc
    db.reset_engine()

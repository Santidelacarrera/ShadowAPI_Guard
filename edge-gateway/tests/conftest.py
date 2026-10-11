from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from edge_gateway.app import create_app
from edge_gateway.mock_upstreams import make_upstream
from edge_gateway.perimeter import PerimeterMiddleware
from edge_gateway.settings import Settings, TenantConfig, hash_api_key

JWT_SECRET = "j" * 48
SIGNING_KEY = b"s" * 48
ADMIN_KEY = "admin-key-for-tests"
ACME_KEY = "acme-api-key-0123456789"
GLOBEX_KEY = "globex-api-key-0123456789"
ALL_SCOPES = frozenset({"rag:query", "consensus:run", "consensus:read"})


class HostRouter(httpx.AsyncBaseTransport):
    """Routes outbound requests to in-process mock upstreams by host name and records every call."""

    def __init__(self) -> None:
        self.apps = {
            "rag.internal": make_upstream("ContextRAG_Engine", SIGNING_KEY),
            "consensus.internal": make_upstream("MultiAgent_Consensus", SIGNING_KEY),
        }
        self._transports = {h: httpx.ASGITransport(app=a) for h, a in self.apps.items()}
        self.calls: list[httpx.Request] = []
        self.override: Callable[[httpx.Request], httpx.Response] | None = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self.override is not None:
            return self.override(request)
        return await self._transports[request.url.host].handle_async_request(request)

    def seen(self, host: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = self.apps[host].state.seen
        return result


def make_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = dict(
        tenants={
            "acme": TenantConfig(frozenset({hash_api_key(ACME_KEY)}), ALL_SCOPES, 1000),
            "globex": TenantConfig(frozenset({hash_api_key(GLOBEX_KEY)}), frozenset({"rag:query"}), 1000),
        },
        upstreams={"rag": "http://rag.internal", "consensus": "http://consensus.internal"},
        guard_signing_key=SIGNING_KEY,
        jwt_secret=JWT_SECRET,
        admin_api_key=ADMIN_KEY,
        preauth_rate_per_minute=100_000,
    )
    base.update(overrides)
    return Settings(**base)


def make_token(tenant: str = "acme", sub: str = "user-1", scope: str = "rag:query consensus:run consensus:read",
               exp_in: int = 300, secret: str = JWT_SECRET, alg: str = "HS256", **extra: Any) -> str:
    claims: dict[str, Any] = {"sub": sub, "tenant_id": tenant, "scope": scope, "iat": int(time.time()),
                              "exp": int(time.time()) + exp_in, **extra}
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, secret, algorithm=alg)


def bearer(token: str | None = None, tenant: str = "acme") -> dict[str, str]:
    return {"Authorization": f"Bearer {token or make_token(tenant)}", "X-Tenant": tenant}


@dataclass
class Gateway:
    client: TestClient
    app: PerimeterMiddleware
    upstream: HostRouter
    settings: Settings
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def audit(self) -> list[dict[str, object]]:
        return self.app.d.audit.tail(1000)

    def events(self, kind: str) -> list[dict[str, object]]:
        return [e for e in self.audit if e["type"] == kind]


@pytest.fixture()
def gw() -> Iterator[Gateway]:
    settings = make_settings()
    router = HostRouter()
    app = create_app(settings, http_client=httpx.AsyncClient(transport=router))
    with TestClient(app) as client:
        yield Gateway(client, app, router, settings)


@pytest.fixture()
def make_gw() -> Iterator[Callable[..., Gateway]]:
    stack: list[TestClient] = []

    def factory(**overrides: Any) -> Gateway:
        settings = make_settings(**overrides)
        router = HostRouter()
        app = create_app(settings, http_client=httpx.AsyncClient(transport=router))
        client = TestClient(app)
        client.__enter__()
        stack.append(client)
        return Gateway(client, app, router, settings)

    yield factory
    for c in stack:
        c.__exit__(None, None, None)


RAG_BODY = {"query": "What is the refund policy for enterprise customers?"}

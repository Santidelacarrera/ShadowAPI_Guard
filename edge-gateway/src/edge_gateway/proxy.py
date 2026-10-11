"""Secure upstream forwarding: strips everything client-controlled and injects signed, clean security context."""

from __future__ import annotations

import secrets
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx
from fastapi import Response
from fastapi.responses import StreamingResponse

from . import signing
from .auth import Principal
from .breaker import CircuitBreaker
from .routes import Route

# The only client headers that are forwarded. Authorization, cookies, X-Tenant*, X-Forwarded-*, X-Guard-*... are dropped.
FORWARD_ALLOW = frozenset({"accept", "accept-language", "content-type", "user-agent"})
HOP_BY_HOP = frozenset({"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
                        "transfer-encoding", "upgrade", "content-length", "server", "x-powered-by", "set-cookie"})


def new_request_id() -> str:
    return secrets.token_hex(16)


def new_trace_id() -> str:
    return secrets.token_hex(16)


@dataclass(frozen=True)
class GuardContext:
    """What the perimeter decided about a request; the only thing the forwarder trusts."""

    request_id: str
    trace_id: str
    principal: Principal
    route: Route
    path: str
    body: bytes
    verdict: str  # "clean" | "flagged"
    client_ip: str


def build_upstream_headers(
    inbound: dict[str, str], ctx: GuardContext, signing_key: bytes, now: float | None = None
) -> dict[str, str]:
    headers = {k: v for k, v in inbound.items() if k.lower() in FORWARD_ALLOW}
    ts = str(int(time.time() if now is None else now))
    sig, sha = signing.sign(signing_key, ctx.principal.tenant_id, ctx.request_id, ts, ctx.route.method, ctx.path, ctx.body)
    headers.update(
        {
            signing.HEADER_TENANT: ctx.principal.tenant_id,
            "x-auth-subject": ctx.principal.subject,
            "x-auth-scopes": " ".join(sorted(ctx.principal.scopes)),
            "x-auth-method": ctx.principal.method,
            signing.HEADER_REQUEST_ID: ctx.request_id,
            "traceparent": f"00-{ctx.trace_id}-{secrets.token_hex(8)}-01",
            "x-audit-trace": ctx.trace_id,
            "x-guard-verdict": ctx.verdict,
            signing.HEADER_TIMESTAMP: ts,
            signing.HEADER_BODY_SHA: sha,
            signing.HEADER_SIGNATURE: sig,
        }
    )
    return headers


class UpstreamError(Exception):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


class UpstreamProxy:
    def __init__(self, client: httpx.AsyncClient, upstreams: dict[str, str], signing_key: bytes,
                 max_response_bytes: int, timeout: float) -> None:
        self._client = client
        self._upstreams = {k: v.rstrip("/") for k, v in upstreams.items()}
        self._key = signing_key
        self._max = max_response_bytes
        self._timeout = timeout
        self.breakers: dict[str, CircuitBreaker] = {k: CircuitBreaker() for k in upstreams}

    async def forward(self, inbound_headers: dict[str, str], ctx: GuardContext) -> Response:
        name = ctx.route.upstream
        breaker = self.breakers[name]
        if not breaker.allow():
            raise UpstreamError(503, "upstream_circuit_open")
        url = self._upstreams[name] + ctx.path
        headers = build_upstream_headers(inbound_headers, ctx, self._key)
        try:
            req = self._client.build_request(ctx.route.method, url, headers=headers, content=ctx.body or None,
                                             timeout=self._timeout)
            upstream = await self._client.send(req, stream=True)
        except httpx.TimeoutException as exc:
            breaker.failure()
            raise UpstreamError(504, "upstream_timeout") from exc
        except httpx.HTTPError as exc:
            breaker.failure()
            raise UpstreamError(502, "upstream_unavailable") from exc
        if upstream.status_code >= 500:
            breaker.failure()
        else:
            breaker.success()
        out_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP}
        out_headers["x-request-id"] = ctx.request_id
        return StreamingResponse(self._body(upstream), status_code=upstream.status_code, headers=out_headers)

    async def _body(self, upstream: httpx.Response) -> AsyncIterator[bytes]:
        total = 0
        try:
            async for chunk in upstream.aiter_raw():
                total += len(chunk)
                if total > self._max:
                    break  # truncate: an upstream must not be able to exhaust gateway memory/bandwidth
                yield chunk
        finally:
            await upstream.aclose()

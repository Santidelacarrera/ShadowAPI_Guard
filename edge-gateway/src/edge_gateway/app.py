"""Application factory: PerimeterMiddleware (filter) in front of a minimal FastAPI forwarder."""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator
from typing import Any
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from .anomaly import ProbeTracker, SizeBaseline
from .audit import AuditEvent, AuditLog, safe_path
from .events import EventForwarder
from .metrics import Metrics
from .openapi import build_openapi
from .perimeter import Deps, PerimeterMiddleware
from .proxy import GuardContext, UpstreamError, UpstreamProxy
from .ratelimit import RateLimiter
from .routes import RouteTable, default_routes
from .settings import Settings
from .threats import ThreatScanner

FORWARD_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]


def create_app(
    settings: Settings,
    *,
    http_client: httpx.AsyncClient | None = None,
    events_client: httpx.AsyncClient | None = None,
    routes: RouteTable | None = None,
) -> PerimeterMiddleware:
    """Build the gateway. ``http_client`` / ``events_client`` let tests inject transports."""
    settings.validate()
    forwarder = EventForwarder(settings.events_url, settings.events_api_key, events_client) if settings.events_url else None
    metrics = Metrics()
    audit = AuditLog(settings.audit_buffer, sink=forwarder.submit if forwarder else None)
    deps = Deps(
        settings=settings,
        routes=routes or default_routes(),
        scanner=ThreatScanner(settings.block_threshold),
        limiter=RateLimiter(),
        preauth=RateLimiter(),
        probes=ProbeTracker(settings.probe_threshold, settings.probe_window_seconds, settings.ban_seconds),
        baseline=SizeBaseline(),
        audit=audit,
        metrics=metrics,
    )
    client = http_client or httpx.AsyncClient(timeout=settings.upstream_timeout_seconds)
    proxy = UpstreamProxy(client, dict(settings.upstreams), settings.guard_signing_key, settings.max_response_bytes,
                          settings.upstream_timeout_seconds)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if forwarder:
            await forwarder.start()
        yield
        if forwarder:
            await forwarder.stop()
        if http_client is None:
            await client.aclose()

    api = FastAPI(title="ShadowAPI Guard edge gateway", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    def admin(x_admin_key: str = Header(default="")) -> None:
        if not settings.admin_api_key or not hmac.compare_digest(x_admin_key, settings.admin_api_key):
            raise HTTPException(404)  # indistinguishable from a path that does not exist

    @api.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @api.get("/__guard/audit")
    async def audit_tail(x_admin_key: str = Header(default=""), limit: int = Query(100, ge=1, le=1000),
                         type: str | None = None) -> list[dict[str, object]]:
        admin(x_admin_key)
        return audit.tail(limit, type)

    @api.get("/__guard/metrics")
    async def metrics_text(x_admin_key: str = Header(default="")) -> PlainTextResponse:
        admin(x_admin_key)
        return PlainTextResponse(metrics.render())

    @api.get("/__guard/routes")
    async def documented_routes(x_admin_key: str = Header(default="")) -> list[dict[str, str]]:
        admin(x_admin_key)
        return [{"name": r.name, "method": r.method, "path": r.template, "upstream": r.upstream, "scope": r.scope}
                for r in deps.routes.routes]

    @api.get("/__guard/openapi")
    async def openapi_document(x_admin_key: str = Header(default="")) -> dict[str, Any]:
        admin(x_admin_key)
        return build_openapi(deps.routes)

    @api.api_route("/{full_path:path}", methods=FORWARD_METHODS, include_in_schema=False)
    async def forward(request: Request) -> Response:
        ctx = request.scope.get("guard")
        if not isinstance(ctx, GuardContext):  # the filter did not run: refuse (fail closed)
            return JSONResponse({"error": "forbidden"}, status_code=403)
        try:
            return await proxy.forward(dict(request.headers), ctx)
        except UpstreamError as exc:
            metrics.inc("guard_upstream_errors_total", upstream=ctx.route.upstream, code=exc.code)
            audit.emit(AuditEvent("upstream_error", "allow", exc.status, ctx.request_id, ctx.route.method,
                                  safe_path(ctx.path), ctx.client_ip, ctx.principal.tenant_id, ctx.principal.subject,
                                  ctx.route.name, exc.code, trace_id=ctx.trace_id))
            return JSONResponse({"error": exc.code, "request_id": ctx.request_id}, status_code=exc.status,
                                headers={"x-request-id": ctx.request_id})

    app = PerimeterMiddleware(api, deps)
    app.proxy, app.forwarder = proxy, forwarder
    return app

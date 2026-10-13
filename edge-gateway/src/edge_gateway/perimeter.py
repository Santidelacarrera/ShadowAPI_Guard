"""PerimeterMiddleware: the filtering layer. Nothing reaches the forwarder unless it passed every check here.

Decision order (cheapest and least-informative first):

 1. ban list / path hygiene / query-string and CORS preflight handling
 2. pre-auth, per-client rate limit
 3. authentication (JWT or API key) bound to the mandatory ``X-Tenant`` header      -> 401 / 403
 4. per-tenant rate limit                                                           -> 429
 5. route resolution against the documented surface (Shadow API / bad method)       -> 404 / 405
 6. scope authorisation                                                             -> 403
 7. body: size, content type, strict JSON, structure, schema                        -> 413 / 415 / 400 / 422
 8. threat scan (prompt injection, command/SQL injection, SSRF, ...)                -> 403
 9. forward with a clean, signed security context
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
from collections.abc import MutableMapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError
from starlette.datastructures import Headers
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .anomaly import Limits, PayloadError, ProbeTracker, SizeBaseline, parse_json
from .audit import AuditEvent, AuditLog, EventType, safe_path
from .auth import AuthError, authenticate
from .metrics import Metrics
from .proxy import GuardContext, new_request_id, new_trace_id
from .ratelimit import RateLimiter
from .routes import Route, RouteTable
from .settings import Settings
from .threats import Finding, ThreatScanner

DRAIN_LIMIT_BYTES = 256 * 1024
DRAIN_TIMEOUT_SECONDS = 2.0
PUBLIC_PATHS = frozenset({"/healthz"})
ADMIN_PREFIX = "/__guard/"
_ENCODED_EVASION = ("%2e", "%2f", "%5c", "%00", "%0d", "%0a")
CORS_HEADERS = "authorization,content-type,x-tenant,x-api-key"


@dataclass
class Deps:
    settings: Settings
    routes: RouteTable
    scanner: ThreatScanner
    limiter: RateLimiter
    preauth: RateLimiter
    probes: ProbeTracker
    baseline: SizeBaseline
    audit: AuditLog
    metrics: Metrics
    limits: Limits = field(default_factory=Limits)


class _Deny(Exception):
    """Internal control flow: abort with a response and an audit event."""

    def __init__(self, status: int, code: str, event: EventType, detail: str = "",
                 findings: tuple[Finding, ...] = (), hostile: bool = True, headers: dict[str, str] | None = None) -> None:
        super().__init__(code)
        self.status, self.code, self.event, self.detail = status, code, event, detail
        self.findings, self.hostile, self.headers = findings, hostile, headers or {}


class PerimeterMiddleware:
    def __init__(self, app: ASGIApp, deps: Deps) -> None:
        self.app = app
        self.d = deps
        self.proxy: Any = None  # set by create_app: the UpstreamProxy (exposes circuit breakers)
        self.forwarder: Any = None  # set by create_app: the control-plane EventForwarder, if configured

    # ------------------------------------------------------------------------------------------------------------
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":  # no WebSocket surface is documented: refuse
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        path: str = scope["path"]
        if path in PUBLIC_PATHS or path.startswith(ADMIN_PREFIX):
            await self.app(scope, receive, send)  # the inner app authenticates admin endpoints itself
            return

        rid = new_request_id()
        client = self._client_ip(scope)
        method: str = scope["method"]
        headers = Headers(scope=scope)
        state: dict[str, Any] = {"tenant": None, "subject": None, "route": None, "sha": "", "size": 0, "body_done": []}
        try:
            ctx, replay = await self._filter(scope, receive, rid, client, method, path, headers, state)
        except _Deny as deny:
            await self._deny(scope, receive, send, rid, client, method, path, state, deny)
            return
        except Exception:  # fail closed on any bug in the filter itself
            self.d.metrics.inc("guard_internal_errors_total")
            await self._deny(scope, receive, send, rid, client, method, path, state,
                             _Deny(500, "internal_error", "malformed", "filter failure", hostile=False))
            return

        scope["guard"] = ctx
        out = self._with_cors(send, headers.get("origin"))
        status = {"code": 0}

        async def capture(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status["code"] = int(message["status"])
            await out(message)

        try:
            await self.app(scope, replay, capture)
        finally:
            self.d.audit.emit(AuditEvent(
                "flagged" if ctx.verdict == "flagged" else "allowed", "allow", status["code"], rid, method,
                safe_path(path), client, ctx.principal.tenant_id, ctx.principal.subject, ctx.route.name,
                payload_sha256=state["sha"], payload_bytes=state["size"], trace_id=ctx.trace_id,
                findings=tuple(f.as_dict() for f in state.get("findings", ()))))
            self.d.metrics.inc("guard_requests_total", decision="allow", tenant=ctx.principal.tenant_id)

    # ------------------------------------------------------------------------------------------------------------
    async def _filter(
        self, scope: Scope, receive: Receive, rid: str, client: str, method: str, path: str,
        headers: Headers, state: dict[str, Any],
    ) -> tuple[GuardContext, Receive]:
        s = self.d.settings
        # 1. bans, path hygiene, query string, CORS preflight --------------------------------------------------------
        if self.d.probes.is_banned(client):
            raise _Deny(429, "temporarily_banned", "banned", hostile=False, headers={"retry-after": str(s.ban_seconds)})
        raw_path = scope.get("raw_path") or path.encode()
        low = raw_path.decode("latin-1").lower()
        if (any(tok in low for tok in _ENCODED_EVASION) or "//" in path or "\\" in path or "\x00" in path
                or any(seg in {".", ".."} for seg in path.split("/")) or not path.isascii() or len(path) > 256):
            raise _Deny(400, "malformed_path", "malformed", "path evasion attempt")
        if method == "OPTIONS":
            raise self._preflight(headers)  # always raises: a preflight never reaches the upstream
        if scope.get("query_string"):
            raise _Deny(400, "unexpected_query", "malformed", "the documented API takes no query string")

        # 2. pre-auth rate limit -------------------------------------------------------------------------------------
        if not self.d.preauth.allow(client, s.preauth_rate_per_minute):
            raise _Deny(429, "rate_limited", "rate_limited", hostile=False, headers={"retry-after": "1"})

        # 3. authentication ------------------------------------------------------------------------------------------
        try:
            principal = authenticate(headers.getlist("authorization"), headers.getlist("x-api-key"),
                                     headers.getlist("x-tenant"), s)
        except AuthError as exc:
            res = self.d.routes.resolve(method, path)
            detail = exc.detail + ("" if res.route or res.path_known else " (undocumented path)")
            raise _Deny(exc.status, exc.code, "auth_failed" if exc.status == 401 else "forbidden", detail.strip(),
                        headers={"www-authenticate": "Bearer"} if exc.status == 401 else {}) from exc
        state["tenant"], state["subject"] = principal.tenant_id, principal.subject
        if self.d.probes.is_banned(self._ban_key(principal.tenant_id, client)):
            raise _Deny(429, "temporarily_banned", "banned", hostile=False, headers={"retry-after": str(s.ban_seconds)})

        # 4. per-tenant rate limit -----------------------------------------------------------------------------------
        cfg = s.tenants[principal.tenant_id]
        if not self.d.limiter.allow(principal.tenant_id, cfg.rate_limit_per_minute):
            raise _Deny(429, "rate_limited", "rate_limited", hostile=False, headers={"retry-after": "1"})

        # 5. route resolution: Shadow APIs and wrong methods --------------------------------------------------------
        res = self.d.routes.resolve(method, path)
        if res.route is None:
            if res.path_known:
                raise _Deny(405, "method_not_allowed", "method_not_allowed", f"{method} not documented for this path",
                            headers={"allow": ", ".join(res.allowed_methods)})
            raise _Deny(404, "not_found", "shadow_api", "access to an undocumented endpoint")
        route = res.route
        state["route"] = route.name

        # 6. scope authorisation -------------------------------------------------------------------------------------
        if route.scope not in principal.scopes:
            raise _Deny(403, "insufficient_scope", "forbidden", f"missing scope {route.scope}", hostile=False)

        # 7. body ---------------------------------------------------------------------------------------------------
        body, replay = await self._read_body(receive, headers, route, state["body_done"])
        state["sha"], state["size"] = hashlib.sha256(body).hexdigest(), len(body)
        payload: object = None
        if route.body_model is not None:
            if not headers.get("content-type", "").lower().split(";")[0].strip() == "application/json":
                raise _Deny(415, "unsupported_media_type", "malformed", hostile=False)
            try:
                payload = parse_json(body, self.d.limits)
            except PayloadError as exc:
                raise _Deny(400, exc.code, "schema_anomaly", exc.detail) from exc
            try:
                route.body_model.model_validate(payload)
            except ValidationError as exc:
                errs = "; ".join(f"{'/'.join(map(str, e['loc']))}:{e['type']}" for e in exc.errors()[:5])
                raise _Deny(422, "schema_violation", "schema_anomaly", errs) from exc
        elif body:
            raise _Deny(400, "unexpected_body", "malformed", "this operation takes no body")

        # 8. threat scan -------------------------------------------------------------------------------------------
        findings: tuple[Finding, ...] = ()
        if payload is not None:
            result = self.d.scanner.scan(payload)
            findings = result.findings
            state["findings"] = findings
            if result.blocked:
                raise _Deny(403, "request_blocked", "threat_blocked",
                            f"score {result.score}: " + ", ".join(sorted({f.rule_id for f in findings})[:6]), findings)
        if self.d.baseline.observe(principal.tenant_id, route.name, len(body)):
            findings = (*findings, Finding("anomaly.size_baseline", "anomaly", 2, "", f"{len(body)} bytes"))
            state["findings"] = findings

        verdict = "flagged" if findings else "clean"
        ctx = GuardContext(rid, new_trace_id(), principal, route, path, body, verdict, client)
        return ctx, replay

    # ------------------------------------------------------------------------------------------------------------
    async def _read_body(self, receive: Receive, headers: Headers, route: Route,
                         state_done: list[bool]) -> tuple[bytes, Receive]:
        limit = min(route.max_body_bytes, self.d.settings.max_body_bytes)
        declared = headers.get("content-length")
        if declared is not None:
            if not declared.isdigit():
                raise _Deny(400, "invalid_content_length", "malformed")
            if int(declared) > limit:
                raise _Deny(413, "payload_too_large", "schema_anomaly", f"{declared} > {limit}")
        chunks: list[bytes] = []
        total = 0
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                raise _Deny(400, "client_disconnected", "malformed", hostile=False)
            chunk: bytes = msg.get("body", b"")
            total += len(chunk)
            if total > limit:  # also covers chunked bodies without Content-Length
                raise _Deny(413, "payload_too_large", "schema_anomaly", f"> {limit}")
            chunks.append(chunk)
            if not msg.get("more_body", False):
                break
        body = b"".join(chunks)
        state_done.append(True)
        sent = False

        async def replay() -> Message:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            # After the (already consumed) body, defer to the server's real ``receive``: it blocks until the client
            # genuinely disconnects. Fabricating a disconnect here makes StreamingResponse cancel itself mid-stream.
            return await receive()

        return body, replay

    # ------------------------------------------------------------------------------------------------------------
    def _preflight(self, headers: Headers) -> _Deny:
        origin = headers.get("origin", "")
        if origin and origin in self.d.settings.cors_origins and headers.get("access-control-request-method"):
            return _Deny(204, "preflight", "allowed", hostile=False, headers={
                "access-control-allow-origin": origin, "access-control-allow-methods": "GET, POST",
                "access-control-allow-headers": CORS_HEADERS, "access-control-max-age": "600", "vary": "Origin"})
        return _Deny(405, "method_not_allowed", "cors_denied", "OPTIONS not allowed", headers={"allow": "GET, POST"})

    def _with_cors(self, send: Send, origin: str | None) -> Send:
        if not origin or origin not in self.d.settings.cors_origins:
            return send

        async def wrapped(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                hdrs = list(message.get("headers", []))
                hdrs += [(b"access-control-allow-origin", origin.encode()), (b"vary", b"Origin")]
                message["headers"] = hdrs
            await send(message)

        return wrapped

    @staticmethod
    def _ban_key(tenant: str | None, client: str) -> str:
        """Authenticated misbehaviour is scoped to (tenant, ip): one tenant's buggy client must not lock out
        everybody behind the same NAT. Unauthenticated hostility is scoped to the ip alone."""
        return client if tenant is None else f"{tenant}|{client}"

    def _client_ip(self, scope: Scope) -> str:
        peer = (scope.get("client") or ("unknown", 0))[0]
        trusted = self.d.settings.trusted_proxies
        if peer in trusted:
            xff = Headers(scope=scope).get("x-forwarded-for", "")
            for hop in reversed([h.strip() for h in xff.split(",") if h.strip()]):
                try:
                    ipaddress.ip_address(hop)
                except ValueError:
                    continue
                if hop not in trusted:
                    return hop
        return str(peer)

    async def _deny(self, scope: Scope, receive: Receive, send: Send, rid: str, client: str, method: str,
                    path: str, state: dict[str, Any], deny: _Deny) -> None:
        banned = self.d.probes.record(self._ban_key(state["tenant"], client)) if deny.hostile else False
        if deny.event != "allowed":
            self.d.audit.emit(AuditEvent(
                deny.event, "deny", deny.status, rid, method, safe_path(path), client, state["tenant"], state["subject"],
                state["route"], deny.detail[:300], tuple(f.as_dict() for f in deny.findings), state["sha"], state["size"]))
        self.d.metrics.inc("guard_requests_total", decision="deny", reason=deny.code)
        if banned:
            self.d.metrics.inc("guard_bans_total")
        headers = {"x-request-id": rid, "cache-control": "no-store", "x-content-type-options": "nosniff", **deny.headers}
        resp: Response
        if deny.status == 204:
            resp = Response(status_code=204, headers=headers)
        else:  # generic body: never echo which rule fired or what was wrong with the input
            resp = JSONResponse({"error": deny.code, "request_id": rid}, status_code=deny.status, headers=headers)
        if not state["body_done"]:
            await self._drain(receive)  # avoid a TCP RST (truncated response) when rejecting before reading the body
        await resp(scope, receive, send)

    @staticmethod
    async def _drain(receive: Receive) -> None:
        total = 0

        async def consume() -> None:
            nonlocal total
            while True:
                msg = await receive()
                if msg["type"] != "http.request":
                    return
                total += len(msg.get("body", b""))
                if not msg.get("more_body", False) or total > DRAIN_LIMIT_BYTES:
                    return

        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(consume(), DRAIN_TIMEOUT_SECONDS)

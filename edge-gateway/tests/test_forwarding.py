"""Secure propagation to ContextRAG_Engine / MultiAgent_Consensus: clean, signed security context."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from edge_gateway import signing

from conftest import ACME_KEY, RAG_BODY, SIGNING_KEY, Gateway, bearer, make_token

URL = "/v1/rag/query"


def streamed(status: int, content: bytes = b"{}") -> httpx.Response:
    """A response shaped like a real network one: body not yet consumed."""
    return httpx.Response(status, stream=httpx.ByteStream(content), headers={"content-type": "application/json"})


def upstream_seen(gw: Gateway, host: str = "rag.internal") -> dict[str, Any]:
    return gw.upstream.seen(host)[-1]


# ---- routing ---------------------------------------------------------------------------------------------------------

def test_rag_route_goes_to_context_rag_engine(gw: Gateway) -> None:
    r = gw.client.post(URL, json=RAG_BODY, headers=bearer())
    assert r.status_code == 200 and r.json()["service"] == "ContextRAG_Engine"
    assert gw.upstream.calls[-1].url.host == "rag.internal"


def test_consensus_routes_go_to_multi_agent_consensus(gw: Gateway) -> None:
    r = gw.client.post("/v1/consensus/run", json={"task": "evaluate vendor proposals", "agents": ["legal", "finance"], "max_rounds": 2},
                       headers=bearer())
    assert r.status_code == 200 and r.json()["service"] == "MultiAgent_Consensus"
    r = gw.client.get("/v1/consensus/runs/run-123", headers=bearer())
    assert r.status_code == 200 and r.json()["path"] == "/v1/consensus/runs/run-123"
    assert [c.url.host for c in gw.upstream.calls] == ["consensus.internal"] * 2


# ---- security context injection ---------------------------------------------------------------------------------------

def test_clean_security_context_is_injected(gw: Gateway) -> None:
    gw.client.post(URL, json=RAG_BODY, headers=bearer(make_token(sub="alice")))
    h = upstream_seen(gw)["headers"]
    assert h["x-tenant-id"] == "acme" and h["x-auth-subject"] == "alice" and h["x-auth-method"] == "jwt"
    assert set(h["x-auth-scopes"].split()) == {"rag:query", "consensus:run", "consensus:read"}
    assert h["x-guard-verdict"] == "clean"
    assert len(h["x-request-id"]) == 32 and len(h["x-audit-trace"]) == 32
    assert h["traceparent"].startswith(f"00-{h['x-audit-trace']}-")


def test_request_id_in_response_matches_upstream_and_audit(gw: Gateway) -> None:
    r = gw.client.post(URL, json=RAG_BODY, headers=bearer())
    assert r.headers["x-request-id"] == upstream_seen(gw)["headers"]["x-request-id"]
    assert gw.events("allowed")[0]["request_id"] == r.headers["x-request-id"]


def test_client_supplied_security_headers_are_stripped_and_overwritten(gw: Gateway) -> None:
    evil = {**bearer(), "X-Tenant-Id": "globex", "X-Auth-Subject": "admin", "X-Auth-Scopes": "root", "X-Guard-Verdict": "clean",
            "X-Guard-Signature": "v1=deadbeef", "X-Forwarded-For": "6.6.6.6", "Cookie": "session=steal", "X-Request-Id": "forged",
            "Traceparent": "00-" + "a" * 32 + "-" + "b" * 16 + "-01", "X-Audit-Trace": "forged", "Proxy-Authorization": "x"}
    r = gw.client.post(URL, json=RAG_BODY, headers=evil)
    assert r.status_code == 200 and r.json()["tenant"] == "acme"
    h = upstream_seen(gw)["headers"]
    assert h["x-tenant-id"] == "acme" and h["x-auth-subject"] != "admin" and h["x-auth-scopes"] != "root"
    assert h["x-request-id"] != "forged" and h["x-audit-trace"] != "forged"
    assert "cookie" not in h and "x-forwarded-for" not in h and "proxy-authorization" not in h


def test_credentials_are_never_forwarded_upstream(gw: Gateway) -> None:
    gw.client.post(URL, json=RAG_BODY, headers=bearer())
    gw.client.post(URL, json=RAG_BODY, headers={"X-API-Key": ACME_KEY, "X-Tenant": "acme"})
    for seen in gw.upstream.seen("rag.internal"):
        assert "authorization" not in seen["headers"] and "x-api-key" not in seen["headers"] and "x-tenant" not in seen["headers"]
        assert ACME_KEY not in str(seen)


def test_api_key_principal_is_identified_without_exposing_the_key(gw: Gateway) -> None:
    gw.client.post(URL, json=RAG_BODY, headers={"X-API-Key": ACME_KEY, "X-Tenant": "acme"})
    h = upstream_seen(gw)["headers"]
    assert h["x-auth-method"] == "api_key" and h["x-auth-subject"].startswith("apikey:") and ACME_KEY not in h["x-auth-subject"]


def test_body_is_forwarded_unmodified(gw: Gateway) -> None:
    body = b'{"query":"unicode \\u00f1 ok","top_k":3}'
    gw.client.post(URL, content=body, headers={**bearer(), "Content-Type": "application/json"})
    assert upstream_seen(gw)["body"] == body.decode()


def test_flagged_requests_are_forwarded_with_marked_verdict(gw: Gateway) -> None:
    r = gw.client.post(URL, json={"query": "hel\u200blo there, what is the policy?"}, headers=bearer())
    assert r.status_code == 200
    assert upstream_seen(gw)["headers"]["x-guard-verdict"] == "flagged"
    assert gw.events("flagged")


# ---- service-to-service trust (signatures) ----------------------------------------------------------------------------

def test_upstream_can_verify_the_guard_signature(gw: Gateway) -> None:
    gw.client.post(URL, json=RAG_BODY, headers=bearer())
    assert upstream_seen(gw)["verified_tenant"] == "acme"


def test_direct_call_bypassing_the_guard_is_rejected_by_upstream(gw: Gateway) -> None:
    """An attacker who reaches an upstream directly cannot assert a tenant without the guard's key."""
    app = gw.upstream.apps["rag.internal"]
    import asyncio
    async def go() -> int:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://rag.internal") as c:
            r = await c.post(URL, json=RAG_BODY, headers={"X-Tenant-Id": "acme"})
            return r.status_code
    assert asyncio.run(go()) == 401


def _signed(**over: Any) -> tuple[dict[str, str], dict[str, Any]]:
    args: dict[str, Any] = dict(tenant="acme", rid="r1", ts=str(int(time.time())), method="POST", path=URL, body=b'{"a":1}')
    args.update(over)
    sig, sha = signing.sign(SIGNING_KEY, args["tenant"], args["rid"], args["ts"], args["method"], args["path"], args["body"])
    headers = {"x-tenant-id": args["tenant"], "x-request-id": args["rid"], "x-guard-timestamp": args["ts"], "x-guard-signature": sig}
    return headers, args


def test_signature_verification_unit() -> None:
    h, a = _signed()
    assert signing.verify_guard_request(h, a["method"], a["path"], a["body"], SIGNING_KEY) == "acme"


@pytest.mark.parametrize("tamper", [
    {"tenant": "globex"}, {"method": "GET"}, {"path": "/v1/other"}, {"body": b'{"a":2}'},
])
def test_tampering_invalidates_signature(tamper: dict[str, Any]) -> None:
    h, a = _signed()
    h2 = dict(h)
    if "tenant" in tamper:
        h2["x-tenant-id"] = tamper["tenant"]
    result = signing.verify_guard_request(h2, tamper.get("method", a["method"]), tamper.get("path", a["path"]),
                                          tamper.get("body", a["body"]), SIGNING_KEY)
    assert result is None


def test_replay_outside_clock_skew_is_rejected() -> None:
    h, a = _signed(ts=str(int(time.time()) - 600))
    assert signing.verify_guard_request(h, a["method"], a["path"], a["body"], SIGNING_KEY) is None


def test_wrong_key_and_missing_headers_are_rejected() -> None:
    h, a = _signed()
    assert signing.verify_guard_request(h, a["method"], a["path"], a["body"], b"k" * 48) is None
    assert signing.verify_guard_request({}, "POST", URL, b"", SIGNING_KEY) is None
    h["x-guard-timestamp"] = "not-a-number"
    assert signing.verify_guard_request(h, a["method"], a["path"], a["body"], SIGNING_KEY) is None


# ---- response handling ------------------------------------------------------------------------------------------------

def test_upstream_internal_headers_are_not_leaked(gw: Gateway) -> None:
    r = gw.client.post(URL, json=RAG_BODY, headers=bearer())
    assert "set-cookie" not in r.headers and "server" not in r.headers


def test_upstream_5xx_is_passed_through_and_trips_breaker(gw: Gateway) -> None:
    gw.upstream.override = lambda req: streamed(500, b'{"error":"boom"}')
    codes = [gw.client.post(URL, json=RAG_BODY, headers=bearer()).status_code for _ in range(8)]
    assert codes[:5] == [500] * 5 and codes[5:] == [503] * 3  # breaker open: fail fast without touching the upstream
    assert len(gw.upstream.calls) == 5
    assert gw.events("upstream_error")


def test_other_upstream_is_unaffected_by_an_open_breaker(gw: Gateway) -> None:
    gw.upstream.override = lambda req: streamed(500)
    for _ in range(6):
        gw.client.post(URL, json=RAG_BODY, headers=bearer())
    gw.upstream.override = None
    assert gw.client.post("/v1/consensus/run", json={"task": "x ok"}, headers=bearer()).status_code == 200


def test_unreachable_upstream_is_502_without_details(gw: Gateway) -> None:
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused 10.0.3.7:8000")
    gw.upstream.override = boom
    r = gw.client.post(URL, json=RAG_BODY, headers=bearer())
    assert r.status_code == 502 and "10.0.3.7" not in r.text and set(r.json()) == {"error", "request_id"}


def test_upstream_timeout_is_504(gw: Gateway) -> None:
    def slow(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")
    gw.upstream.override = slow
    assert gw.client.post(URL, json=RAG_BODY, headers=bearer()).status_code == 504


def test_oversized_upstream_response_is_truncated(make_gw: Callable[..., Gateway]) -> None:
    gw = make_gw(max_response_bytes=1000)
    gw.upstream.override = lambda req: streamed(200, b"x" * 50_000)
    r = gw.client.post(URL, json=RAG_BODY, headers=bearer())
    assert len(r.content) <= 1000


# ---- CORS (browser portal) --------------------------------------------------------------------------------------------

def test_cors_preflight_for_allowed_origin(make_gw: Callable[..., Gateway]) -> None:
    gw = make_gw(cors_origins=frozenset({"https://portal.example.com"}))
    r = gw.client.options(URL, headers={"Origin": "https://portal.example.com", "Access-Control-Request-Method": "POST"})
    assert r.status_code == 204 and r.headers["access-control-allow-origin"] == "https://portal.example.com"
    assert gw.upstream.calls == []
    ok = gw.client.post(URL, json=RAG_BODY, headers={**bearer(), "Origin": "https://portal.example.com"})
    assert ok.headers["access-control-allow-origin"] == "https://portal.example.com"


def test_cors_preflight_for_unknown_origin_is_denied(make_gw: Callable[..., Gateway]) -> None:
    gw = make_gw(cors_origins=frozenset({"https://portal.example.com"}))
    r = gw.client.options(URL, headers={"Origin": "https://evil.example.com", "Access-Control-Request-Method": "POST"})
    assert r.status_code == 405 and "access-control-allow-origin" not in r.headers
    bad = gw.client.post(URL, json=RAG_BODY, headers={**bearer(), "Origin": "https://evil.example.com"})
    assert "access-control-allow-origin" not in bad.headers


# ---- rate limiting ----------------------------------------------------------------------------------------------------

def test_per_tenant_rate_limit_isolated_between_tenants(make_gw: Callable[..., Gateway]) -> None:
    from edge_gateway.settings import TenantConfig, hash_api_key

    from conftest import ALL_SCOPES, GLOBEX_KEY
    gw = make_gw(tenants={"acme": TenantConfig(frozenset({hash_api_key(ACME_KEY)}), ALL_SCOPES, 5),
                          "globex": TenantConfig(frozenset({hash_api_key(GLOBEX_KEY)}), ALL_SCOPES, 5)})
    codes = [gw.client.post(URL, json=RAG_BODY, headers=bearer()).status_code for _ in range(8)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429] * 3
    assert gw.client.post(URL, json=RAG_BODY, headers=bearer(tenant="globex")).status_code == 200  # noisy neighbour contained


def test_pre_auth_rate_limit_throttles_credential_stuffing(make_gw: Callable[..., Gateway]) -> None:
    gw = make_gw(preauth_rate_per_minute=5, probe_threshold=1000)
    codes = [gw.client.post(URL, json=RAG_BODY, headers={"Authorization": "Bearer junk", "X-Tenant": "acme"}).status_code for _ in range(8)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429] * 3


def test_slow_streamed_upstream_response_is_delivered_completely_over_a_real_server_receive(gw: Gateway) -> None:
    """Regression: a fabricated ``http.disconnect`` after the body made StreamingResponse cancel mid-stream, truncating
    forwarded responses on real servers (uvicorn's receive blocks until the client really disconnects)."""
    import anyio

    class Slow(httpx.AsyncByteStream):
        async def __aiter__(self) -> Any:
            for part in (b'{"answer":"', b"part-one,", b"part-two,", b'part-three"}'):
                await anyio.sleep(0.05)
                yield part

    gw.upstream.override = lambda req: httpx.Response(200, stream=Slow(), headers={"content-type": "application/json"})
    sent: list[dict[str, Any]] = []

    async def call() -> None:
        body = b'{"query":"hello world question"}'
        scope = {"type": "http", "method": "POST", "path": URL, "raw_path": URL.encode(), "query_string": b"",
                 "headers": [(b"authorization", bearer()["Authorization"].encode()), (b"x-tenant", b"acme"),
                            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
                 "client": ("1.2.3.4", 1), "scheme": "http", "server": ("gw", 80), "http_version": "1.1"}
        delivered = False
        never = anyio.Event()  # a real server blocks here until the client disconnects

        async def receive() -> dict[str, Any]:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            await never.wait()
            return {"type": "http.disconnect"}

        async def send(msg: dict[str, Any]) -> None:
            sent.append(msg)

        with anyio.fail_after(5):
            await gw.app(scope, receive, send)  # type: ignore[arg-type]

    anyio.run(call)
    assert sent[0]["status"] == 200
    payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    assert payload == b'{"answer":"part-one,part-two,part-three"}', payload
    assert sent[-1]["type"] == "http.response.body" and not sent[-1].get("more_body", False)

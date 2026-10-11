"""Shadow API detection, method enforcement and structural anomalies."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from conftest import RAG_BODY, Gateway, bearer

URL = "/v1/rag/query"


# ---- Shadow APIs -----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/admin", "/admin/debug", "/v1/rag/export", "/v2/rag/query", "/v1/rag", "/internal/metrics", "/.env", "/actuator/env",
    "/v1/consensus/runs", "/v1/consensus/runs/abc/cancel", "/graphql", "/swagger.json", "/v1/rag/query/", "/",
])
def test_undocumented_endpoint_is_404_and_audited_as_shadow_api(gw: Gateway, path: str) -> None:
    r = gw.client.get(path, headers=bearer())
    assert r.status_code == 404 and r.json()["error"] == "not_found"
    assert gw.upstream.calls == []
    ev = gw.events("shadow_api")
    assert ev and ev[0]["tenant"] == "acme" and ev[0]["decision"] == "deny"


def test_unauthenticated_probe_of_unknown_path_gets_401_not_404(gw: Gateway) -> None:
    """Do not confirm to anonymous scanners which paths exist; still record that the path was undocumented."""
    r = gw.client.get("/admin/debug")
    assert r.status_code == 401
    ev = gw.events("auth_failed")[0]
    assert "undocumented path" in str(ev["detail"])


@pytest.mark.parametrize("method,path", [("GET", URL), ("PUT", URL), ("DELETE", URL), ("PATCH", URL), ("POST", "/v1/consensus/runs/abc")])
def test_wrong_method_is_405_with_allow_header(gw: Gateway, method: str, path: str) -> None:
    r = gw.client.request(method, path, headers=bearer())
    assert r.status_code == 405 and "allow" in r.headers
    assert gw.upstream.calls == []
    assert gw.events("method_not_allowed")


def test_scanner_gets_banned_after_repeated_probing(make_gw: Callable[..., Gateway]) -> None:
    gw = make_gw(probe_threshold=5)
    for i in range(5):
        assert gw.client.get(f"/probe{i}", headers=bearer()).status_code == 404
    r = gw.client.post(URL, json=RAG_BODY, headers=bearer())  # even a legitimate request from that client
    assert r.status_code == 429 and r.json()["error"] == "temporarily_banned"
    assert gw.upstream.calls == []
    assert gw.events("banned")


def test_failed_logins_also_count_towards_a_ban(make_gw: Callable[..., Gateway]) -> None:
    gw = make_gw(probe_threshold=4)
    for _ in range(4):
        gw.client.post(URL, json=RAG_BODY, headers={"Authorization": "Bearer bad", "X-Tenant": "acme"})
    assert gw.client.post(URL, json=RAG_BODY, headers=bearer()).status_code == 429


def test_legitimate_traffic_never_triggers_a_ban(make_gw: Callable[..., Gateway]) -> None:
    gw = make_gw(probe_threshold=3)
    assert all(gw.client.post(URL, json=RAG_BODY, headers=bearer()).status_code == 200 for _ in range(20))


# ---- path hygiene -----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/v1//rag/query", "/v1/rag/%2e%2e/query", "/v1/rag%2fquery", "/v1/rag/query%00",
    "/v1/rag\\query", "/v1/rag/query%0d%0aX-Evil:1", "/v1/rag/ünïcode", "/" + "a" * 300,
])
def test_path_evasion_is_400(gw: Gateway, path: str) -> None:
    r = gw.client.post(path, json=RAG_BODY, headers=bearer())
    assert r.status_code == 400 and r.json()["error"] == "malformed_path"
    assert gw.upstream.calls == []


def test_query_string_is_rejected(gw: Gateway) -> None:
    r = gw.client.post(URL + "?debug=1", json=RAG_BODY, headers=bearer())
    assert r.status_code == 400 and r.json()["error"] == "unexpected_query"


def test_websocket_is_refused(gw: Gateway) -> None:
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with gw.client.websocket_connect(URL):
            pass


# ---- structural / schema anomalies -----------------------------------------------------------------------------------

def raw(gw: Gateway, body: bytes, ctype: str = "application/json", url: str = URL) -> Any:
    return gw.client.post(url, content=body, headers={**bearer(), "Content-Type": ctype})


@pytest.mark.parametrize("body", [
    {"query": "x", "extra": 1},                      # unknown field
    {"query": 123},                                  # wrong type (strict)
    {"query": "x", "top_k": "5"},                    # string instead of int (strict)
    {"query": "x", "top_k": 0}, {"query": "x", "top_k": 51},
    {"query": ""}, {},                                # empty / missing
    {"query": "x", "filters": {"bad key!": "v"}},
    {"query": "x", "filters": {f"k{i}": "v" for i in range(25)}},
    {"query": "x", "conversation_id": "not-a-uuid"},
    {"query": "x" * 4001},
    ["query"], "query", 5,                            # not an object
])
def test_schema_violations_are_422_or_400(gw: Gateway, body: Any) -> None:
    r = gw.client.post(URL, json=body, headers=bearer())
    assert r.status_code in (400, 422)
    assert gw.upstream.calls == []
    assert gw.events("schema_anomaly")


@pytest.mark.parametrize("body,code", [
    (b'{"query":"a","query":"b"}', "duplicate_key"),                     # parameter pollution
    (b'{"query":"x","top_k":NaN}', "invalid_number"),
    (b'{"query":"x","top_k":Infinity}', "invalid_number"),
    (b'{"query":"x","top_k":' + b"9" * 40 + b"}", "integer_too_large"),
    (b"{'query':'x'}", "invalid_json"),
    (b'{"query":"x",}', "invalid_json"),
    (b"", "invalid_json"),
    (b'\xef\xbb\xbf{"query":"x"}', "invalid_encoding"),
    (b'{"query":"\xff\xfe"}', "invalid_encoding"),
])
def test_malformed_json_is_400(gw: Gateway, body: bytes, code: str) -> None:
    r = raw(gw, body)
    assert r.status_code == 400 and r.json()["error"] == code
    assert gw.upstream.calls == []


def test_deeply_nested_json_is_400(gw: Gateway) -> None:
    deep = '{"query":"x","filters":' + '{"a":' * 50 + "1" + "}" * 50 + "}"
    r = raw(gw, deep.encode())
    assert r.status_code == 400 and r.json()["error"] in {"too_deep", "invalid_json"}


def test_json_bomb_wide_array_is_rejected(gw: Gateway) -> None:
    r = raw(gw, json.dumps({"query": "x", "agents": list(range(100000))}).encode())
    assert r.status_code in (400, 413, 422)


def test_oversized_body_is_413_by_content_length(gw: Gateway) -> None:
    r = raw(gw, json.dumps({"query": "x" * 30_000}).encode())
    assert r.status_code == 413
    assert gw.upstream.calls == []


def test_oversized_chunked_body_without_content_length_is_413(gw: Gateway) -> None:
    def chunks() -> Any:
        for _ in range(40):
            yield b'{"query":"' + b"x" * 1000 if _ == 0 else b"x" * 1000
    r = gw.client.post(URL, content=chunks(), headers={**bearer(), "Content-Type": "application/json"})
    assert r.status_code == 413
    assert gw.upstream.calls == []


@pytest.mark.parametrize("ctype", ["text/plain", "application/x-www-form-urlencoded", "application/xml", "multipart/form-data"])
def test_wrong_content_type_is_415(gw: Gateway, ctype: str) -> None:
    assert raw(gw, b'{"query":"x"}', ctype).status_code == 415


def test_json_content_type_with_charset_is_accepted(gw: Gateway) -> None:
    assert raw(gw, b'{"query":"hello world"}', "application/json; charset=utf-8").status_code == 200


def test_get_with_body_is_rejected(gw: Gateway) -> None:
    r = gw.client.request("GET", "/v1/consensus/runs/run-1", content=b'{"x":1}', headers=bearer())
    assert r.status_code == 400 and r.json()["error"] == "unexpected_body"


def test_invalid_path_parameter_is_treated_as_undocumented(gw: Gateway) -> None:
    for bad in ("a b", "x" * 80, "run;id", "run'1"):
        assert gw.client.get(f"/v1/consensus/runs/{bad}", headers=bearer()).status_code in (400, 404)
    assert gw.upstream.calls == []


def test_size_baseline_flags_but_does_not_block(make_gw: Callable[..., Gateway]) -> None:
    gw = make_gw()
    for i in range(60):
        assert gw.client.post(URL, json={"query": f"routine question number {i:03d}"}, headers=bearer()).status_code == 200
    r = gw.client.post(URL, json={"query": "a perfectly normal sentence " * 120}, headers=bearer())
    assert r.status_code == 200
    seen = gw.upstream.seen("rag.internal")[-1]
    assert seen["headers"]["x-guard-verdict"] == "flagged"
    assert any(f["rule"] == "anomaly.size_baseline" for e in gw.events("flagged") for f in e["findings"])  # type: ignore[attr-defined]


@pytest.mark.parametrize("path", ["/v1/rag/query/../query", "/v1/rag/./query", "/v1/rag/query/.."])
def test_dot_segments_are_rejected_even_when_a_client_does_not_normalise_them(gw: Gateway, path: str) -> None:
    """httpx collapses dot segments before sending, so drive the ASGI app directly with the raw path."""
    import anyio

    async def call() -> int:
        status = {"code": 0}
        scope = {"type": "http", "method": "POST", "path": path, "raw_path": path.encode(), "query_string": b"",
                 "headers": [(b"authorization", f"Bearer {bearer()['Authorization'][7:]}".encode()), (b"x-tenant", b"acme"),
                            (b"content-type", b"application/json")], "client": ("1.2.3.4", 1), "scheme": "http",
                 "server": ("gw", 80), "http_version": "1.1"}

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b'{"query":"x"}', "more_body": False}

        async def send(msg: dict[str, Any]) -> None:
            if msg["type"] == "http.response.start":
                status["code"] = msg["status"]

        await gw.app(scope, receive, send)  # type: ignore[arg-type]
        return status["code"]

    assert anyio.run(call) == 400
    assert gw.upstream.calls == []


def test_empty_body_without_content_type_is_rejected(gw: Gateway) -> None:
    assert gw.client.post(URL, headers=bearer()).status_code in (400, 415)


def test_dotfile_probe_is_a_shadow_api_not_a_path_attack(gw: Gateway) -> None:
    assert gw.client.get("/.git/config", headers=bearer()).status_code == 404
    assert gw.events("shadow_api")


def test_a_tenants_misbehaviour_does_not_lock_out_other_tenants_behind_the_same_ip(make_gw: Callable[..., Gateway]) -> None:
    gw = make_gw(probe_threshold=5)
    for i in range(5):
        gw.client.get(f"/probe{i}", headers=bearer())  # acme (authenticated) keeps probing
    assert gw.client.post(URL, json=RAG_BODY, headers=bearer()).status_code == 429  # acme+ip banned
    other = gw.client.post(URL, json=RAG_BODY, headers=bearer(tenant="globex"))
    assert other.status_code == 200, "ban must be scoped to (tenant, ip) for authenticated clients"


def test_unauthenticated_hostility_bans_the_ip_for_everyone(make_gw: Callable[..., Gateway]) -> None:
    gw = make_gw(probe_threshold=4)
    for _ in range(4):
        gw.client.get("/wp-admin/setup-config.php")  # anonymous scanner
    assert gw.client.post(URL, json=RAG_BODY, headers=bearer(tenant="globex")).status_code == 429


@pytest.mark.parametrize("headers,expected", [({}, 401), ({"content-length": "300000"}, 401)])
def test_early_rejection_drains_the_request_body_to_avoid_tcp_reset(gw: Gateway, headers: dict[str, str], expected: int) -> None:
    """Regression: rejecting (401/413/...) before reading a large body made the server close the socket with unread
    data -> RST -> clients saw a truncated response on real networks. The body must be consumed before replying."""
    import anyio

    chunks = [b"x" * 10_000 for _ in range(20)]
    consumed: list[int] = []
    sent_status: list[int] = []

    async def call() -> None:
        scope = {"type": "http", "method": "POST", "path": URL, "raw_path": URL.encode(), "query_string": b"",
                 "headers": [(b"x-tenant", b"acme"), (b"content-type", b"application/json"),
                            *[(k.encode(), v.encode()) for k, v in headers.items()]],
                 "client": ("1.2.3.4", 1), "scheme": "http", "server": ("gw", 80), "http_version": "1.1"}
        it = iter(chunks)

        async def receive() -> dict[str, Any]:
            try:
                c = next(it)
            except StopIteration:
                return {"type": "http.disconnect"}
            consumed.append(len(c))
            return {"type": "http.request", "body": c, "more_body": len(consumed) < len(chunks)}

        async def send(msg: dict[str, Any]) -> None:
            if msg["type"] == "http.response.start":
                sent_status.append(msg["status"])
                assert len(consumed) == len(chunks), "response sent before the request body was drained"

        await gw.app(scope, receive, send)  # type: ignore[arg-type]

    anyio.run(call)
    assert sent_status == [expected]

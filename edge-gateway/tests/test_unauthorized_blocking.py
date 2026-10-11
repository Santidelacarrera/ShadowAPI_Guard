"""Unauthenticated / spoofed / unauthorised requests must be rejected at the perimeter and never reach an upstream."""

from __future__ import annotations

import time
from typing import Any

import jwt
import pytest

from conftest import ACME_KEY, GLOBEX_KEY, JWT_SECRET, RAG_BODY, Gateway, bearer, make_token

URL = "/v1/rag/query"


def post(gw: Gateway, headers: dict[str, str], body: Any = RAG_BODY, url: str = URL) -> Any:
    return gw.client.post(url, json=body, headers=headers)


def never_reached(gw: Gateway) -> None:
    assert gw.upstream.calls == [], "a rejected request leaked to an upstream"


# ---- 401: missing / invalid credentials ----------------------------------------------------------------------------

def test_no_credentials_is_401(gw: Gateway) -> None:
    r = post(gw, {"X-Tenant": "acme"})
    assert r.status_code == 401 and r.json()["error"] == "missing_credentials"
    assert r.headers["www-authenticate"] == "Bearer"
    never_reached(gw)


def test_no_credentials_and_no_tenant_is_401(gw: Gateway) -> None:
    assert post(gw, {}).status_code == 401
    never_reached(gw)


@pytest.mark.parametrize("authz", ["Bearer", "Bearer ", "Bearer garbage", "Bearer a.b.c", "Basic dXNlcjpwYXNz", "bearer x", "Token abc"])
def test_malformed_authorization_is_401(gw: Gateway, authz: str) -> None:
    assert post(gw, {"Authorization": authz, "X-Tenant": "acme"}).status_code == 401
    never_reached(gw)


def test_expired_token_is_401(gw: Gateway) -> None:
    r = post(gw, bearer(make_token(exp_in=-3600)))
    assert r.status_code == 401
    never_reached(gw)


def test_wrong_signature_is_401(gw: Gateway) -> None:
    assert post(gw, bearer(make_token(secret="x" * 48))).status_code == 401
    never_reached(gw)


def test_alg_none_token_is_401(gw: Gateway) -> None:
    forged = jwt.encode({"sub": "u", "tenant_id": "acme", "scope": "rag:query", "exp": int(time.time()) + 300}, None, algorithm="none")
    assert post(gw, {"Authorization": f"Bearer {forged}", "X-Tenant": "acme"}).status_code == 401
    never_reached(gw)


def test_alg_confusion_hs512_is_401(gw: Gateway) -> None:
    assert post(gw, bearer(make_token(secret=JWT_SECRET, alg="HS512"))).status_code == 401
    never_reached(gw)


def test_token_without_exp_is_401(gw: Gateway) -> None:
    token = jwt.encode({"sub": "u", "tenant_id": "acme", "scope": "rag:query"}, JWT_SECRET, algorithm="HS256")
    assert post(gw, bearer(token)).status_code == 401
    never_reached(gw)


def test_oversized_token_is_401(gw: Gateway) -> None:
    assert post(gw, {"Authorization": "Bearer " + "a" * 5000, "X-Tenant": "acme"}).status_code == 401


def test_invalid_and_unknown_credentials_are_indistinguishable(gw: Gateway) -> None:
    """No oracle: a wrong key for a real tenant and a key for a tenant that does not exist answer identically."""
    wrong_key = gw.client.post(URL, json=RAG_BODY, headers={"X-API-Key": "nope", "X-Tenant": "acme"})
    ghost = gw.client.post(URL, json=RAG_BODY, headers={"X-API-Key": "nope", "X-Tenant": "ghost-tenant"})
    assert wrong_key.status_code == ghost.status_code == 401
    assert wrong_key.json()["error"] == ghost.json()["error"]


def test_both_jwt_and_api_key_is_ambiguous_401(gw: Gateway) -> None:
    h = {**bearer(), "X-API-Key": ACME_KEY}
    assert post(gw, h).status_code == 401
    never_reached(gw)


# ---- 403: tenant binding / impersonation -----------------------------------------------------------------------------

def test_missing_x_tenant_with_valid_jwt_is_403(gw: Gateway) -> None:
    r = post(gw, {"Authorization": f"Bearer {make_token()}"})
    assert r.status_code == 403 and r.json()["error"] == "invalid_tenant_header"
    never_reached(gw)


@pytest.mark.parametrize("tenant", ["", "ACME", "acme ", "../acme", "acme;drop", "a", "x" * 80, "acme\tx"])
def test_malformed_x_tenant_is_403(gw: Gateway, tenant: str) -> None:
    assert post(gw, {"Authorization": f"Bearer {make_token()}", "X-Tenant": tenant}).status_code == 403
    never_reached(gw)


def test_tenant_spoofing_header_differs_from_token_is_403(gw: Gateway) -> None:
    """Token minted for acme, header claims globex: classic cross-tenant impersonation."""
    r = post(gw, {"Authorization": f"Bearer {make_token('acme')}", "X-Tenant": "globex"})
    assert r.status_code == 403 and r.json()["error"] == "tenant_mismatch"
    never_reached(gw)
    assert gw.events("forbidden")


def test_token_for_unconfigured_tenant_is_403(gw: Gateway) -> None:
    assert post(gw, bearer(make_token("initech"), "initech")).status_code == 403
    never_reached(gw)


def test_duplicate_x_tenant_headers_is_403(gw: Gateway) -> None:
    r = gw.client.post(URL, json=RAG_BODY, headers=[("Authorization", f"Bearer {make_token()}"),
                                                    ("X-Tenant", "acme"), ("X-Tenant", "globex")])  # type: ignore[arg-type]
    assert r.status_code == 403
    never_reached(gw)


def test_api_key_of_other_tenant_is_401(gw: Gateway) -> None:
    r = gw.client.post(URL, json=RAG_BODY, headers={"X-API-Key": GLOBEX_KEY, "X-Tenant": "acme"})
    assert r.status_code == 401
    never_reached(gw)


def test_api_key_without_tenant_header_is_403(gw: Gateway) -> None:
    assert gw.client.post(URL, json=RAG_BODY, headers={"X-API-Key": ACME_KEY}).status_code == 403
    never_reached(gw)


def test_tenant_claim_cannot_be_injected_through_body(gw: Gateway) -> None:
    r = post(gw, bearer(), {**RAG_BODY, "tenant_id": "globex"})
    assert r.status_code == 422  # unknown field
    never_reached(gw)


# ---- 403: scopes ---------------------------------------------------------------------------------------------------

def test_insufficient_scope_is_403(gw: Gateway) -> None:
    r = post(gw, bearer(make_token(scope="consensus:read")))
    assert r.status_code == 403 and r.json()["error"] == "insufficient_scope"
    never_reached(gw)


def test_token_scopes_are_capped_by_tenant_policy(gw: Gateway) -> None:
    """globex may only use RAG, even if its token claims more."""
    token = make_token("globex", scope="rag:query consensus:run")
    assert post(gw, bearer(token, "globex")).status_code == 200
    r = gw.client.post("/v1/consensus/run", json={"task": "plan the launch"}, headers=bearer(token, "globex"))
    assert r.status_code == 403
    assert len(gw.upstream.calls) == 1


# ---- the happy path still works ------------------------------------------------------------------------------------

def test_valid_jwt_is_forwarded(gw: Gateway) -> None:
    r = post(gw, bearer())
    assert r.status_code == 200 and r.json() == {"service": "ContextRAG_Engine", "tenant": "acme", "path": URL}


def test_valid_api_key_is_forwarded(gw: Gateway) -> None:
    r = gw.client.post(URL, json=RAG_BODY, headers={"X-API-Key": ACME_KEY, "X-Tenant": "acme"})
    assert r.status_code == 200 and r.json()["tenant"] == "acme"


# ---- no information leaks in error bodies ----------------------------------------------------------------------------

def test_error_bodies_are_generic(gw: Gateway) -> None:
    r = post(gw, bearer(make_token(exp_in=-3600)))
    assert set(r.json()) == {"error", "request_id"}
    assert "expired" not in r.text.lower() and "signature" not in r.text.lower()

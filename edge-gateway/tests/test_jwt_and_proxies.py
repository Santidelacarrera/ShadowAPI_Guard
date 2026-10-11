"""RS256, issuer/audience enforcement, and client-IP trust."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import RAG_BODY, Gateway, bearer, make_token

URL = "/v1/rag/query"


def _keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


def _forge_hs256_with_public_key(pub: str) -> str:
    """What an attacker does by hand (PyJWT refuses to sign HS256 with an asymmetric key)."""
    import base64
    import hashlib
    import hmac
    import json

    def b64(b: bytes) -> bytes:
        return base64.urlsafe_b64encode(b).rstrip(b"=")

    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"sub": "u", "tenant_id": "acme", "scope": "rag:query", "exp": int(time.time()) + 300}).encode())
    sig = b64(hmac.new(pub.encode(), head + b"." + body, hashlib.sha256).digest())
    return (head + b"." + body + b"." + sig).decode()


def rs_token(priv: str, tenant: str = "acme", **extra: Any) -> str:
    claims = {"sub": "u", "tenant_id": tenant, "scope": "rag:query", "exp": int(time.time()) + 300, **extra}
    return jwt.encode(claims, priv, algorithm="RS256")


def test_rs256_token_is_accepted_and_hs256_confusion_rejected(make_gw: Callable[..., Gateway]) -> None:
    priv, pub = _keypair()
    gw = make_gw(jwt_algorithm="RS256", jwt_public_key=pub, jwt_secret="")
    assert gw.client.post(URL, json=RAG_BODY, headers=bearer(rs_token(priv))).status_code == 200
    # classic algorithm-confusion attack: sign HS256 using the *public key* as the HMAC secret
    forged = _forge_hs256_with_public_key(pub)
    assert gw.client.post(URL, json=RAG_BODY, headers=bearer(forged)).status_code == 401
    other_priv, _ = _keypair()
    assert gw.client.post(URL, json=RAG_BODY, headers=bearer(rs_token(other_priv))).status_code == 401


def test_issuer_and_audience_are_enforced(make_gw: Callable[..., Gateway]) -> None:
    gw = make_gw(jwt_issuer="https://idp.example.com", jwt_audience="nexus-gateway")
    ok = make_token(iss="https://idp.example.com", aud="nexus-gateway")
    assert gw.client.post(URL, json=RAG_BODY, headers=bearer(ok)).status_code == 200
    for bad in (make_token(), make_token(iss="https://evil.example.com", aud="nexus-gateway"),
                make_token(iss="https://idp.example.com", aud="another-service")):
        assert gw.client.post(URL, json=RAG_BODY, headers=bearer(bad)).status_code == 401


def test_scope_claim_may_be_a_list(gw: Gateway) -> None:
    token = make_token(scope=None, scopes=["rag:query"])
    assert gw.client.post(URL, json=RAG_BODY, headers=bearer(token)).status_code == 200


def test_non_string_tenant_claim_is_403(gw: Gateway) -> None:
    assert gw.client.post(URL, json=RAG_BODY, headers=bearer(make_token(tenant=12345))).status_code == 403  # type: ignore[arg-type]


def test_x_forwarded_for_is_ignored_unless_the_peer_is_a_trusted_proxy(make_gw: Callable[..., Gateway]) -> None:
    gw = make_gw(probe_threshold=3)  # no trusted proxies: spoofing XFF must not let an attacker rotate identities
    for i in range(3):
        gw.client.get(f"/probe{i}", headers={"X-Forwarded-For": f"9.9.9.{i}"})
    assert gw.client.get("/x", headers={"X-Forwarded-For": "8.8.8.8"}).status_code == 429


def test_trusted_proxy_forwarded_for_is_honoured(make_gw: Callable[..., Gateway]) -> None:
    gw = make_gw(probe_threshold=3, trusted_proxies=frozenset({"testclient", "10.0.0.1"}))
    for _ in range(3):
        gw.client.get("/probe", headers={"X-Forwarded-For": "7.7.7.7, 10.0.0.1"})
    assert gw.client.get("/probe", headers={"X-Forwarded-For": "7.7.7.7, 10.0.0.1"}).status_code == 429  # 7.7.7.7 banned
    assert gw.client.get("/probe", headers={"X-Forwarded-For": "5.5.5.5"}).status_code != 429  # a different client is not

"""Authentication: JWT or API key, bound to a mandatory ``X-Tenant`` header."""

from __future__ import annotations

import hmac
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

import jwt

from .settings import TENANT_RE, Settings, hash_api_key

MAX_TOKEN_CHARS = 4096
MAX_API_KEY_CHARS = 256
_DUMMY_HASH = "0" * 64


class AuthError(Exception):
    """Authentication/authorisation failure carrying the HTTP status and a stable error code."""

    def __init__(self, status: int, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    subject: str
    scopes: frozenset[str]
    method: Literal["jwt", "api_key"]


def _single(values: Sequence[str]) -> str | None:
    return values[0] if len(values) == 1 else None


def _claim_scopes(claims: dict[str, object]) -> frozenset[str]:
    raw = claims.get("scopes", claims.get("scope", ""))
    if isinstance(raw, str):
        return frozenset(raw.split())
    if isinstance(raw, list):
        return frozenset(str(x) for x in raw)
    return frozenset()


def authenticate(
    authorization: Sequence[str],
    api_key: Sequence[str],
    tenant_header: Sequence[str],
    settings: Settings,
) -> Principal:
    """Return the authenticated principal or raise :class:`AuthError`.

    * no/invalid credentials -> 401 (never reveals whether a tenant exists)
    * valid credentials but missing/unknown/mismatching ``X-Tenant`` -> 403
    """
    if not authorization and not api_key:
        raise AuthError(401, "missing_credentials")
    if authorization and api_key:
        raise AuthError(401, "ambiguous_credentials")

    if authorization:
        header = _single(authorization)
        if header is None or not header.startswith("Bearer "):
            raise AuthError(401, "invalid_credentials")
        principal = _verify_jwt(header[7:].strip(), settings)
        tenant = _tenant_header(tenant_header)
        if tenant != principal.tenant_id:
            raise AuthError(403, "tenant_mismatch")
    else:
        key = _single(api_key)
        if key is None or not key or len(key) > MAX_API_KEY_CHARS:
            raise AuthError(401, "invalid_credentials")
        tenant = _tenant_header_for_key(tenant_header)
        principal = _verify_api_key(key, tenant, settings)

    cfg = settings.tenants.get(principal.tenant_id)
    if cfg is None:
        raise AuthError(403, "unknown_tenant")
    return Principal(principal.tenant_id, principal.subject, principal.scopes & cfg.scopes, principal.method)


def _tenant_header(values: Sequence[str]) -> str:
    tenant = _single(values)
    if tenant is None or not TENANT_RE.match(tenant):
        raise AuthError(403, "invalid_tenant_header")
    return tenant


def _tenant_header_for_key(values: Sequence[str]) -> str:
    # API keys are looked up per tenant, so a malformed header must not be distinguishable
    # from a wrong key: both are rejected after a constant-time dummy comparison.
    tenant = _single(values)
    if tenant is None or not TENANT_RE.match(tenant):
        raise AuthError(403, "invalid_tenant_header")
    return tenant


def _verify_api_key(key: str, tenant: str, settings: Settings) -> Principal:
    cfg = settings.tenants.get(tenant)
    candidate = hash_api_key(key)
    hashes = cfg.api_key_sha256 if cfg is not None else frozenset({_DUMMY_HASH})
    ok = False
    for stored in hashes:  # no early exit: constant time in the number of keys
        ok |= hmac.compare_digest(candidate, stored)
    if cfg is None or not ok:
        raise AuthError(401, "invalid_credentials")
    return Principal(tenant, f"apikey:{candidate[:12]}", cfg.scopes, "api_key")


def _verify_jwt(token: str, settings: Settings) -> Principal:
    if not token or len(token) > MAX_TOKEN_CHARS:
        raise AuthError(401, "invalid_credentials")
    key = settings.jwt_secret if settings.jwt_algorithm == "HS256" else settings.jwt_public_key
    if not key:
        raise AuthError(401, "jwt_not_enabled")
    kwargs: dict[str, object] = {}
    if settings.jwt_issuer:
        kwargs["issuer"] = settings.jwt_issuer
    if settings.jwt_audience:
        kwargs["audience"] = settings.jwt_audience
    try:
        claims: dict[str, object] = jwt.decode(
            token,
            key,
            algorithms=[settings.jwt_algorithm],  # a fixed allow-list: "none" and alg-confusion are rejected
            leeway=settings.jwt_leeway_seconds,
            options={"require": ["exp", "sub"], "verify_aud": bool(settings.jwt_audience)},
            **kwargs,  # type: ignore[arg-type]
        )
    except jwt.PyJWTError as exc:
        raise AuthError(401, "invalid_credentials", type(exc).__name__) from exc
    tenant = claims.get("tenant_id")
    subject = claims.get("sub")
    if not isinstance(tenant, str) or not TENANT_RE.match(tenant) or not isinstance(subject, str) or not subject:
        raise AuthError(403, "invalid_tenant_claim")
    return Principal(tenant, subject[:128], _claim_scopes(claims), "jwt")

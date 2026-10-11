"""Service-to-service trust: the guard signs what it forwards, upstreams verify before trusting tenant headers."""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Mapping

HEADER_SIGNATURE = "x-guard-signature"
HEADER_TIMESTAMP = "x-guard-timestamp"
HEADER_TENANT = "x-tenant-id"
HEADER_REQUEST_ID = "x-request-id"
HEADER_BODY_SHA = "x-guard-body-sha256"
SIGNATURE_PREFIX = "v1="


def canonical(tenant: str, request_id: str, timestamp: str, method: str, path: str, body_sha256: str) -> bytes:
    return "\n".join((tenant, request_id, timestamp, method.upper(), path, body_sha256)).encode()


def sign(key: bytes, tenant: str, request_id: str, timestamp: str, method: str, path: str, body: bytes) -> tuple[str, str]:
    """Return (signature_header_value, body_sha256_hex)."""
    sha = hashlib.sha256(body).hexdigest()
    mac = hmac.new(key, canonical(tenant, request_id, timestamp, method, path, sha), hashlib.sha256).hexdigest()
    return SIGNATURE_PREFIX + mac, sha


def verify_guard_request(
    headers: Mapping[str, str], method: str, path: str, body: bytes, key: bytes, max_skew_seconds: int = 60,
    now: float | None = None,
) -> str | None:
    """For upstream services: return the verified tenant id, or None if the request did not come from the guard
    (or was tampered with / replayed outside the allowed clock skew)."""
    h = {k.lower(): v for k, v in headers.items()}
    tenant, rid = h.get(HEADER_TENANT), h.get(HEADER_REQUEST_ID)
    ts, sig = h.get(HEADER_TIMESTAMP), h.get(HEADER_SIGNATURE)
    if not (tenant and rid and ts and sig and sig.startswith(SIGNATURE_PREFIX)):
        return None
    try:
        age = abs((time.time() if now is None else now) - int(ts))
    except ValueError:
        return None
    if age > max_skew_seconds:
        return None
    sha = hashlib.sha256(body).hexdigest()
    expected = hmac.new(key, canonical(tenant, rid, ts, method, path, sha), hashlib.sha256).hexdigest()
    return tenant if hmac.compare_digest(sig[len(SIGNATURE_PREFIX):], expected) else None

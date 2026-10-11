"""Gateway configuration. Fails closed: an incomplete configuration refuses to start."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
MIN_SECRET_BYTES = 32


class ConfigError(Exception):
    """Raised when the gateway is misconfigured."""


@dataclass(frozen=True)
class TenantConfig:
    """Per-tenant policy. API keys are stored only as SHA-256 hex digests."""

    api_key_sha256: frozenset[str] = frozenset()
    scopes: frozenset[str] = frozenset()
    rate_limit_per_minute: int = 120


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


@dataclass(frozen=True)
class Settings:
    tenants: Mapping[str, TenantConfig]
    upstreams: Mapping[str, str]
    guard_signing_key: bytes
    jwt_algorithm: str = "HS256"
    jwt_secret: str = ""
    jwt_public_key: str = ""
    jwt_issuer: str = ""
    jwt_audience: str = ""
    jwt_leeway_seconds: int = 10
    admin_api_key: str = ""
    max_body_bytes: int = 64 * 1024
    max_response_bytes: int = 10 * 1024 * 1024
    block_threshold: int = 7
    preauth_rate_per_minute: int = 300
    probe_threshold: int = 8  # failed-auth / shadow-API attempts per window before a temporary ban
    probe_window_seconds: int = 60
    ban_seconds: int = 300
    upstream_timeout_seconds: float = 30.0
    events_url: str = ""
    events_api_key: str = ""
    cors_origins: frozenset[str] = frozenset()
    trusted_proxies: frozenset[str] = frozenset()
    audit_buffer: int = 2000
    extra_headers: Mapping[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        if len(self.guard_signing_key) < MIN_SECRET_BYTES:
            raise ConfigError(f"GUARD_SIGNING_KEY must be at least {MIN_SECRET_BYTES} bytes")
        if self.jwt_algorithm not in {"HS256", "RS256"}:
            raise ConfigError("jwt_algorithm must be HS256 or RS256")
        if self.jwt_algorithm == "HS256" and self.jwt_secret and len(self.jwt_secret.encode()) < MIN_SECRET_BYTES:
            raise ConfigError(f"GUARD_JWT_SECRET must be at least {MIN_SECRET_BYTES} bytes")
        if self.jwt_algorithm == "RS256" and not self.jwt_public_key and self.jwt_secret:
            raise ConfigError("RS256 needs GUARD_JWT_PUBLIC_KEY, not a shared secret")
        has_jwt = bool(self.jwt_secret if self.jwt_algorithm == "HS256" else self.jwt_public_key)
        has_keys = any(t.api_key_sha256 for t in self.tenants.values())
        if not (has_jwt or has_keys):
            raise ConfigError("no authentication method configured (JWT key or tenant API keys)")
        if not self.tenants:
            raise ConfigError("no tenants configured")
        for name, tenant in self.tenants.items():
            if not TENANT_RE.match(name):
                raise ConfigError(f"invalid tenant id {name!r}")
            if tenant.rate_limit_per_minute < 1:
                raise ConfigError(f"tenant {name!r}: rate limit must be >= 1")
        for key in ("rag", "consensus"):
            if not self.upstreams.get(key, "").startswith(("http://", "https://")):
                raise ConfigError(f"upstream {key!r} must be an http(s) URL")
        if self.block_threshold < 1 or self.max_body_bytes < 1:
            raise ConfigError("block_threshold and max_body_bytes must be positive")

    @staticmethod
    def from_env(env: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        raw = e.get("GUARD_TENANTS_JSON", "")
        if not raw and e.get("GUARD_TENANTS_FILE"):
            raw = Path(e["GUARD_TENANTS_FILE"]).read_text()
        try:
            data = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            raise ConfigError(f"tenants configuration is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError("tenants configuration must be a JSON object")
        tenants: dict[str, TenantConfig] = {}
        for name, cfg in data.items():
            if not isinstance(cfg, dict):
                raise ConfigError(f"tenant {name!r} configuration must be an object")
            tenants[str(name)] = TenantConfig(
                api_key_sha256=frozenset(str(k).lower() for k in cfg.get("api_keys_sha256", [])),
                scopes=frozenset(str(s) for s in cfg.get("scopes", [])),
                rate_limit_per_minute=int(cfg.get("rate_limit_per_minute", 120)),
            )

        def csv(name: str) -> frozenset[str]:
            return frozenset(x.strip() for x in e.get(name, "").split(",") if x.strip())

        s = Settings(
            tenants=tenants,
            upstreams={"rag": e.get("GUARD_UPSTREAM_RAG", ""), "consensus": e.get("GUARD_UPSTREAM_CONSENSUS", "")},
            guard_signing_key=e.get("GUARD_SIGNING_KEY", "").encode(),
            jwt_algorithm=e.get("GUARD_JWT_ALGORITHM", "HS256"),
            jwt_secret=e.get("GUARD_JWT_SECRET", ""),
            jwt_public_key=e.get("GUARD_JWT_PUBLIC_KEY", ""),
            jwt_issuer=e.get("GUARD_JWT_ISSUER", ""),
            jwt_audience=e.get("GUARD_JWT_AUDIENCE", ""),
            admin_api_key=e.get("GUARD_ADMIN_API_KEY", ""),
            max_body_bytes=int(e.get("GUARD_MAX_BODY_BYTES", str(64 * 1024))),
            block_threshold=int(e.get("GUARD_BLOCK_THRESHOLD", "7")),
            preauth_rate_per_minute=int(e.get("GUARD_PREAUTH_RATE_PER_MINUTE", "300")),
            probe_threshold=int(e.get("GUARD_PROBE_THRESHOLD", "8")),
            probe_window_seconds=int(e.get("GUARD_PROBE_WINDOW_SECONDS", "60")),
            ban_seconds=int(e.get("GUARD_BAN_SECONDS", "300")),
            upstream_timeout_seconds=float(e.get("GUARD_UPSTREAM_TIMEOUT_SECONDS", "30")),
            events_url=e.get("GUARD_EVENTS_URL", ""),
            events_api_key=e.get("GUARD_EVENTS_API_KEY", ""),
            cors_origins=csv("GUARD_CORS_ORIGINS"),
            trusted_proxies=csv("GUARD_TRUSTED_PROXIES"),
        )
        s.validate()
        return s

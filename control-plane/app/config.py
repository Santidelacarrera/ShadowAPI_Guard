import os


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


class Settings:
    """Read lazily from the environment so tests can override variables."""

    @property
    def database_url(self) -> str:
        return _env("DATABASE_URL", "sqlite+pysqlite:///./shadowapi.db")

    @property
    def clickhouse_url(self) -> str:
        return _env("CLICKHOUSE_URL", "http://localhost:8123")

    @property
    def clickhouse_user(self) -> str:
        return _env("CLICKHOUSE_USER", "default")

    @property
    def clickhouse_password(self) -> str:
        return _env("CLICKHOUSE_PASSWORD", "")

    @property
    def clickhouse_ttl_days(self) -> int:
        """Retention for stored events (0 = keep forever)."""
        return int(_env("CLICKHOUSE_TTL_DAYS", "90"))

    @property
    def api_key(self) -> str:
        """If set, every request must carry it in X-API-Key."""
        return _env("API_KEY")

    @property
    def waf_url(self) -> str:
        return _env("WAF_URL")

    @property
    def waf_api_key(self) -> str:
        return _env("WAF_API_KEY") or self.api_key

    @property
    def waf_shadow_policy(self) -> str:
        """monitor | block: what to do with shadow endpoints."""
        return _env("WAF_SHADOW_POLICY", "monitor")

    @property
    def redteam_allowed_hosts(self) -> set[str]:
        return {h.strip() for h in _env("REDTEAM_ALLOWED_HOSTS").split(",") if h.strip()}


settings = Settings()

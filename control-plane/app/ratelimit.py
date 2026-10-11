"""Token-bucket limiter for the ingest endpoint (per client)."""
import os
import threading
import time

_lock = threading.Lock()
_buckets: dict[str, tuple[float, float]] = {}


def allow(client: str) -> bool:
    rate = float(os.environ.get("EVENTS_RATE_LIMIT", "200"))  # batches per second; 0 disables
    if rate <= 0:
        return True
    burst = rate * 2
    now = time.monotonic()
    with _lock:
        tokens, last = _buckets.get(client, (burst, now))
        tokens = min(burst, tokens + (now - last) * rate)
        if tokens < 1:
            _buckets[client] = (tokens, now)
            return False
        _buckets[client] = (tokens - 1, now)
        return True


def reset() -> None:
    _buckets.clear()

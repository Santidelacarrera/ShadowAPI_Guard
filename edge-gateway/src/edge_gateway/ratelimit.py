"""Token-bucket rate limiting."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    last: float


class RateLimiter:
    """Per-key token bucket: ``per_minute`` sustained rate with a burst of the same size."""

    def __init__(self, clock: Callable[[], float] = time.monotonic, max_keys: int = 50_000) -> None:
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._max_keys = max_keys

    def allow(self, key: str, per_minute: int) -> bool:
        now = self._clock()
        capacity = float(per_minute)
        b = self._buckets.get(key)
        if b is None:
            if len(self._buckets) >= self._max_keys:  # bound memory against key-spraying
                self._buckets.clear()
            b = self._buckets[key] = _Bucket(capacity, now)
        b.tokens = min(capacity, b.tokens + (now - b.last) * capacity / 60.0)
        b.last = now
        if b.tokens < 1.0:
            return False
        b.tokens -= 1.0
        return True

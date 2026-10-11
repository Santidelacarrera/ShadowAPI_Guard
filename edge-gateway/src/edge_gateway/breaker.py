"""Circuit breaker per upstream: fail fast while an upstream is down instead of piling up requests."""

from __future__ import annotations

import time
from collections.abc import Callable


class CircuitBreaker:
    def __init__(self, failures: int = 5, reset_seconds: float = 10.0, clock: Callable[[], float] = time.monotonic) -> None:
        self._failures = failures
        self._reset = reset_seconds
        self._clock = clock
        self._count = 0
        self._opened_at: float | None = None

    def allow(self) -> bool:
        if self._opened_at is None:
            return True
        if self._clock() - self._opened_at >= self._reset:
            return True  # half-open: let one probe through
        return False

    def success(self) -> None:
        self._count = 0
        self._opened_at = None

    def failure(self) -> None:
        self._count += 1
        if self._count >= self._failures:
            self._opened_at = self._clock()

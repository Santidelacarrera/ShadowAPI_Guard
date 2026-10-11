"""Minimal Prometheus-style counters."""

from __future__ import annotations

import threading
from collections import defaultdict


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = defaultdict(int)

    def inc(self, name: str, **labels: str) -> None:
        with self._lock:
            self._counters[(name, tuple(sorted(labels.items())))] += 1

    def value(self, name: str, **labels: str) -> int:
        with self._lock:
            return self._counters.get((name, tuple(sorted(labels.items()))), 0)

    def render(self) -> str:
        with self._lock:
            items = sorted(self._counters.items())
        lines: list[str] = []
        seen: set[str] = set()
        for (name, labels), v in items:
            if name not in seen:
                lines.append(f"# TYPE {name} counter")
                seen.add(name)
            lab = "{" + ",".join(f'{k}="{val}"' for k, val in labels) + "}" if labels else ""
            lines.append(f"{name}{lab} {v}")
        return "\n".join(lines) + "\n"

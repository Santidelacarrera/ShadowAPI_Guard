"""Perimeter security audit trail. Never records payload contents: only hashes, sizes and capped excerpts."""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Literal

log = logging.getLogger("shadowapi.audit")

EventType = Literal[
    "allowed", "flagged", "auth_failed", "forbidden", "shadow_api", "method_not_allowed", "schema_anomaly",
    "threat_blocked", "rate_limited", "banned", "malformed", "upstream_error", "cors_denied",
]
_ID = re.compile(r"/(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{24})(?=/|$)")
_UNSAFE = re.compile(r"[^\x20-\x7e]")


def safe_path(path: str, limit: int = 200) -> str:
    """Path for logs/events: printable ASCII only, ids collapsed, capped. Query strings are never kept."""
    return _ID.sub("/{id}", _UNSAFE.sub("?", path.split("?", 1)[0]))[:limit]


@dataclass(frozen=True)
class AuditEvent:
    type: EventType
    decision: Literal["allow", "deny"]
    status: int
    request_id: str
    method: str
    path: str
    client_ip: str
    tenant: str | None = None
    subject: str | None = None
    route: str | None = None
    detail: str = ""
    findings: tuple[dict[str, object], ...] = ()
    payload_sha256: str = ""
    payload_bytes: int = 0
    trace_id: str = ""
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    ts: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, object]:
        d = asdict(self)
        d["findings"] = list(self.findings)
        return d


class AuditLog:
    """Ring buffer + structured log line + optional sink (e.g. the ShadowAPI control-plane forwarder)."""

    def __init__(self, capacity: int = 2000, sink: Callable[[AuditEvent], None] | None = None) -> None:
        self._events: deque[AuditEvent] = deque(maxlen=capacity)
        self._sink = sink

    def emit(self, event: AuditEvent) -> None:
        self._events.append(event)
        level = logging.INFO if event.decision == "allow" else logging.WARNING
        log.log(level, json.dumps(event.as_dict(), default=str, separators=(",", ":")))
        if self._sink is not None:
            try:
                self._sink(event)
            except Exception:  # auditing must never break the request path
                log.exception("audit sink failed")

    def tail(self, limit: int = 100, event_type: str | None = None) -> list[dict[str, object]]:
        items = [e for e in reversed(self._events) if event_type is None or e.type == event_type]
        return [e.as_dict() for e in items[:limit]]

    def count(self, event_type: str) -> int:
        return sum(1 for e in self._events if e.type == event_type)

"""Structural anomaly detection: strict JSON parsing, size/shape limits, behavioural baselines, scanner bans."""

from __future__ import annotations

import json
import math
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field


class PayloadError(Exception):
    """The body is not acceptable JSON. ``code`` is a stable machine-readable reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Limits:
    max_depth: int = 8
    max_keys: int = 200  # total object keys in the document
    max_array_len: int = 500
    max_nodes: int = 5000
    max_int_digits: int = 18


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen: dict[str, object] = {}
    for k, v in pairs:
        if k in seen:
            raise PayloadError("duplicate_key", "JSON parameter pollution")
        seen[k] = v
    return seen


def _reject_constant(name: str) -> object:
    raise PayloadError("invalid_number", f"{name} is not allowed")


def _parse_int(text: str, limits: Limits = Limits()) -> int:
    if len(text.lstrip("-")) > limits.max_int_digits:
        raise PayloadError("integer_too_large")
    return int(text)


def parse_json(body: bytes, limits: Limits = Limits()) -> object:
    """Strict, bounded JSON parsing: UTF-8 only, no duplicate keys, no NaN/Infinity, no huge integers."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PayloadError("invalid_encoding") from exc
    if text.startswith("﻿"):
        raise PayloadError("invalid_encoding", "BOM not allowed")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_constant=_reject_constant,
            parse_int=lambda t: _parse_int(t, limits),
        )
    except PayloadError:
        raise
    except RecursionError as exc:
        raise PayloadError("too_deep") from exc
    except ValueError as exc:
        raise PayloadError("invalid_json") from exc
    check_structure(value, limits)
    return value


def check_structure(value: object, limits: Limits = Limits()) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = keys = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if depth > limits.max_depth:
            raise PayloadError("too_deep")
        if nodes > limits.max_nodes:
            raise PayloadError("too_many_nodes")
        if isinstance(node, dict):
            keys += len(node)
            if keys > limits.max_keys:
                raise PayloadError("too_many_keys")
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            if len(node) > limits.max_array_len:
                raise PayloadError("array_too_long")
            stack.extend((v, depth + 1) for v in node)


@dataclass
class _Welford:
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def push(self, x: float) -> None:
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    def zscore(self, x: float) -> float:
        if self.n < 2:
            return 0.0
        std = math.sqrt(self.m2 / (self.n - 1))
        return abs(x - self.mean) / max(std, 16.0)  # 16-byte floor: tiny variances must not alarm


class SizeBaseline:
    """Per (tenant, route) running mean/std of body size; flags payloads far outside the learned envelope."""

    def __init__(self, min_samples: int = 50, z_limit: float = 6.0) -> None:
        self._stats: dict[tuple[str, str], _Welford] = defaultdict(_Welford)
        self.min_samples = min_samples
        self.z_limit = z_limit

    def observe(self, tenant: str, route: str, size: int) -> bool:
        """Record ``size``; return True when it is anomalous w.r.t. the baseline *before* this sample."""
        w = self._stats[(tenant, route)]
        anomalous = w.n >= self.min_samples and w.zscore(float(size)) > self.z_limit
        if not anomalous:  # outliers must not shift the baseline an attacker could slowly poison
            w.push(float(size))
        return anomalous


@dataclass
class ProbeTracker:
    """Counts hostile events per client in a sliding window and bans scanners temporarily."""

    threshold: int
    window_seconds: float
    ban_seconds: float
    clock: Callable[[], float] = time.monotonic
    _events: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))
    _banned: dict[str, float] = field(default_factory=dict)

    def record(self, client: str) -> bool:
        """Register one hostile event; return True if the client is now banned."""
        now = self.clock()
        q = self._events[client]
        q.append(now)
        while q and now - q[0] > self.window_seconds:
            q.popleft()
        if len(q) >= self.threshold:
            self._banned[client] = now + self.ban_seconds
            q.clear()
            return True
        return False

    def is_banned(self, client: str) -> bool:
        until = self._banned.get(client)
        if until is None:
            return False
        if self.clock() >= until:
            del self._banned[client]
            return False
        return True

    def prune(self) -> None:
        now = self.clock()
        for k in [k for k, u in self._banned.items() if u <= now]:
            del self._banned[k]
        for k in [k for k, q in self._events.items() if not q or now - q[-1] > self.window_seconds]:
            del self._events[k]

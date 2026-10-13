"""Best-effort forwarding of audit events to the ShadowAPI Guard control plane (``POST /events``)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

import httpx

from .audit import AuditEvent

log = logging.getLogger("shadowapi.events")


class EventForwarder:
    """Bounded queue + batching background task. Drops (and counts) events rather than blocking the gateway."""

    def __init__(self, url: str, api_key: str = "", client: httpx.AsyncClient | None = None, max_queue: int = 5000) -> None:
        self._url = url.rstrip("/") + "/events"
        self._headers = {"X-API-Key": api_key} if api_key else {}
        self._client = client
        self._owns_client = client is None
        self._queue: asyncio.Queue[dict[str, Any]] | None = None
        self._max_queue = max_queue
        self._task: asyncio.Task[None] | None = None
        self._inflight: list[dict[str, Any]] = []  # popped from the queue but not yet acknowledged: flushed on shutdown
        self.dropped = 0
        self.sent = 0

    @staticmethod
    def to_control_plane(e: AuditEvent) -> dict[str, Any]:
        return {"ts": e.ts, "method": e.method, "path": e.path, "host": "edge-gateway", "status": e.status,
                "subject": e.tenant or "", "source": "edge-gateway"}

    def submit(self, event: AuditEvent) -> None:
        if self._queue is None:
            return
        try:
            self._queue.put_nowait(self.to_control_plane(event))
        except asyncio.QueueFull:
            self.dropped += 1

    async def start(self) -> None:
        self._queue = asyncio.Queue(self._max_queue)
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=5)
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        await self.flush()  # at-least-once on shutdown: includes the batch that was being assembled/sent
        if self._owns_client and self._client is not None:
            await self._client.aclose()

    async def flush(self) -> None:
        if self._queue is None:
            return
        batch, self._inflight = self._inflight, []
        while not self._queue.empty():
            batch.append(self._queue.get_nowait())
            if len(batch) >= 200:
                await self._send(batch)
                batch = []
        await self._send(batch)

    async def _send(self, batch: list[dict[str, Any]]) -> None:
        if not batch or self._client is None:
            return
        try:
            r = await self._client.post(self._url, json=batch, headers=self._headers)
            if r.status_code < 300:
                self.sent += len(batch)
            else:
                self.dropped += len(batch)
        except httpx.HTTPError:
            self.dropped += len(batch)

    async def _run(self) -> None:
        if self._queue is None:
            raise RuntimeError("EventForwarder.start() must be awaited before the worker runs")
        while True:
            self._inflight = [await self._queue.get()]
            await asyncio.sleep(0.2)
            while not self._queue.empty() and len(self._inflight) < 200:
                self._inflight.append(self._queue.get_nowait())
            await self._send(self._inflight)
            self._inflight = []

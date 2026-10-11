"""Simulation probe: ASGI middleware that mirrors L7 traffic to the detector.

This is the local/test fallback for the eBPF probe: it emits the same event shape
(method, path, host, status, bodies, Authorization) without needing a kernel.
"""
import json
import os
import queue
import threading
import time

import httpx

MAX = 4096


class CaptureMiddleware:
    def __init__(self, app, detector_url: str | None = None, source: str = "gateway-sim"):
        self.app = app
        self.url = (detector_url or os.environ.get("DETECTOR_URL", "")).rstrip("/")
        self.source = source
        self.q: queue.Queue = queue.Queue(maxsize=10000)
        if self.url:
            threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        client = httpx.Client(timeout=5)
        while True:
            batch = [self.q.get()]
            deadline = time.time() + 0.3
            while len(batch) < 100 and time.time() < deadline:
                try:
                    batch.append(self.q.get(timeout=0.05))
                except queue.Empty:
                    pass
            try:
                client.post(self.url + "/events", json=batch)
            except httpx.HTTPError:
                pass  # observability must never break the data path

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"].startswith("/__"):
            return await self.app(scope, receive, send)
        req_body, resp_body, status = bytearray(), bytearray(), 0

        async def rcv():
            msg = await receive()
            if msg["type"] == "http.request" and len(req_body) < MAX:
                req_body.extend(msg.get("body", b"")[: MAX - len(req_body)])
            return msg

        async def snd(msg):
            nonlocal status
            if msg["type"] == "http.response.start":
                status = msg["status"]
            elif msg["type"] == "http.response.body" and len(resp_body) < MAX:
                resp_body.extend(msg.get("body", b"")[: MAX - len(resp_body)])
            await send(msg)

        try:
            await self.app(scope, rcv, snd)
        finally:
            if self.url:
                headers = {k.decode().lower(): v.decode("latin-1") for k, v in scope["headers"]}
                qs = scope.get("query_string", b"").decode("latin-1")
                ev = {
                    "ts": time.time(), "method": scope["method"],
                    "path": scope["path"] + ("?" + qs if qs else ""),
                    "host": headers.get("host", ""), "status": status,
                    "req_body": req_body.decode("utf-8", "replace"), "resp_body": resp_body.decode("utf-8", "replace"),
                    "authorization": headers.get("authorization", ""),
                    "source": "redteam" if "x-shadowapi-scan" in headers else self.source,
                }
                try:
                    self.q.put_nowait(ev)
                except queue.Full:
                    pass

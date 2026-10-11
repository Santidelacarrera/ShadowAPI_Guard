"""Gateway WAF: enforces rules synced from the control plane (block / rate_limit / mask_pii)."""
import hmac
import json
import os
import re
import time
from collections import defaultdict, deque

try:  # shared module with the control plane (copied next to this file in the image)
    from pii import redact_text
except ImportError:  # local checkout
    import pathlib
    import sys
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "control-plane" / "app"))
    from pii import redact_text

_ID = re.compile(r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{24})$")


def templatize(path: str) -> str:
    out = "/".join("{id}" if _ID.match(s) else s for s in path.split("/"))
    return out.rstrip("/") if len(out) > 1 else out or "/"


class WafMiddleware:
    def __init__(self, app, api_key: str | None = None):
        self.app = app
        self.api_key = api_key if api_key is not None else os.environ.get("WAF_API_KEY", "")
        self.version = "none"
        self.rules: list[dict] = []
        self.hits: dict[tuple, deque] = defaultdict(deque)

    def _match(self, method: str, path: str, action: str):
        for r in self.rules:
            if r["action"] == action and r["method"] in ("*", method) and r["path"] in ("*", path):
                return r
        return None

    async def _json(self, send, status: int, obj) -> None:
        body = json.dumps(obj).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope["path"]
        if path == "/__waf/rules":
            headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
            if self.api_key and not hmac.compare_digest(headers.get("x-api-key", ""), self.api_key):
                return await self._json(send, 401, {"error": "unauthorized"})
            if scope["method"] == "PUT":
                body = b""
                while True:
                    m = await receive()
                    body += m.get("body", b"")
                    if not m.get("more_body"):
                        break
                doc = json.loads(body)
                self.rules, self.version = doc["rules"], doc["version"]
                return await self._json(send, 200, {"version": self.version, "rules": len(self.rules)})
            return await self._json(send, 200, {"version": self.version, "rules": self.rules})

        method, tpl = scope["method"], templatize(path)
        if self._match(method, tpl, "block"):
            return await self._json(send, 403, {"error": "blocked by ShadowAPI Guard", "rule": tpl})
        rl = self._match(method, tpl, "rate_limit")
        if rl:
            client = (scope.get("client") or ("?", 0))[0]
            key = (method, tpl, client)
            now, q = time.time(), self.hits[key]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= rl.get("limit_per_minute", 30):
                return await self._json(send, 429, {"error": "rate limited by ShadowAPI Guard"})
            q.append(now)

        if not self._match("*", "*", "mask_pii"):
            return await self.app(scope, receive, send)

        # buffer the response so that text/JSON bodies can be masked
        start, chunks = None, []

        async def snd(msg):
            nonlocal start
            if msg["type"] == "http.response.start":
                start = msg
            elif msg["type"] == "http.response.body":
                chunks.append(msg.get("body", b""))
                if msg.get("more_body"):
                    return
                body = b"".join(chunks)
                ctype = dict((k.lower(), v) for k, v in start["headers"]).get(b"content-type", b"")
                if b"json" in ctype or b"text" in ctype:
                    body = redact_text(body.decode("utf-8", "replace"))[0].encode()
                hdrs = [(k, v) for k, v in start["headers"] if k.lower() != b"content-length"]
                hdrs.append((b"content-length", str(len(body)).encode()))
                await send({**start, "headers": hdrs})
                await send({"type": "http.response.body", "body": body})

        await self.app(scope, receive, snd)

"""Stand-ins for ContextRAG_Engine and MultiAgent_Consensus, for local development and tests.

They behave like well-behaved internal services: they trust the tenant only if the guard's signature verifies.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .signing import verify_guard_request


def make_upstream(name: str, key: bytes) -> FastAPI:
    app = FastAPI(title=f"mock {name}")
    app.state.seen = []

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def anything(request: Request, path: str) -> JSONResponse:
        body = await request.body()
        tenant = verify_guard_request(dict(request.headers), request.method, request.url.path, body, key)
        seen = {"method": request.method, "path": request.url.path, "headers": dict(request.headers),
                "body": body.decode(errors="replace"), "verified_tenant": tenant}
        app.state.seen.append(seen)
        if tenant is None:
            return JSONResponse({"error": "untrusted caller"}, status_code=401)
        return JSONResponse({"service": name, "tenant": tenant, "path": request.url.path}, headers={"set-cookie": "leak=1",
                                                                                                   "server": f"{name}/1.0"})

    return app


def rag_app() -> FastAPI:  # pragma: no cover - dev entry point (uvicorn --factory)
    return make_upstream("ContextRAG_Engine", os.environ["GUARD_SIGNING_KEY"].encode())


def consensus_app() -> FastAPI:  # pragma: no cover
    return make_upstream("MultiAgent_Consensus", os.environ["GUARD_SIGNING_KEY"].encode())

"""OpenAPI 3.1 document of the documented surface, derived from the route table and request schemas.

Register it as the official catalog in the ShadowAPI control plane (``PUT /catalog/edge``) so that drift detection
compares observed traffic against exactly what this gateway is willing to forward.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .routes import RouteTable


def build_openapi(routes: RouteTable) -> dict[str, Any]:
    paths: dict[str, dict[str, Any]] = {}
    for r in routes.routes:
        op: dict[str, Any] = {
            "operationId": r.name,
            "summary": f"{r.method} {r.template} -> {r.upstream}",
            "x-required-scope": r.scope,
            "security": [{"bearerAuth": [], "tenantHeader": []}, {"apiKey": [], "tenantHeader": []}],
            "responses": {
                "200": {"description": "Forwarded upstream response"},
                "401": {"description": "Missing or invalid credentials"},
                "403": {"description": "Tenant mismatch, insufficient scope or blocked by the WAF"},
                "422": {"description": "Request does not match the documented schema"},
                "429": {"description": "Rate limited"},
            },
        }
        params = [seg[1:-1] for seg in r.segments if seg.startswith("{")]
        if params:
            op["parameters"] = [{"name": p, "in": "path", "required": True, "schema": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"}}
                                for p in params]
        if r.body_model is not None:
            op["requestBody"] = {"required": True, "content": {"application/json": {"schema": r.body_model.model_json_schema()}}}
        paths.setdefault(r.template, {})[r.method.lower()] = op
    return {
        "openapi": "3.1.0",
        "info": {"title": "ShadowAPI Guard edge gateway - documented surface", "version": __version__},
        "paths": paths,
        "components": {"securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
            "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            "tenantHeader": {"type": "apiKey", "in": "header", "name": "X-Tenant"},
        }},
    }

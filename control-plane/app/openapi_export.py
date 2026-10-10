"""Build an OpenAPI 3.1 draft from observed traffic."""
from datetime import date

from . import db
from .catalog import compute_drift
from .schema import to_openapi_schema


def _params(path: str) -> tuple[str, list[str]]:
    """Rename repeated {id} placeholders ({id}, {id_2}...) so the document is valid."""
    names, out = [], []
    for seg in path.split("/"):
        if seg == "{id}":
            n = "id" if "id" not in names else f"id_{len([x for x in names if x.startswith('id')]) + 1}"
            names.append(n)
            seg = "{" + n + "}"
        out.append(seg)
    return "/".join(out), names


def build(scope: str = "shadow") -> dict:
    observed = {(o["method"], o["path"]): o for o in db.list_observed()}
    if scope == "shadow":
        wanted = {(s["method"], s["path"]) for s in compute_drift()["shadow"]}
        observed = {k: v for k, v in observed.items() if k in wanted}
    schemas = {(s["method"], s["path"], s["direction"]): s["schema"] for s in db.list_schemas()}
    paths: dict = {}
    for (method, path), o in sorted(observed.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        templ, names = _params(path)
        op: dict = {
            "summary": f"{method} {path} (inferred from traffic)",
            "x-shadowapi": {"hits": o["hits"], "first_seen": o["first_seen"].isoformat(), "last_seen": o["last_seen"].isoformat(),
                            "shadow": scope == "shadow"},
            "responses": {"200": {"description": "Inferred from observed 2xx responses"}},
        }
        if names:
            op["parameters"] = [{"name": n, "in": "path", "required": True, "schema": {"type": "string"}} for n in names]
        req = schemas.get((method, path, "request"))
        if req:
            op["requestBody"] = {"content": {"application/json": {"schema": to_openapi_schema(req)}}}
        resp = schemas.get((method, path, "response"))
        if resp:
            op["responses"]["200"]["content"] = {"application/json": {"schema": to_openapi_schema(resp)}}
        paths.setdefault(templ, {})[method.lower()] = op
    return {"openapi": "3.1.0", "info": {"title": "ShadowAPI inferred specification", "version": date.today().isoformat(),
                                         "description": "Draft generated from observed traffic. Review before adopting."},
            "paths": paths}

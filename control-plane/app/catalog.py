"""OpenAPI catalog parsing and drift computation."""
import json

import yaml

from . import db
from .paths import matches, normalize_catalog_path
from .schema import extra_fields, from_openapi_schema, resolve_refs

HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def _json_schema(content: dict | None, doc: dict) -> str | None:
    for ctype, body in (content or {}).items():
        if "json" in ctype and isinstance(body, dict) and "schema" in body:
            red = from_openapi_schema(resolve_refs(body["schema"], doc))
            return json.dumps(red) if red else None
    return None


def parse_openapi(raw: bytes | str) -> list[tuple]:
    """Return (METHOD, normalized_path, raw_path, req_schema_json, resp_schema_json) for every operation.
    Accepts JSON or YAML."""
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ValueError(f"invalid document: {e}") from e
    if not isinstance(doc, dict) or not str(doc.get("openapi", "")).startswith("3"):
        raise ValueError("not an OpenAPI 3.x document")
    paths = doc.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise ValueError("document has no paths")
    out = []
    for p, item in paths.items():
        if not isinstance(item, dict):
            continue
        for m in item:
            if m.lower() in HTTP_METHODS and isinstance(item[m], dict):
                op = item[m]
                req = _json_schema((op.get("requestBody") or {}).get("content"), doc)
                resp = None
                for code, r in (op.get("responses") or {}).items():
                    if str(code).startswith("2") and isinstance(r, dict):
                        resp = _json_schema(r.get("content"), doc)
                        if resp:
                            break
                out.append((m.upper(), normalize_catalog_path(p), p, req, resp))
    if not out:
        raise ValueError("document has no operations")
    return out


def compute_drift(min_hits: int = 1) -> dict:
    cat = db.list_catalog()
    obs = db.list_observed()
    cat_keys = {(c["method"], c["path"]) for c in cat}

    def documented(o: dict) -> bool:
        return any(m == o["method"] and matches(p, o["path"]) for m, p in cat_keys)

    accepted = db.list_accepted()

    def is_accepted(o: dict) -> bool:
        return any(a["method"] in ("*", o["method"]) and matches(a["path"], o["path"]) for a in accepted)

    undocumented = [o for o in obs if o["hits"] >= min_hits and not documented(o)]
    shadow = [o for o in undocumented if not is_accepted(o)]
    zombie = [c for c in cat if not any(o["method"] == c["method"] and matches(c["path"], o["path"]) for o in obs)]
    documented_seen = len(obs) - len([o for o in obs if not documented(o)])
    schema_drift = _schema_drift(cat)
    return {
        "summary": {"catalog": len(cat), "observed": len(obs), "shadow": len(shadow), "unused": len(zombie),
                    "documented_seen": documented_seen, "schema_drift": len(schema_drift),
                    "accepted": len(undocumented) - len(shadow)},
        "shadow": [{"method": o["method"], "path": o["path"], "host": o["host"], "hits": o["hits"],
                    "first_seen": o["first_seen"].isoformat(), "last_seen": o["last_seen"].isoformat()} for o in shadow],
        "unused": [{"method": c["method"], "path": c["raw_path"]} for c in zombie],
        "schema_drift": schema_drift,
    }


def _schema_drift(cat: list[dict]) -> list[dict]:
    """Fields observed in traffic but missing from the documented request/response schema."""
    out = []
    observed = {(s["method"], s["path"], s["direction"]): s["schema"] for s in db.list_schemas()}
    for c in cat:
        for direction, col in (("request", "req_schema"), ("response", "resp_schema")):
            if not c.get(col):
                continue
            documented = json.loads(c[col])
            for (m, p, d), schema in observed.items():
                if d == direction and m == c["method"] and matches(c["path"], p):
                    extra = extra_fields(schema, documented)
                    if extra:
                        out.append({"method": m, "path": c["raw_path"], "direction": d, "undocumented_fields": extra,
                                    "pii": sorted({k for f in extra for k in f["pii"]})})
    return out


def is_documented(method: str, path: str) -> bool:
    """True when the endpoint is in the catalog or has been explicitly accepted (allow-listed)."""
    return any(c["method"] == method and matches(c["path"], path) for c in db.list_catalog()) or \
        any(a["method"] in ("*", method) and matches(a["path"], path) for a in db.list_accepted())

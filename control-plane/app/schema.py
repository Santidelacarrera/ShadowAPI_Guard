"""Schema inference from observed (already redacted) JSON bodies, merging and drift."""
import json
import re
from typing import Any

MARKER_FORMATS = {"EMAIL": "email", "CARD": "card", "RUT": "rut", "JWT": "jwt", "BEARER": "token", "APIKEY": "apikey"}
# bandit B105 accepted: "secret" labels a redaction kind, it is not a credential
MARKER_FORMATS["SECRET"] = "secret"  # nosec B105
_MARKER = re.compile(r"^\[REDACTED:([A-Z]+)\]$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?")
MAX_DEPTH = 8
MAX_PROPS = 200


def infer(value: Any, depth: int = 0) -> dict:
    """Infer a JSON-schema-like description. Values are never kept, only types/formats."""
    if value is None:
        return {"type": ["null"]}
    if isinstance(value, bool):
        return {"type": ["boolean"]}
    if isinstance(value, int):
        return {"type": ["integer"]}
    if isinstance(value, float):
        return {"type": ["number"]}
    if isinstance(value, str):
        s: dict = {"type": ["string"]}
        m = _MARKER.match(value)
        if m:
            s["x-pii"] = [m.group(1)]
            if m.group(1) in MARKER_FORMATS:
                s["format"] = MARKER_FORMATS[m.group(1)]
        elif _UUID.match(value):
            s["format"] = "uuid"
        elif _DATE.match(value):
            s["format"] = "date-time"
        return s
    if depth >= MAX_DEPTH:
        return {"type": ["object" if isinstance(value, dict) else "array"]}
    if isinstance(value, list):
        items: dict = {}
        for v in value[:20]:
            items = merge(items, infer(v, depth + 1)) if items else infer(v, depth + 1)
        out: dict = {"type": ["array"]}
        if items:
            out["items"] = items
        return out
    if isinstance(value, dict):
        props = {k: infer(v, depth + 1) for k, v in list(value.items())[:MAX_PROPS]}
        return {"type": ["object"], "properties": props, "required": sorted(props)}
    return {}


def merge(a: dict, b: dict) -> dict:
    """Union of two inferred schemas; `required` is the intersection."""
    if not a:
        return b
    if not b:
        return a
    out: dict = {"type": sorted(set(a.get("type", [])) | set(b.get("type", [])))}
    for k in ("format",):
        if k in a and k in b and a[k] == b[k]:
            out[k] = a[k]
    pii = sorted(set(a.get("x-pii", [])) | set(b.get("x-pii", [])))
    if pii:
        out["x-pii"] = pii
    if "properties" in a or "properties" in b:
        pa, pb = a.get("properties", {}), b.get("properties", {})
        out["properties"] = {k: merge(pa.get(k, {}), pb.get(k, {})) for k in sorted(set(pa) | set(pb))}
        ra = set(a.get("required", pa.keys())) if "properties" in a else None
        rb = set(b.get("required", pb.keys())) if "properties" in b else None
        req = (ra if rb is None else rb if ra is None else ra & rb) or set()
        out["required"] = sorted(req & set(out["properties"]))
    if "items" in a or "items" in b:
        out["items"] = merge(a.get("items", {}), b.get("items", {}))
    return out


def flatten(schema: dict, prefix: str = "") -> dict[str, dict]:
    """dotted.field.path -> leaf schema (arrays use `[]`)."""
    out: dict[str, dict] = {}
    for k, v in schema.get("properties", {}).items():
        p = f"{prefix}.{k}" if prefix else k
        out[p] = v
        out.update(flatten(v, p))
    if "items" in schema:
        out.update(flatten(schema["items"], prefix + "[]"))
    return out


def extra_fields(observed: dict, documented: dict) -> list[dict]:
    """Fields seen in traffic but absent from the documented schema."""
    doc = set(flatten(documented))
    res = []
    for path, sch in sorted(flatten(observed).items()):
        if path not in doc:
            res.append({"field": path, "type": sch.get("type", []), "pii": sch.get("x-pii", [])})
    return res


def to_openapi_schema(s: dict) -> dict:
    """Convert our inferred schema to an OpenAPI 3.1 / JSON-Schema 2020-12 object."""
    out: dict = {}
    types = [t for t in s.get("type", [])]
    if types:
        out["type"] = types[0] if len(types) == 1 else types
    if "format" in s and s["format"] in ("email", "uuid", "date-time"):
        out["format"] = s["format"]
    if "x-pii" in s:
        out["x-pii"] = s["x-pii"]
    if "properties" in s:
        out["properties"] = {k: to_openapi_schema(v) for k, v in s["properties"].items()}
        if s.get("required"):
            out["required"] = s["required"]
    if "items" in s:
        out["items"] = to_openapi_schema(s["items"])
    return out


def resolve_refs(node: Any, root: dict, depth: int = 0) -> Any:
    """Inline local $refs (bounded depth) so OpenAPI schemas can be compared with inferred ones."""
    if depth > 10:
        return {}
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/"):
            target: Any = root
            for part in ref[2:].split("/"):
                target = target.get(part, {}) if isinstance(target, dict) else {}
            return resolve_refs(target, root, depth + 1)
        return {k: resolve_refs(v, root, depth + 1) for k, v in node.items()}
    if isinstance(node, list):
        return [resolve_refs(v, root, depth + 1) for v in node]
    return node


def from_openapi_schema(s: dict) -> dict:
    """Reduce an OpenAPI schema object to the subset we compare (properties/items), merging allOf/oneOf/anyOf."""
    if not isinstance(s, dict):
        return {}
    out: dict = {}
    for key in ("allOf", "oneOf", "anyOf"):
        for sub in s.get(key, []) or []:
            out = merge(out, from_openapi_schema(sub)) if out else from_openapi_schema(sub)
    if isinstance(s.get("properties"), dict):
        props = {k: from_openapi_schema(v) for k, v in s["properties"].items()}
        out = merge(out, {"type": ["object"], "properties": props, "required": s.get("required", [])}) if out else \
            {"type": ["object"], "properties": props, "required": s.get("required", [])}
    if isinstance(s.get("items"), dict):
        out = merge(out, {"type": ["array"], "items": from_openapi_schema(s["items"])})
    return out


def parse_body(body: str) -> Any | None:
    try:
        v = json.loads(body)
    except (ValueError, TypeError):
        return None
    return v if isinstance(v, (dict, list)) else None

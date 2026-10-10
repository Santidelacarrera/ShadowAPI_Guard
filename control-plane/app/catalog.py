"""OpenAPI catalog parsing and drift computation."""
import yaml

from . import db
from .paths import matches, normalize_catalog_path

HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def parse_openapi(raw: bytes | str) -> list[tuple[str, str, str]]:
    """Return (METHOD, normalized_path, raw_path) for every operation. Accepts JSON or YAML."""
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
            if m.lower() in HTTP_METHODS:
                out.append((m.upper(), normalize_catalog_path(p), p))
    if not out:
        raise ValueError("document has no operations")
    return out


def compute_drift(min_hits: int = 1) -> dict:
    cat = db.list_catalog()
    obs = db.list_observed()
    cat_keys = {(c["method"], c["path"]) for c in cat}

    def documented(o: dict) -> bool:
        return any(m == o["method"] and matches(p, o["path"]) for m, p in cat_keys)

    shadow = [o for o in obs if o["hits"] >= min_hits and not documented(o)]
    zombie = [c for c in cat if not any(o["method"] == c["method"] and matches(c["path"], o["path"]) for o in obs)]
    documented_seen = len(obs) - len([o for o in obs if not documented(o)])
    return {
        "summary": {"catalog": len(cat), "observed": len(obs), "shadow": len(shadow), "unused": len(zombie),
                    "documented_seen": documented_seen},
        "shadow": [{"method": o["method"], "path": o["path"], "host": o["host"], "hits": o["hits"],
                    "first_seen": o["first_seen"].isoformat(), "last_seen": o["last_seen"].isoformat()} for o in shadow],
        "unused": [{"method": c["method"], "path": c["raw_path"]} for c in zombie],
    }

"""Derive WAF rules from drift, findings and BOLA alerts, and push them to the gateway."""
import hashlib
import json
import re

import httpx

from . import db
from .catalog import compute_drift
from .config import settings

SEV_BLOCK = {"high", "critical"}


def build_rules() -> dict:
    rules = []
    drift = compute_drift()
    high = {(f["method"], f["path"]) for f in db.list_findings(limit=100000) if f["severity"] in SEV_BLOCK}
    for s in drift["shadow"]:
        key = (s["method"], s["path"])
        if settings.waf_shadow_policy == "block" or key in high:
            why = "exploitable shadow endpoint (red team finding)" if key in high else "undocumented endpoint"
            rules.append({"action": "block", "method": s["method"], "path": s["path"], "reason": why})
        else:
            rules.append({"action": "monitor", "method": s["method"], "path": s["path"], "reason": "undocumented endpoint"})
    for a in db.alert_counts():
        rules.append({"action": "rate_limit", "method": a["method"], "path": a["path"], "limit_per_minute": 30,
                      "reason": f"{a['n']} BOLA violation(s)"})
    rules.append({"action": "mask_pii", "method": "*", "path": "*", "reason": "global response PII masking"})
    version = hashlib.sha256(json.dumps(rules, sort_keys=True).encode()).hexdigest()[:12]
    return {"version": version, "rules": rules}


def sync(client: httpx.Client | None = None) -> dict:
    payload = build_rules()
    if not settings.waf_url:
        return {"synced": False, "reason": "WAF_URL not configured", **payload}
    headers = {"X-API-Key": settings.waf_api_key} if settings.waf_api_key else {}
    c = client or httpx.Client(timeout=10)
    try:
        r = c.put(settings.waf_url.rstrip("/") + "/__waf/rules", json=payload, headers=headers)
        r.raise_for_status()
    except httpx.HTTPError as e:
        return {"synced": False, "reason": str(e), **payload}
    return {"synced": True, **payload}


# ---- exporters for real gateways (generated config; validate with the gateway's own tooling) ------------------------

_SAFE = re.compile(r"^[A-Za-z0-9._~/%:@{}-]+$")


def _regex(path: str) -> str:
    return "^" + "/".join("[^/]+" if seg == "{id}" else re.escape(seg) for seg in path.split("/")) + "$"


def _usable(rules: list[dict]):
    for r in rules:
        if r["action"] in ("block", "rate_limit") and _SAFE.match(r["path"]):
            yield r


def render(fmt: str) -> tuple[str, str]:
    """Return (content_type, body) for fmt in nginx | envoy | kong."""
    doc = build_rules()
    rules = list(_usable(doc["rules"]))
    blocks = [r for r in rules if r["action"] == "block"]
    limits = [r for r in rules if r["action"] == "rate_limit"]
    note = "mask_pii and monitor rules are not expressible in this format and were omitted"
    if fmt == "nginx":
        L = [f"# ShadowAPI Guard rules {doc['version']}  ({note})",
             "# --- http {} level ---", 'map "$request_method $uri" $shadowapi_block {', "    default 0;"]
        for r in blocks:
            meth = "[A-Z]+" if r["method"] == "*" else r["method"]
            L.append(f'    "~^{meth} {_regex(r["path"])[1:-1]}$" 1;')
        L += ["}", 'map "$request_method $uri" $shadowapi_limit_key {', '    default "";']
        for r in limits:
            meth = "[A-Z]+" if r["method"] == "*" else r["method"]
            L.append(f'    "~^{meth} {_regex(r["path"])[1:-1]}$" $binary_remote_addr;')
        L += ["}", "limit_req_zone $shadowapi_limit_key zone=shadowapi:10m rate=30r/m;",
              "# --- inside server {} or location / {} ---", "if ($shadowapi_block) { return 403; }",
              "limit_req_status 429;", "limit_req zone=shadowapi burst=5 nodelay;"]
        return "text/plain", "\n".join(L) + "\n"
    if fmt == "envoy":
        policies = {}
        for i, r in enumerate(blocks):
            perms = [{"url_path": {"path": {"safe_regex": {"regex": _regex(r["path"])}}}}]
            if r["method"] != "*":
                perms.insert(0, {"header": {"name": ":method", "string_match": {"exact": r["method"]}}})
            policies[f"shadowapi_block_{i}"] = {"permissions": [{"and_rules": {"rules": perms}}], "principals": [{"any": True}]}
        flt = {"name": "envoy.filters.http.rbac", "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC",
            "rules": {"action": "DENY", "policies": policies}}}
        return "application/json", json.dumps({"version": doc["version"], "note": note + "; rate_limit needs local_ratelimit/RLS config",
                                               "http_filter": flt}, indent=2)
    if fmt == "kong":
        import yaml
        routes = []
        for i, r in enumerate(blocks):
            routes.append({"name": f"shadowapi-block-{i}", "paths": ["~" + _regex(r["path"])[1:]], "regex_priority": 100,
                           **({"methods": [r["method"]]} if r["method"] != "*" else {}),
                           "plugins": [{"name": "request-termination", "config": {"status_code": 403, "message": "blocked by ShadowAPI Guard"}}]})
        for i, r in enumerate(limits):
            routes.append({"name": f"shadowapi-limit-{i}", "paths": ["~" + _regex(r["path"])[1:]], "regex_priority": 90,
                           **({"methods": [r["method"]]} if r["method"] != "*" else {}),
                           "plugins": [{"name": "rate-limiting", "config": {"minute": r.get("limit_per_minute", 30), "policy": "local"}}]})
        routes.append({"name": "shadowapi-default", "paths": ["/"]})
        cfg = {"_format_version": "3.0",
               "services": [{"name": "protected-api", "url": "http://UPSTREAM_HOST:8080", "routes": routes}]}
        return "text/yaml", yaml.safe_dump(cfg, sort_keys=False)
    raise ValueError(f"unknown format {fmt!r}")

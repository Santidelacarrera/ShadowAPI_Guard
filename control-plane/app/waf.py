"""Derive WAF rules from drift, findings and BOLA alerts, and push them to the gateway."""
import hashlib
import json

import httpx

from . import db
from .catalog import compute_drift
from .config import settings

SEV_BLOCK = {"high", "critical"}


def build_rules() -> dict:
    rules = []
    drift = compute_drift()
    high = {(f["method"], f["path"]) for f in db.list_findings() if f["severity"] in SEV_BLOCK}
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

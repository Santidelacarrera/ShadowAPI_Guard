"""Red Team agent: safe, authorised verification/fuzzing of drifted (shadow) endpoints."""
import hashlib
import json
from urllib.parse import urlparse

import httpx

from . import db, metrics, notify
from .catalog import compute_drift
from .config import settings
from .pii import scan

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
ERROR_SIGNATURES = ("sql syntax", "sqlite3.", "psycopg", "traceback (most recent", "root:x:0:0", "stack trace",
                    "unterminated quoted", "syntax error at")
PAYLOADS = ["' OR '1'='1", "../../../../etc/passwd", "{{7*7}}", "<script>alert(1)</script>", "1;SELECT pg_sleep(0)--"]
ID_PROBES = ["1", "2", "3", "0", "-1"]


class ScopeError(Exception):
    pass


def check_scope(target: str) -> None:
    """Never fuzz a host that has not been explicitly authorised."""
    host = urlparse(target).hostname or ""
    if host not in settings.redteam_allowed_hosts:
        raise ScopeError(f"host {host!r} is not in REDTEAM_ALLOWED_HOSTS")


def concretize(path: str, value: str = "1") -> str:
    return path.replace("{id}", value)


def _f(method, path, check, severity, detail) -> dict:
    return {"method": method, "path": path, "check": check, "severity": severity, "detail": detail}


# bandit B107 accepted: empty = "no token"
def scan_endpoint(c: httpx.Client, method: str, template: str, token: str = "", allow_unsafe: bool = False) -> list[dict]:  # nosec B107
    out: list[dict] = []
    auth = {"Authorization": f"Bearer {token}"} if token else {}
    url = concretize(template)

    def send(m, u, headers=None, **kw):
        try:
            return c.request(m, u, headers=headers, **kw)
        except httpx.HTTPError:
            return None

    if method not in SAFE_METHODS and not allow_unsafe:
        out.append(_f(method, template, "skipped_unsafe", "info", "state-changing method not probed (allow_unsafe=false)"))
        # still verify reachability / auth enforcement using a safe method
        probe_method = "OPTIONS"
    else:
        probe_method = method

    # 1. Authentication enforcement
    r = send(probe_method, url)
    if r is not None and r.status_code < 300 and probe_method == method:
        out.append(_f(method, template, "unauthenticated_access", "high",
                      f"{method} {url} answered {r.status_code} without credentials"))
    if r is not None and r.status_code < 300:
        pii = scan(r.text)
        if pii:
            out.append(_f(method, template, "pii_exposure", "critical",
                          f"unauthenticated response leaks {', '.join(sorted(pii))}"))
    # 2. Verb tampering: advertised methods
    r = send("OPTIONS", url)
    if r is not None:
        allow = {m.strip().upper() for m in r.headers.get("allow", "").split(",") if m.strip()}
        risky = sorted(allow & {"PUT", "DELETE", "PATCH"})
        if risky:
            out.append(_f(method, template, "dangerous_methods", "medium", f"endpoint advertises {', '.join(risky)}"))
    # 3. IDOR / BOLA enumeration (read-only)
    if "{id}" in template and probe_method in SAFE_METHODS and method in SAFE_METHODS:
        bodies = {}
        for i in ID_PROBES:
            r = send(method, concretize(template, i), headers=auth)
            if r is not None and r.status_code == 200:
                bodies[i] = r.text
        if len(set(bodies.values())) >= 2:
            out.append(_f(method, template, "idor_enumeration", "high",
                          f"{len(bodies)} sequential ids returned distinct objects ({'with' if token else 'without'} credentials)"))
    # 4. Injection fuzzing (read methods only)
    if method in SAFE_METHODS:
        for p in PAYLOADS:
            r = send(method, concretize(template, p), headers=auth)
            r2 = send(method, url, headers=auth, params={"q": p})
            for resp in (r, r2):
                if resp is None:
                    continue
                low = resp.text.lower()
                if resp.status_code >= 500 or any(sig in low for sig in ERROR_SIGNATURES):
                    out.append(_f(method, template, "injection_error", "high",
                                  f"payload {p!r} produced HTTP {resp.status_code} / error disclosure"))
                    break
                if p in resp.text and p.startswith("<"):
                    out.append(_f(method, template, "reflected_input", "medium", f"payload {p!r} reflected unescaped"))
                    break
    # de-duplicate
    seen, uniq = set(), []
    for f in out:
        k = (f["check"], f["detail"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq


def bola_test(c: httpx.Client, method: str, template: str, identities: list[dict]) -> list[dict]:
    """Cross-identity object access: can identity X read an object that belongs to identity Y?"""
    if "{id}" not in template or method not in SAFE_METHODS or len(identities) < 2:
        return []

    def get(ident, oid):
        try:
            return c.request(method, concretize(template, oid), headers={"Authorization": f"Bearer {ident['token']}"})
        except httpx.HTTPError:
            return None

    out = []
    for xi, x in enumerate(identities):
        for yi, y in enumerate(identities):
            if xi == yi:
                continue
            for oid in y.get("owned_ids", []):
                base = get(y, oid)
                if base is None or base.status_code != 200:
                    continue
                r = get(x, oid)
                if r is not None and r.status_code == 200 and r.text == base.text:
                    out.append(_f(method, template, "bola_confirmed", "critical",
                                  f"identity #{xi + 1} read object {oid} owned by identity #{yi + 1} (HTTP 200, identical body)"))
    return out


def fingerprint(method: str, path: str, schemas: dict) -> str:
    """Changes when the endpoint's observed request/response structure changes -> triggers a rescan."""
    parts = [schemas.get((method, path, d), {}) for d in ("request", "response")]
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()[:16]


# bandit B107 accepted: empty = "no token"
def run_scan(target: str, token: str = "", allow_unsafe: bool = False, only_new: bool = False,  # nosec B107
             transport: httpx.BaseTransport | None = None, scope: str = "shadow",
             identities: list[dict] | None = None) -> dict:
    check_scope(target)
    if scope == "all":
        endpoints = [{"method": o["method"], "path": o["path"]} for o in db.list_observed()]
    else:
        endpoints = compute_drift()["shadow"]
    schemas = {(s["method"], s["path"], s["direction"]): s["schema"] for s in db.list_schemas()}
    state = db.get_scan_state() if only_new else {}
    findings: list[dict] = []
    probed = 0
    with httpx.Client(base_url=target, timeout=5, follow_redirects=False, transport=transport,
                      headers={"X-ShadowAPI-Scan": "1"}) as c:
        for s in endpoints:
            key = (s["method"], s["path"])
            fp = fingerprint(*key, schemas)
            if only_new and state.get(key) == fp:
                continue
            findings += scan_endpoint(c, s["method"], s["path"], token, allow_unsafe)
            findings += bola_test(c, s["method"], s["path"], identities or [])
            db.set_scan_state(*key, fp)
            probed += 1
    new = db.add_findings(findings)
    for f in new:
        metrics.inc("shadowapi_findings_total", severity=f["severity"])
        if f["severity"] in ("high", "critical"):
            notify.notify("finding", f"{f['method']} {f['path']} {f['check']}",
                          f"{f['severity'].upper()} {f['check']} on {f['method']} {f['path']}: {f['detail']}")
    return {"endpoints_probed": probed, "findings": findings, "new_findings": len(new)}

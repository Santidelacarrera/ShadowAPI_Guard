"""Red Team agent: safe, authorised verification/fuzzing of drifted (shadow) endpoints."""
from urllib.parse import urlparse

import httpx

from . import db
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


def scan_endpoint(c: httpx.Client, method: str, template: str, token: str = "", allow_unsafe: bool = False) -> list[dict]:
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


def run_scan(target: str, token: str = "", allow_unsafe: bool = False, only_new: bool = False,
             transport: httpx.BaseTransport | None = None, scanned: set | None = None) -> dict:
    check_scope(target)
    shadow = compute_drift()["shadow"]
    findings: list[dict] = []
    probed = 0
    with httpx.Client(base_url=target, timeout=5, follow_redirects=False, transport=transport,
                      headers={"X-ShadowAPI-Scan": "1"}) as c:
        for s in shadow:
            key = (s["method"], s["path"])
            if only_new and scanned is not None and key in scanned:
                continue
            findings += scan_endpoint(c, s["method"], s["path"], token, allow_unsafe)
            probed += 1
            if scanned is not None:
                scanned.add(key)
    db.add_findings(findings)
    return {"endpoints_probed": probed, "findings": findings}

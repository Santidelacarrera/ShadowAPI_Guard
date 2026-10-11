"""Tiny stand-in for ClickHouse's HTTP interface, for running the stack without Docker.

Supports: DDL (ignored), `INSERT ... FORMAT JSONEachRow`, and SELECTs (returns stored rows,
or a grouped count when the query has GROUP BY). Not a SQL engine: use the real thing in compose.
"""
import json
import sys
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ROWS: list[dict] = []


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self._ok(b"Ok.\n")

    def do_POST(self):
        q = parse_qs(urlparse(self.path).query).get("query", [""])[0]
        body = self.rfile.read(int(self.headers.get("content-length", 0))).decode()
        if q.startswith("INSERT"):
            ROWS.extend(json.loads(l) for l in body.splitlines() if l)
            return self._ok(b"")
        if q.startswith("SELECT"):
            if "GROUP BY" in q:
                c = Counter((r["path_template"], r["method"]) for r in ROWS)
                data = [{"path_template": p, "method": m, "requests": n} for (p, m), n in c.items()]
            else:
                data = ROWS
            return self._ok(json.dumps({"data": data}).encode())
        self._ok(b"")

    def _ok(self, b: bytes):
        self.send_response(200)
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8123), H).serve_forever()

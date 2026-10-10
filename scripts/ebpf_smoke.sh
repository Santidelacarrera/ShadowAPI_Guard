#!/bin/bash
# Smoke test of the real eBPF probe (Linux, root, bpf-linker + nightly installed, tracefs available).
# Loads the program (kernel verifier), attaches tracepoints + SSL_write uprobe, generates plain HTTP and
# HTTPS requests with curl and checks the probe reported them without TLS decryption keys.
set -u
R=$(cd "$(dirname "$0")/.." && pwd); T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf $T' EXIT
mountpoint -q /sys/kernel/tracing || mount -t tracefs nodev /sys/kernel/tracing
(cd "$R/probe/ebpf" && cargo +nightly build --release -q) || { echo "FAIL build eBPF object"; exit 1; }
cargo build -q -p shadowapi-probe --manifest-path "$R/Cargo.toml" || { echo "FAIL build probe"; exit 1; }
python3 - "$T" <<'PY' &
import json, sys, ssl, http.server, threading, subprocess
t = sys.argv[1]
class D(http.server.BaseHTTPRequestHandler):           # fake detector
    def log_message(self, *a): pass
    def do_POST(self):
        for e in json.loads(self.rfile.read(int(self.headers['content-length']))):
            open(t + "/events", "a").write(f"{e['method']} {e['path']}\n")
        self.send_response(202); self.send_header('content-length', '0'); self.end_headers()
subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",t+"/k.pem","-out",t+"/c.pem","-days","1","-subj","/CN=localhost"], capture_output=True)
web = http.server.HTTPServer(("127.0.0.1", 18090), http.server.SimpleHTTPRequestHandler)
tls = http.server.HTTPServer(("127.0.0.1", 18443), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(t+"/c.pem", t+"/k.pem"); tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
for s in (web, tls): threading.Thread(target=s.serve_forever, daemon=True).start()
http.server.HTTPServer(("127.0.0.1", 18081), D).serve_forever()
PY
sleep 2
LIB=$(ldd "$(command -v curl)" | grep -o '/[^ ]*libssl[^ ]*' | head -1)
"$R/target/debug/shadowapi-probe" --detector http://127.0.0.1:18081 attach \
  --object "$R/probe/ebpf/target/bpfel-unknown-none/release/probe-ebpf" ${LIB:+--libssl "$LIB"} 2> "$T/probe.log" &
sleep 3
grep -q attached "$T/probe.log" || { echo "FAIL probe did not attach:"; cat "$T/probe.log"; exit 1; }
curl -s -o /dev/null http://127.0.0.1:18090/plain/1
curl -sk -o /dev/null https://127.0.0.1:18443/tls/secret/77
sleep 3
rc=0
grep -q "GET /plain/1" "$T/events" && echo "PASS plain HTTP request captured" || { echo "FAIL plain HTTP"; rc=1; }
[ -n "$LIB" ] && { grep -q "GET /tls/secret/77" "$T/events" && echo "PASS TLS request captured before encryption" || { echo "FAIL TLS"; rc=1; }; }
[ "$(grep -c 'POST /events' "$T/events")" = 0 ] && echo "PASS probe ignores its own uploads" || { echo "FAIL self-capture loop"; rc=1; }
exit $rc

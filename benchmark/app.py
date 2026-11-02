"""Benchmark target app: serves every flaw in manifest.py. Standard library only.

Responses are simulated. Nothing runs on the host: SQL, file reads, commands, and fetches are
imitated with fixed output, so the app is safe to run on the scanner box. Each flaw responds the
way its class looks on the wire (error text, reflected markup, file contents, and so on).
"""

import json
import re

import manifest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

MATH_RE = re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}")


def _query_response(cls: str, value: str) -> tuple[int, str, str]:
    if cls == "sqli":
        if "'" in value or " or " in value.lower():
            return 500, "text/plain", "You have an error in your SQL syntax near '" + value + "' at line 1"
        return 200, "application/json", json.dumps({"rows": [[1, "admin"]]})
    if cls == "xss":
        return 200, "text/html", f"<html><body><p>Hello {value}</p></body></html>"
    if cls == "ssti":
        rendered = MATH_RE.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), value)
        return 200, "text/html", f"<html><body><h2>Welcome {rendered}</h2></body></html>"
    if cls == "lfi":
        if "etc/passwd" in value or "../" in value:
            return 200, "text/plain", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh"
        return 404, "text/plain", "file not found"
    if cls == "rce":
        if re.search(r"[;|`]|\$\(", value) and "id" in value:
            return 200, "text/plain", "uid=0(root) gid=0(root) groups=0(root)"
        return 200, "text/plain", "pong"
    if cls == "ssrf":
        if re.match(r"https?://(127\.0\.0\.1|localhost)", value):
            return 200, "text/plain", "ami-id: i-0abc123 instance-type: t3.micro"
        return 200, "text/plain", "fetched 0 bytes"
    return 404, "text/plain", "not found"


def _path_response(cls: str, n: str) -> tuple[int, str, str]:
    if cls == "exposure":
        return 200, "text/plain", "DB_HOST=db.internal\nDB_PASS=benchmark-secret\nDEBUG=true"
    if cls == "idor":
        return 200, "application/json", json.dumps({"id": n, "content": f"private note {n}"})
    return 404, "text/plain", "not found"


def _index() -> str:
    """Home page linking every flaw, the way a real app links its pages. Discovery is tested against it."""
    items = []
    for flaw in manifest.flaws():
        href = flaw["path"] if flaw["location"] == "path" else f"{flaw['path']}?{flaw['param']}="
        items.append(f'<li><a href="{href}">{flaw["id"]}</a></li>')
    return "<html><body><h1>Benchmark app</h1><ul>" + "".join(items) + "</ul></body></html>"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            return self._send(200, "text/html", _index())
        match = re.fullmatch(r"/bm/([a-z]+)/(\d+)", parsed.path)
        if not match:
            return self._send(404, "text/plain", "not found")
        cls, n = match.group(1), match.group(2)
        if cls in ("idor", "exposure"):
            status, ctype, body = _path_response(cls, n)
        else:
            params = parse_qs(parsed.query, keep_blank_values=True)
            value = next(iter(params.values()), [""])[0]
            status, ctype, body = _query_response(cls, value)
        self._send(status, ctype, body)

    def _send(self, status: int, ctype: str, body: str):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def serve(port: int = 9090) -> None:
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"benchmark app on :{port}")
    server.serve_forever()


if __name__ == "__main__":
    import sys

    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 9090)

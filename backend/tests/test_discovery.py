"""Endpoint discovery: parameterized URLs found from a target's own pages, bounded and same-host."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

PAGES = {
    "/": """<html><body>
      <a href="/about">About</a>
      <code>GET /api/tools/ping?host=127.0.0.1;id</code>
      <form action="/search" method="get"><input name="q"><input name="lang"></form>
      <form action="/login" method="post"><input name="user"></form>
      <a href="http://example.org/x?y=1">external</a>
    </body></html>""",
    "/about": """<html><body>
      <a href="/api/files/read?file=/etc/passwd">read</a>
      <a href="/deep">deeper</a>
    </body></html>""",
    "/deep": """<html><body>Try /api/render?name=7*7 and <a href="/api/notes?id=1">note</a></body></html>""",
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("#")[0]
        if path.split("?")[0] in PAGES:
            body = PAGES[path.split("?")[0]].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture()
def site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_discovers_parameterized_urls_from_text_links_and_forms(site):
    from app.services.discovery import discover

    found = set(discover(site + "/"))
    assert f"{site}/api/tools/ping?host=127.0.0.1;id" in found
    assert f"{site}/api/files/read?file=/etc/passwd" in found  # from a linked page
    assert f"{site}/api/render?name=7*7" in found  # from a page two levels down
    assert f"{site}/api/notes?id=1" in found
    assert f"{site}/search?q=test&lang=test" in found  # GET form
    assert not any("login" in url for url in found)  # POST forms are not fuzzed
    assert not any("example.org" in url for url in found)  # other hosts are never followed


def test_bounds_are_respected(site):
    from app.services.discovery import discover

    assert len(discover(site + "/", max_urls=2)) == 2
    assert len(discover(site + "/", max_pages=1)) <= 2  # only the root page is read


def test_unreachable_base_returns_nothing():
    from app.services.discovery import discover

    assert discover("http://127.0.0.1:9/", timeout=0.5) == []

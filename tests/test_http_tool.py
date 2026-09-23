"""
Description: http_request tool — loopback/scope floor + a real local round-trip.
Author: Aleksa Zatezalo
Date Created: 09-22-2026
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from appsec.tools.http_tool import _parse_headers, http_request


def test_parse_headers_newline_and_semicolon():
    assert _parse_headers("A: 1\nB: 2") == {"A": "1", "B": "2"}
    assert _parse_headers("A: 1; B: 2") == {"A": "1", "B": "2"}
    assert _parse_headers("") == {}


def test_refuses_non_loopback_host():
    # 8.8.8.8 is unambiguously not loopback, regardless of local DNS quirks.
    out = http_request.invoke({"url": "http://8.8.8.8/"})
    assert "REFUSED" in out and "loopback" in out


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("X-Test", "ok")
        self.end_headers()
        self.wfile.write(b"hello from target")

    def log_message(self, *a):  # silence
        pass


@pytest.fixture()
def local_server():
    srv = HTTPServer(("127.0.0.1", 0), _Echo)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()


def test_live_loopback_request(runtime, local_server):
    out = http_request.invoke({"url": local_server})
    assert "HTTP 200" in out
    assert "X-Test: ok" in out
    assert "hello from target" in out

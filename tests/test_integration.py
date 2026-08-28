"""Integration tests against a real local HTTP server (real sockets).

These reach 127.0.0.1, so they run in controlled-testing mode
(``allow_private=True``) which is the only way BLHawk will touch private
addresses. This exercises the real network path deterministically without
depending on third-party services.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from blhawk.core.config import ScanConfig
from blhawk.core.engine import Scanner
from blhawk.core.errors import PermanentError
from blhawk.core.http_client import SafeHTTPClient
from blhawk.core.models import Verdict
from blhawk.core.ssrf import SSRFGuard
from blhawk.providers.base import StatusProvider


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command == "GET":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path
        if path == "/ok":
            self._send(200, b"hello world")
        elif path == "/missing":
            self._send(404, b"not found")
        elif path == "/redirect":
            self._send(302, b"", {"Location": "/ok"})
        elif path == "/loop":
            self._send(302, b"", {"Location": "/loop"})
        elif path == "/big":
            self._send(200, b"A" * 200000)
        elif path.startswith("/catchall"):
            self._send(200, b"<html>generic catch-all page for everything</html>")
        else:
            self._send(404, b"not found")


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    yield f"http://{host}:{port}"
    httpd.shutdown()


@pytest.fixture
def local_client():
    return SafeHTTPClient(guard=SSRFGuard(allow_private=True), retries=0)


def test_real_get(server, local_client):
    resp = local_client.get(server + "/ok")
    assert resp.status_code == 200
    assert resp.text == "hello world"


def test_real_redirect(server, local_client):
    resp = local_client.get(server + "/redirect")
    assert resp.status_code == 200
    assert resp.text == "hello world"
    assert resp.history


def test_real_redirect_loop(server, local_client):
    with pytest.raises(PermanentError):
        local_client.get(server + "/loop")


def test_real_size_cap(server):
    client = SafeHTTPClient(guard=SSRFGuard(allow_private=True), max_bytes=1000, retries=0)
    resp = client.get(server + "/big")
    assert len(resp.body) <= 1000
    assert resp.truncated is True


def test_engine_end_to_end_over_sockets(server, monkeypatch):
    """Full engine pipeline (provider + detection) over real sockets."""

    class LocalProvider(StatusProvider):
        name = "local-test"
        hosts = ("127.0.0.1",)
        from blhawk.core.models import Reclaimability, Severity
        default_reclaimability = Reclaimability.POSSIBLE
        default_severity = Severity.MEDIUM

    monkeypatch.setattr("blhawk.core.engine.find_provider", lambda url: LocalProvider())
    scanner = Scanner(
        config=ScanConfig(allow_private=True, enable_soft404=False, threads=2),
    )
    findings = scanner.scan([server + "/missing", server + "/ok"])
    by_url = {f.target.url: f for f in findings}
    assert by_url[server + "/missing"].verdict == Verdict.POTENTIALLY_RECLAIMABLE
    assert by_url[server + "/ok"].verdict == Verdict.NOT_VULNERABLE


def test_engine_soft404_over_sockets(server, monkeypatch):
    class LocalProvider(StatusProvider):
        name = "local-test"
        hosts = ("127.0.0.1",)

    monkeypatch.setattr("blhawk.core.engine.find_provider", lambda url: LocalProvider())
    scanner = Scanner(config=ScanConfig(allow_private=True, enable_soft404=True))
    findings = scanner.scan([server + "/catchall/profile"])
    # The server returns a near-identical 200 for the random control path, so
    # the "present" result must be downgraded to UNKNOWN.
    assert findings[0].verdict == Verdict.UNKNOWN
    assert findings[0].evidence.soft_404 is True


@pytest.mark.live
def test_live_pypi_missing_project():
    """Opt-in live test (``pytest -m live``); excluded from CI."""
    scanner = Scanner(config=ScanConfig(enable_soft404=False))
    findings = scanner.scan(["https://pypi.org/project/blhawk-nonexistent-xyz-98765/"])
    assert findings[0].provider == "pypi"
    assert findings[0].verdict == Verdict.DEAD_RESOURCE

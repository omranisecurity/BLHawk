"""SafeHTTPClient tests with mocked HTTP (no real network)."""

from __future__ import annotations

import pytest
import responses

from blhawk.core.errors import PermanentError, SSRFBlockedError
from blhawk.core.http_client import SafeHTTPClient
from blhawk.core.ssrf import SSRFGuard

PUBLIC_IP = "93.184.216.34"


def _public_guard(monkeypatch, blocked_hosts=None):
    """A guard that resolves everything to a public IP except blocked hosts."""
    blocked = set(blocked_hosts or [])
    guard = SSRFGuard()

    def fake_resolve(host):
        if host in blocked:
            return ["127.0.0.1"]
        return [PUBLIC_IP]

    monkeypatch.setattr(guard, "resolve", fake_resolve)
    return guard


@responses.activate
def test_get_returns_status_and_body(monkeypatch):
    responses.add(responses.GET, "https://example.com/foo", body="hello", status=200)
    client = SafeHTTPClient(guard=_public_guard(monkeypatch), retries=0)
    resp = client.get("https://example.com/foo")
    assert resp.status_code == 200
    assert resp.text == "hello"
    assert resp.url == "https://example.com/foo"


@responses.activate
def test_manual_redirect_following(monkeypatch):
    responses.add(
        responses.GET,
        "https://example.com/a",
        status=302,
        headers={"Location": "https://example.com/b"},
    )
    responses.add(responses.GET, "https://example.com/b", body="final", status=200)
    client = SafeHTTPClient(guard=_public_guard(monkeypatch), retries=0)
    resp = client.get("https://example.com/a")
    assert resp.status_code == 200
    assert resp.text == "final"
    assert resp.history == ["https://example.com/a"]


@responses.activate
def test_redirect_to_internal_is_blocked(monkeypatch):
    responses.add(
        responses.GET,
        "https://example.com/open",
        status=302,
        headers={"Location": "https://internal.evil/secret"},
    )
    guard = _public_guard(monkeypatch, blocked_hosts={"internal.evil"})
    client = SafeHTTPClient(guard=guard, retries=0)
    with pytest.raises(SSRFBlockedError):
        client.get("https://example.com/open")


@responses.activate
def test_too_many_redirects(monkeypatch):
    for i in range(10):
        responses.add(
            responses.GET,
            f"https://example.com/r{i}",
            status=302,
            headers={"Location": f"https://example.com/r{i + 1}"},
        )
    client = SafeHTTPClient(guard=_public_guard(monkeypatch), max_redirects=3, retries=0)
    with pytest.raises(PermanentError):
        client.get("https://example.com/r0")


@responses.activate
def test_response_size_capped(monkeypatch):
    responses.add(responses.GET, "https://example.com/big", body="A" * 10000, status=200)
    client = SafeHTTPClient(guard=_public_guard(monkeypatch), max_bytes=100, retries=0)
    resp = client.get("https://example.com/big")
    assert len(resp.body) <= 100
    assert resp.truncated is True


def test_non_http_scheme_rejected(monkeypatch):
    client = SafeHTTPClient(guard=_public_guard(monkeypatch), retries=0)
    with pytest.raises(PermanentError):
        client.get("file:///etc/passwd")


def test_ssrf_guard_blocks_before_request(monkeypatch):
    guard = _public_guard(monkeypatch, blocked_hosts={"example.com"})
    client = SafeHTTPClient(guard=guard, retries=0)
    with pytest.raises(SSRFBlockedError):
        client.get("https://example.com/foo")

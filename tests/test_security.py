"""Security hardening suite: BLHawk must never become an SSRF/abuse primitive."""
from __future__ import annotations

import pytest
import responses

from blhawk.core.errors import BLHawkError, ConfigError, PermanentError, SSRFBlockedError
from blhawk.core.http_client import SafeHTTPClient
from blhawk.core.logging import sanitize
from blhawk.core.ssrf import SSRFGuard
from blhawk.discovery.inputs import read_target_file


# -- SSRF: IPv4-mapped IPv6 ------------------------------------------------
def test_ipv4_mapped_loopback_blocked():
    guard = SSRFGuard()
    assert guard.is_ip_blocked("::ffff:127.0.0.1") is True
    assert guard.is_ip_blocked("::ffff:10.0.0.1") is True


def test_ipv4_mapped_public_allowed():
    guard = SSRFGuard()
    assert guard.is_ip_blocked("::ffff:8.8.8.8") is False


# -- SSRF: mixed DNS answers (rebinding-style) -----------------------------
def test_host_with_any_private_answer_is_blocked(monkeypatch):
    guard = SSRFGuard()
    monkeypatch.setattr(guard, "resolve", lambda host: ["93.184.216.34", "127.0.0.1"])
    allowed, reason = guard.check_host("rebind.example")
    assert allowed is False
    assert "blocked address" in reason


def test_decimal_ip_that_resolves_to_loopback_is_blocked(monkeypatch):
    # Obfuscated integer host that the resolver maps to loopback.
    guard = SSRFGuard()
    monkeypatch.setattr(guard, "resolve", lambda host: ["127.0.0.1"])
    with pytest.raises(SSRFBlockedError):
        guard.enforce("2130706433")


# -- HTTP client hardening -------------------------------------------------
def _guard(monkeypatch, ip="93.184.216.34"):
    guard = SSRFGuard()
    monkeypatch.setattr(guard, "resolve", lambda host: [ip])
    return guard


def test_non_http_scheme_rejected(monkeypatch):
    client = SafeHTTPClient(guard=_guard(monkeypatch), retries=0)
    for url in ["file:///etc/passwd", "gopher://x/", "ftp://x/"]:
        with pytest.raises(PermanentError):
            client.get(url)


def test_crlf_in_url_is_rejected(monkeypatch):
    client = SafeHTTPClient(guard=_guard(monkeypatch), retries=0)
    with pytest.raises(BLHawkError):
        client.get("https://exa\r\nmple.com/inject")


@responses.activate
def test_response_size_bounded(monkeypatch):
    responses.add(responses.GET, "https://example.com/x", body="A" * 1_000_000, status=200)
    client = SafeHTTPClient(guard=_guard(monkeypatch), max_bytes=1024, retries=0)
    resp = client.get("https://example.com/x")
    assert len(resp.body) <= 1024
    assert resp.truncated is True


@responses.activate
def test_redirect_to_metadata_endpoint_blocked(monkeypatch):
    responses.add(
        responses.GET, "https://example.com/go", status=302,
        headers={"Location": "http://169.254.169.254/latest/meta-data/"},
    )
    guard = SSRFGuard()

    def resolve(host):
        return ["169.254.169.254"] if host == "169.254.169.254" else ["93.184.216.34"]

    monkeypatch.setattr(guard, "resolve", resolve)
    client = SafeHTTPClient(guard=guard, retries=0)
    with pytest.raises(SSRFBlockedError):
        client.get("https://example.com/go")


# -- log injection ---------------------------------------------------------
def test_sanitize_strips_crlf_and_control_chars():
    dirty = "line1\r\nFAKE LOG ENTRY\x00\x07 end"
    clean = sanitize(dirty)
    assert "\n" not in clean and "\r" not in clean
    assert "\x00" not in clean and "\x07" not in clean
    assert "FAKE LOG ENTRY" in clean


def test_sanitize_truncates():
    assert sanitize("A" * 5000, max_len=100).endswith("...(truncated)")


# -- malicious input files -------------------------------------------------
def test_oversized_target_file_rejected(tmp_path, monkeypatch):
    import blhawk.discovery.inputs as inputs

    f = tmp_path / "targets.txt"
    f.write_text("example.com\n")
    monkeypatch.setattr(inputs, "MAX_INPUT_BYTES", 1)
    with pytest.raises(ConfigError):
        read_target_file(f)

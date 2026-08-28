"""SSRF guard tests: the tool must never connect to internal addresses."""
from __future__ import annotations

import pytest

from blhawk.core.errors import SSRFBlockedError
from blhawk.core.ssrf import SSRFGuard


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "127.5.5.5",
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "0.0.0.0",
        "100.64.0.1",  # CGNAT
        "::1",
        "fe80::1",
        "fc00::1",
        "fd00:ec2::254",
    ],
)
def test_blocked_ip_literals(ip):
    guard = SSRFGuard()
    assert guard.is_ip_blocked(ip) is True


@pytest.mark.parametrize(
    "ip",
    ["93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:2800:220:1:248:1893:25c8:1946"],
)
def test_allowed_public_ip_literals(ip):
    guard = SSRFGuard()
    assert guard.is_ip_blocked(ip) is False


def test_check_host_blocks_localhost():
    guard = SSRFGuard()
    allowed, reason = guard.check_host("localhost")
    assert allowed is False
    assert "localhost" in reason


def test_check_host_blocks_metadata_hostname():
    guard = SSRFGuard()
    allowed, _ = guard.check_host("metadata.google.internal")
    assert allowed is False


def test_check_host_ip_literal_private():
    guard = SSRFGuard()
    allowed, _ = guard.check_host("169.254.169.254")
    assert allowed is False


def test_enforce_raises_for_private(monkeypatch):
    guard = SSRFGuard()
    monkeypatch.setattr(guard, "resolve", lambda host: ["10.0.0.5"])
    with pytest.raises(SSRFBlockedError):
        guard.enforce("internal.example")


def test_enforce_allows_public(monkeypatch):
    guard = SSRFGuard()
    monkeypatch.setattr(guard, "resolve", lambda host: ["93.184.216.34"])
    guard.enforce("example.com")  # should not raise


def test_allow_private_mode_disables_guard():
    guard = SSRFGuard(allow_private=True)
    allowed, reason = guard.check_host("127.0.0.1")
    assert allowed is True
    assert reason == "ssrf-guard-disabled"


def test_dns_failure_is_blocked(monkeypatch):
    import socket

    guard = SSRFGuard()

    def boom(host):
        raise socket.gaierror("nxdomain")

    monkeypatch.setattr(guard, "resolve", boom)
    allowed, reason = guard.check_host("does-not-exist.invalid")
    assert allowed is False
    assert "dns" in reason.lower()


def test_extra_blocked_hosts():
    guard = SSRFGuard(extra_blocked_hosts={"forbidden.example"})
    allowed, _ = guard.check_host("forbidden.example")
    assert allowed is False

"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from blhawk.core.http_client import SafeHTTPClient
from blhawk.core.ssrf import SSRFGuard

PUBLIC_IP = "93.184.216.34"


@pytest.fixture
def public_guard(monkeypatch):
    """An SSRF guard that resolves any hostname to a public IP (offline tests)."""
    guard = SSRFGuard()
    monkeypatch.setattr(guard, "resolve", lambda host: [PUBLIC_IP])
    return guard


@pytest.fixture
def client_factory(public_guard):
    """Factory returning a SafeHTTPClient with retries disabled for determinism."""

    def _make(**kwargs):
        kwargs.setdefault("retries", 0)
        return SafeHTTPClient(guard=public_guard, **kwargs)

    return _make


@pytest.fixture
def client(client_factory):
    return client_factory()

"""Tests for the optional, robots-respecting single-program fetch."""

from __future__ import annotations

import pytest
import responses

from blhawk.bugrap.fetch import fetch_program
from blhawk.bugrap.robots import can_fetch, load_robots
from blhawk.core.errors import BLHawkError
from blhawk.core.http_client import SafeHTTPClient
from blhawk.core.ssrf import SSRFGuard

PAGE = """
<table>
<tr><td>In Scope</td></tr>
<tr><td>Websites</td><td>*.example.org</td></tr>
<tr><td>Blockchain</td><td>https://github.com/example/contracts</td></tr>
</table>
"""


@pytest.fixture
def client(monkeypatch):
    guard = SSRFGuard()
    monkeypatch.setattr(guard, "resolve", lambda host: ["93.184.216.34"])
    return SafeHTTPClient(guard=guard, retries=0)


@responses.activate
def test_fetch_program_allowed_by_robots(client):
    responses.add(
        responses.GET, "https://bugrap.io/robots.txt", status=200, body="User-agent: *\nAllow: /"
    )
    responses.add(responses.GET, "https://bugrap.io/bounties/example", status=200, body=PAGE)
    program = fetch_program(client, "https://bugrap.io/bounties/example", name="example")
    assets = {a.asset for a in program.assets}
    assert "*.example.org" in assets
    assert "https://github.com/example/contracts" in assets
    assert program.research_status == "unreviewed"


@responses.activate
def test_fetch_program_blocked_by_robots(client):
    responses.add(
        responses.GET, "https://bugrap.io/robots.txt", status=200, body="User-agent: *\nDisallow: /"
    )
    with pytest.raises(BLHawkError):
        fetch_program(client, "https://bugrap.io/bounties/example", name="example")


@responses.activate
def test_fetch_program_non_200(client):
    responses.add(responses.GET, "https://bugrap.io/robots.txt", status=404)
    responses.add(responses.GET, "https://bugrap.io/bounties/missing", status=404)
    with pytest.raises(BLHawkError):
        fetch_program(client, "https://bugrap.io/bounties/missing", name="missing")


@responses.activate
def test_load_robots_missing_is_permissive(client):
    responses.add(responses.GET, "https://bugrap.io/robots.txt", status=404)
    parser = load_robots(client, "https://bugrap.io/x")
    assert can_fetch(parser, "https://bugrap.io/x", "BLHawk") is True

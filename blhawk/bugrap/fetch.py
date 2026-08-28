"""Optional single-program fetch (ToS/robots-respecting).

This is NOT a mass crawler. It fetches one program page the user explicitly
requests, honoring robots.txt, and returns best-effort extracted scope that
must be verified against the official program rules before any scanning.
"""

from __future__ import annotations

from ..core.errors import BLHawkError
from ..core.http_client import DEFAULT_USER_AGENT, SafeHTTPClient
from .models import Program
from .parser import parse_program_html
from .robots import can_fetch, load_robots


def fetch_program(
    http: SafeHTTPClient,
    url: str,
    name: str | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    respect_robots: bool = True,
) -> Program:
    if respect_robots:
        robots = load_robots(http, url)
        if not can_fetch(robots, url, user_agent):
            raise BLHawkError(f"robots.txt disallows fetching {url}")
    resp = http.get(url)
    if resp.status_code != 200:
        raise BLHawkError(f"program page returned HTTP {resp.status_code}")
    program = parse_program_html(resp.text, name or url, source_url=url)
    program.research_status = "unreviewed"
    return program

"""robots.txt handling for the optional single-program fetch.

Fetching is routed through the SafeHTTPClient (so the SSRF guard applies) and
gated by ``robots.txt`` to respect the site's crawl policy.
"""
from __future__ import annotations

from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

from ..core.http_client import SafeHTTPClient
from ..core.logging import get_logger, sanitize

_log = get_logger("bugrap.robots")


def robots_url_for(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}/robots.txt"


def load_robots(http: SafeHTTPClient, url: str) -> RobotFileParser:
    parser = RobotFileParser()
    parser.parse([])  # default: allow all if robots is unavailable
    try:
        resp = http.get(robots_url_for(url))
    except Exception as exc:  # noqa: BLE001 - missing robots => permissive default
        _log.debug("robots fetch failed for %s: %s", sanitize(url), sanitize(exc))
        return parser
    if resp.status_code == 200 and resp.text:
        parser.parse(resp.text.splitlines())
    return parser


def can_fetch(parser: RobotFileParser, url: str, user_agent: str) -> bool:
    try:
        return parser.can_fetch(user_agent, url)
    except Exception:  # noqa: BLE001 - be conservative on parser errors
        return False

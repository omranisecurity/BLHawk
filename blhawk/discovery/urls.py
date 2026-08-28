"""Safe URL extraction from HTML/text.

Fixes the original extractor bug where a regex greedily captured trailing
markup (e.g. ``https://x/y</a``). We extract from href/src attributes first,
then bare URLs, and strip trailing punctuation/markup.
"""

from __future__ import annotations

import re
from html import unescape

_ATTR_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_BARE_RE = re.compile(r"""https?://[^\s"'<>\\]+""", re.IGNORECASE)
_TRAILING = ".,);]}>\"'"


def _clean(url: str) -> str:
    url = unescape(url).strip()
    # Strip common trailing punctuation and any stray markup.
    while url and url[-1] in _TRAILING:
        url = url[:-1]
    for marker in ("</a", "</A", "\\"):
        idx = url.find(marker)
        if idx != -1:
            url = url[:idx]
    return url


def extract_links(html: str, limit: int = 5000) -> list[str]:
    """Return de-duplicated absolute http(s) links found in ``html``."""
    found: list[str] = []
    seen: set[str] = set()

    def add(candidate: str) -> None:
        candidate = _clean(candidate)
        if not candidate.lower().startswith(("http://", "https://")):
            return
        if candidate not in seen:
            seen.add(candidate)
            found.append(candidate)

    for match in _ATTR_RE.findall(html):
        add(match)
        if len(found) >= limit:
            return found
    for match in _BARE_RE.findall(html):
        add(match)
        if len(found) >= limit:
            break
    return found

"""Scope matching and classification.

Precedence rule: an explicit exclude always beats an include. Anything that
matches no rule is ``UNKNOWN`` (never scanned by default).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..core.models import ScopeResult, ScopeStatus
from .hostnames import host_in_wildcard, host_matches_exact, ip_in_cidr, normalize_host
from .model import MANUAL_TYPES, AssetType, Scope, ScopeEntry


def _split_target(target: str) -> tuple[str, str]:
    """Return (normalized_host, normalized_path) for a URL or bare host."""
    text = target.strip()
    if "://" in text:
        parts = urlsplit(text)
        host = normalize_host(parts.hostname or "")
        path = parts.path.rstrip("/")
        return host, path
    # bare host (optionally with a path)
    if "/" in text:
        host_part, _, path_part = text.partition("/")
        return normalize_host(host_part), ("/" + path_part).rstrip("/")
    return normalize_host(text), ""


def _entry_host_path(entry: ScopeEntry) -> tuple[str, str]:
    if entry.type in (AssetType.URL, AssetType.API, AssetType.REPOSITORY):
        raw = entry.asset
        parts = urlsplit(raw if "://" in raw else "//" + raw)
        return normalize_host(parts.hostname or ""), parts.path.rstrip("/")
    return entry.host(), ""


def _path_matches(target_path: str, entry_path: str) -> bool:
    if not entry_path or entry_path == "/":
        return True
    return target_path == entry_path or target_path.startswith(entry_path + "/")


def entry_matches(entry: ScopeEntry, target_host: str, target_path: str) -> bool:
    if entry.type == AssetType.CIDR:
        return ip_in_cidr(target_host, entry.asset)
    if entry.type == AssetType.IP:
        return host_matches_exact(target_host, entry.host())
    if entry.type == AssetType.WILDCARD:
        return host_in_wildcard(target_host, entry.host())
    if entry.type == AssetType.DOMAIN:
        return host_matches_exact(target_host, entry.host())
    if entry.type in (AssetType.URL, AssetType.API, AssetType.REPOSITORY):
        ehost, epath = _entry_host_path(entry)
        return host_matches_exact(target_host, ehost) and _path_matches(target_path, epath)
    # PACKAGE / MOBILE_APP / OTHER are not host-addressable; no URL match.
    return False


def classify_target(target: str, scope: Scope) -> ScopeResult:
    host, path = _split_target(target)
    if not host:
        return ScopeResult(status=ScopeStatus.UNKNOWN, reason="unparseable target")

    # Excludes win.
    for entry in scope.excludes:
        if entry_matches(entry, host, path):
            return ScopeResult(
                status=ScopeStatus.OUT_OF_SCOPE,
                program=entry.program,
                matched_rule=entry.asset,
                source=entry.source,
                reason="matched an explicit exclusion",
            )

    for entry in scope.includes:
        if entry_matches(entry, host, path):
            needs_review = entry.type in MANUAL_TYPES or any(
                "manual" in r.lower() for r in entry.restrictions
            )
            status = ScopeStatus.REQUIRES_MANUAL_REVIEW if needs_review else ScopeStatus.IN_SCOPE
            return ScopeResult(
                status=status,
                program=entry.program,
                matched_rule=entry.asset,
                source=entry.source,
                reason="matched an in-scope asset",
            )

    return ScopeResult(status=ScopeStatus.UNKNOWN, reason="no matching scope rule")

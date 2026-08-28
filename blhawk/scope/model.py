"""Scope data model."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .hostnames import is_ip_literal, normalize_host


class AssetType(enum.Enum):
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    URL = "url"
    IP = "ip"
    CIDR = "cidr"
    PACKAGE = "package"
    REPOSITORY = "repository"
    MOBILE_APP = "mobile_app"
    API = "api"
    OTHER = "other"


# Asset types that BLHawk cannot safely test automatically and that should be
# flagged for manual review when matched in-scope.
MANUAL_TYPES = {AssetType.MOBILE_APP, AssetType.OTHER}


def infer_asset_type(asset: str) -> AssetType:
    """Best-effort inference of an asset type from a bare string."""
    text = asset.strip()
    low = text.lower()
    if low.startswith("pkg:"):
        return AssetType.PACKAGE
    if low.startswith("*.") or low.startswith("*"):
        return AssetType.WILDCARD
    if "://" in low:
        parts = urlsplit(text)
        if parts.path.strip("/") or parts.query:
            return AssetType.URL
        return AssetType.DOMAIN
    if "/" in text:
        # Could be CIDR (ip/prefix) or a bare path-bearing URL.
        left = text.split("/", 1)[0]
        if is_ip_literal(left):
            return AssetType.CIDR
        return AssetType.URL
    if is_ip_literal(text):
        return AssetType.IP
    return AssetType.DOMAIN


@dataclass
class ScopeEntry:
    asset: str
    type: AssetType = AssetType.DOMAIN
    scope: str = "in"  # "in" or "out"
    program: str | None = None
    platform: str | None = None
    restrictions: list[str] = field(default_factory=list)
    source: str | None = None
    last_verified: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def is_exclude(self) -> bool:
        return self.scope.lower() == "out"

    def host(self) -> str:
        """Return the normalized host component of this asset (if any)."""
        text = self.asset
        if self.type == AssetType.WILDCARD:
            return normalize_host(text.lstrip("*").lstrip("."))
        if self.type in (AssetType.URL, AssetType.API):
            return normalize_host(urlsplit(text).hostname or "")
        if self.type in (AssetType.DOMAIN, AssetType.IP):
            if "://" in text:
                return normalize_host(urlsplit(text).hostname or "")
            return normalize_host(text)
        return normalize_host(text)

    def to_dict(self) -> dict:
        return {
            "asset": self.asset,
            "type": self.type.value,
            "scope": self.scope,
            "program": self.program,
            "platform": self.platform,
            "restrictions": list(self.restrictions),
            "source": self.source,
            "last_verified": self.last_verified,
            "notes": list(self.notes),
        }


@dataclass
class Scope:
    entries: list[ScopeEntry] = field(default_factory=list)
    program: str | None = None
    platform: str | None = None
    source: str | None = None

    @property
    def includes(self) -> list[ScopeEntry]:
        return [e for e in self.entries if not e.is_exclude]

    @property
    def excludes(self) -> list[ScopeEntry]:
        return [e for e in self.entries if e.is_exclude]

    def add(self, entry: ScopeEntry) -> None:
        if entry.program is None:
            entry.program = self.program
        if entry.platform is None:
            entry.platform = self.platform
        if entry.source is None:
            entry.source = self.source
        self.entries.append(entry)

    def to_dict(self) -> dict:
        return {
            "program": self.program,
            "platform": self.platform,
            "source": self.source,
            "entries": [e.to_dict() for e in self.entries],
        }

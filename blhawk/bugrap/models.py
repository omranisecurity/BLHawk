"""BugRap program data model."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..scope.model import AssetType, Scope, ScopeEntry, infer_asset_type


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ProgramAsset:
    asset: str
    type: str = "domain"
    scope: str = "in"

    def as_scope_entry(self, program: str | None, source: str | None) -> ScopeEntry:
        try:
            atype = AssetType(self.type)
        except ValueError:
            atype = infer_asset_type(self.asset)
        return ScopeEntry(
            asset=self.asset,
            type=atype,
            scope=self.scope,
            program=program,
            platform="bugrap",
            source=source,
        )

    def to_dict(self) -> dict:
        return {"asset": self.asset, "type": self.type, "scope": self.scope}


@dataclass
class Program:
    name: str
    url: str | None = None
    platform: str = "bugrap"
    bounty_range: str | None = None
    assets: list[ProgramAsset] = field(default_factory=list)
    restrictions: list[str] = field(default_factory=list)
    rate_limit: str | None = None
    safe_harbor: str | None = None
    source_url: str | None = None
    scope_last_checked: str | None = None
    research_status: str = "unreviewed"

    # -- derived metrics -----------------------------------------------
    @property
    def in_scope_assets(self) -> list[ProgramAsset]:
        return [a for a in self.assets if a.scope == "in"]

    @property
    def excluded_assets(self) -> list[ProgramAsset]:
        return [a for a in self.assets if a.scope == "out"]

    def in_scope_domain_count(self) -> int:
        return sum(
            1
            for a in self.in_scope_assets
            if a.type in ("domain", "wildcard", "url", "api")
        )

    def has_wildcard(self) -> bool:
        return any(a.type == "wildcard" for a in self.in_scope_assets)

    def requires_manual(self) -> bool:
        text = " ".join(self.restrictions).lower()
        return "manual" in text or self.research_status == "manual_required"

    # -- conversions ----------------------------------------------------
    def to_scope(self) -> Scope:
        scope = Scope(program=self.name, platform=self.platform, source=self.source_url)
        for asset in self.assets:
            scope.add(asset.as_scope_entry(self.name, self.source_url))
        return scope

    def asset_keys(self) -> set[str]:
        return {f"{a.scope}:{a.type}:{a.asset.lower()}" for a in self.assets}

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "url": self.url,
            "platform": self.platform,
            "bounty_range": self.bounty_range,
            "assets": [a.to_dict() for a in self.assets],
            "restrictions": list(self.restrictions),
            "rate_limit": self.rate_limit,
            "safe_harbor": self.safe_harbor,
            "source_url": self.source_url,
            "scope_last_checked": self.scope_last_checked,
            "research_status": self.research_status,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Program:
        assets = [
            ProgramAsset(
                asset=a["asset"],
                type=a.get("type", "domain"),
                scope=a.get("scope", "in"),
            )
            for a in data.get("assets", [])
        ]
        return cls(
            name=data["name"],
            url=data.get("url"),
            platform=data.get("platform", "bugrap"),
            bounty_range=data.get("bounty_range"),
            assets=assets,
            restrictions=list(data.get("restrictions", [])),
            rate_limit=data.get("rate_limit"),
            safe_harbor=data.get("safe_harbor"),
            source_url=data.get("source_url"),
            scope_last_checked=data.get("scope_last_checked"),
            research_status=data.get("research_status", "unreviewed"),
        )

    def touch(self) -> None:
        self.scope_last_checked = _now()

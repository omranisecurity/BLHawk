"""Parse BugRap program metadata from user-provided exports or program pages.

Structured import (JSON/YAML/CSV) is the primary, reliable path. HTML
extraction is a conservative best-effort helper for static scope tables and
should always be verified against the official program rules.
"""

from __future__ import annotations

import json
import re
from html import unescape

import yaml

from ..core.errors import BLHawkError
from ..scope.model import infer_asset_type
from .models import Program, ProgramAsset

_TAG_RE = re.compile(r"<[^>]+>")
_WILDCARD_RE = re.compile(r"\*\.[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_REPO_RE = re.compile(r"https?://(?:github|gitlab)\.com/[^\s<>\"']+", re.IGNORECASE)


def _program_from_mapping(data: dict) -> Program:
    if "name" not in data:
        raise BLHawkError("program entry missing 'name'")
    assets: list[ProgramAsset] = []
    for item in data.get("assets", []) or []:
        if isinstance(item, str):
            assets.append(ProgramAsset(asset=item, type=infer_asset_type(item).value))
        elif isinstance(item, dict):
            asset = item.get("asset") or item.get("host") or item.get("domain")
            if not asset:
                continue
            assets.append(
                ProgramAsset(
                    asset=asset,
                    type=item.get("type") or infer_asset_type(asset).value,
                    scope=item.get("scope", "in"),
                )
            )
    for item in data.get("out_of_scope", []) or data.get("excludes", []) or []:
        asset = item if isinstance(item, str) else item.get("asset")
        if asset:
            atype = infer_asset_type(asset).value
            assets.append(ProgramAsset(asset=asset, type=atype, scope="out"))
    data = dict(data)
    data["assets"] = [a.to_dict() for a in assets]
    return Program.from_dict(data)


def parse_programs(text: str, fmt: str) -> list[Program]:
    fmt = fmt.lower().lstrip(".")
    if fmt == "json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise BLHawkError(f"invalid JSON program data: {exc}") from exc
    elif fmt in ("yaml", "yml"):
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise BLHawkError(f"invalid YAML program data: {exc}") from exc
    else:
        raise BLHawkError(f"unsupported program format: {fmt}")

    if isinstance(data, dict):
        items = data.get("programs", [data])
    elif isinstance(data, list):
        items = data
    else:
        raise BLHawkError("unsupported program structure")
    return [_program_from_mapping(item) for item in items]


def parse_program_html(html: str, name: str, source_url: str | None = None) -> Program:
    """Best-effort extraction of scope tokens from a static program page.

    This is intentionally conservative and must be verified against official
    rules; JS-rendered pages will yield little and should be imported instead.
    """
    text = unescape(_TAG_RE.sub(" ", html))
    assets: list[ProgramAsset] = []
    seen: set[str] = set()

    def add(asset: str, atype: str) -> None:
        key = asset.lower()
        if key not in seen:
            seen.add(key)
            assets.append(ProgramAsset(asset=asset, type=atype, scope="in"))

    for repo in _REPO_RE.findall(html):
        add(repo.rstrip(".,"), "repository")
    for wc in _WILDCARD_RE.findall(text):
        add(wc, "wildcard")
    for dom in _DOMAIN_RE.findall(text):
        if dom.lower() in seen or any(dom in w for w in seen):
            continue
        # Skip obvious non-asset domains from page chrome.
        if dom.lower() in ("bugrap.io", "www.bugrap.io"):
            continue
        add(dom, "domain")

    program = Program(
        name=name,
        url=source_url,
        source_url=source_url,
        assets=assets,
        research_status="unreviewed",
    )
    program.touch()
    return program

"""Scope parsers for txt, JSON, YAML and CSV inputs.

All formats normalize into a :class:`Scope`. YAML is parsed with
``yaml.safe_load`` only (never ``load``) to avoid unsafe deserialization.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import yaml

from ..core.errors import ScopeError
from .model import AssetType, Scope, ScopeEntry, infer_asset_type


def _coerce_type(value: str | None, asset: str) -> AssetType:
    if value:
        try:
            return AssetType(value.strip().lower())
        except ValueError:
            pass
    return infer_asset_type(asset)


def _entry_from_mapping(item: dict, default_scope: str = "in") -> ScopeEntry:
    asset = str(item.get("asset") or item.get("host") or item.get("domain") or "").strip()
    if not asset:
        raise ScopeError(f"scope entry missing 'asset': {item!r}")
    restrictions = item.get("restrictions") or []
    if isinstance(restrictions, str):
        restrictions = [restrictions]
    return ScopeEntry(
        asset=asset,
        type=_coerce_type(item.get("type"), asset),
        scope=str(item.get("scope") or default_scope).lower(),
        program=item.get("program"),
        platform=item.get("platform"),
        restrictions=list(restrictions),
        source=item.get("source"),
        last_verified=item.get("last_verified"),
        notes=list(item.get("notes") or []),
    )


def parse_txt(text: str) -> Scope:
    """One asset per line. ``#`` comments; ``!`` prefix marks an exclusion."""
    scope = Scope(source="txt")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        is_exclude = line.startswith("!")
        asset = line[1:].strip() if is_exclude else line
        if not asset:
            continue
        scope.add(
            ScopeEntry(
                asset=asset,
                type=infer_asset_type(asset),
                scope="out" if is_exclude else "in",
            )
        )
    return scope


def _scope_from_structured(data: object) -> Scope:
    scope = Scope()
    if isinstance(data, dict):
        scope.program = data.get("program")
        scope.platform = data.get("platform")
        scope.source = data.get("source")
        items = data.get("assets") or data.get("scope") or data.get("entries") or []
        excludes = data.get("out_of_scope") or data.get("excludes") or []
    elif isinstance(data, list):
        items = data
        excludes = []
    else:
        raise ScopeError("unsupported scope structure")

    for item in items:
        if isinstance(item, str):
            scope.add(ScopeEntry(asset=item, type=infer_asset_type(item), scope="in"))
        elif isinstance(item, dict):
            scope.add(_entry_from_mapping(item, default_scope="in"))
        else:
            raise ScopeError(f"unsupported scope item: {item!r}")
    for item in excludes:
        if isinstance(item, str):
            scope.add(ScopeEntry(asset=item, type=infer_asset_type(item), scope="out"))
        elif isinstance(item, dict):
            scope.add(_entry_from_mapping(item, default_scope="out"))
    return scope


def parse_json(text: str) -> Scope:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ScopeError(f"invalid JSON scope: {exc}") from exc
    return _scope_from_structured(data)


def parse_yaml(text: str) -> Scope:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ScopeError(f"invalid YAML scope: {exc}") from exc
    return _scope_from_structured(data)


def parse_csv(text: str) -> Scope:
    scope = Scope(source="csv")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return scope
    for row in reader:
        clean = {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
        scope.add(_entry_from_mapping(clean, default_scope="in"))
    return scope


def parse_scope(text: str, fmt: str) -> Scope:
    fmt = fmt.lower().lstrip(".")
    if fmt in ("txt", "text", "lst"):
        return parse_txt(text)
    if fmt == "json":
        return parse_json(text)
    if fmt in ("yaml", "yml"):
        return parse_yaml(text)
    if fmt == "csv":
        return parse_csv(text)
    raise ScopeError(f"unsupported scope format: {fmt}")


def load_scope_file(path: str | Path) -> Scope:
    p = Path(path)
    if not p.exists():
        raise ScopeError(f"scope file not found: {p}")
    fmt = p.suffix.lstrip(".") or "txt"
    return parse_scope(p.read_text(encoding="utf-8"), fmt)

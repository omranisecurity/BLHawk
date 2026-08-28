"""Scope subsystem: parse, normalize, and enforce authorized testing scope."""
from __future__ import annotations

from .matcher import classify_target
from .model import AssetType, Scope, ScopeEntry
from .parsers import load_scope_file, parse_scope

__all__ = [
    "AssetType",
    "Scope",
    "ScopeEntry",
    "classify_target",
    "load_scope_file",
    "parse_scope",
]

"""Load target lists from files, stdin, or a parsed scope."""
from __future__ import annotations

import sys
from pathlib import Path

from ..core.errors import ConfigError
from ..scope.model import AssetType, Scope


def read_target_file(path: str | Path) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"target file not found: {p}")
    targets: list[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line)
    return targets


def read_stdin() -> list[str]:
    if sys.stdin is None or sys.stdin.isatty():
        return []
    return [line.strip() for line in sys.stdin if line.strip() and not line.startswith("#")]


def targets_from_scope(scope: Scope) -> list[str]:
    """Derive concrete probe URLs from a scope.

    Only URL/API/REPOSITORY assets map to concrete resources BLHawk can probe.
    Bare domains and wildcards describe host ranges, not specific resources, so
    they are not turned into targets automatically.
    """
    targets: list[str] = []
    for entry in scope.includes:
        if entry.type in (AssetType.URL, AssetType.API, AssetType.REPOSITORY):
            targets.append(entry.asset)
    return targets

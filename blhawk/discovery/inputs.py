"""Load target lists from files, stdin, or a parsed scope."""
from __future__ import annotations

import sys
from pathlib import Path

from ..core.errors import ConfigError
from ..scope.model import AssetType, Scope

#: Refuse absurdly large input files to bound memory (malicious-input guard).
MAX_INPUT_BYTES = 50 * 1024 * 1024
MAX_INPUT_LINES = 1_000_000


def read_target_file(path: str | Path) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"target file not found: {p}")
    size = p.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise ConfigError(f"target file too large ({size} bytes > {MAX_INPUT_BYTES})")
    targets: list[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line)
        if len(targets) > MAX_INPUT_LINES:
            raise ConfigError(f"target file has too many lines (> {MAX_INPUT_LINES})")
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

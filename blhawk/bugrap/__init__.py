"""BugRap program intelligence (safe, import-first).

BLHawk does not mass-scrape the BugRap directory. It consumes program metadata
that the user provides (exported JSON/YAML/CSV) or, optionally, a single
program page fetched with the user's authorization and while honoring
``robots.txt``. Official program rules are always treated as the authoritative
scope source and are re-validated before any live scan. Program metadata is
cached with timestamps so scope changes can be detected.
"""
from __future__ import annotations

from .models import Program, ProgramAsset
from .store import ChangeSet, ProgramStore

__all__ = ["ChangeSet", "Program", "ProgramAsset", "ProgramStore"]

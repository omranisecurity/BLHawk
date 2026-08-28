"""CLI glue for BugRap program intelligence."""

from __future__ import annotations

import os
from pathlib import Path

from ..core.errors import BLHawkError
from ..scope.model import Scope
from .parser import parse_programs
from .prioritize import prioritize
from .store import ProgramStore


def default_store_dir() -> Path:
    base = os.environ.get("BLHAWK_HOME")
    if base:
        return Path(base)
    return Path.home() / ".cache" / "blhawk"


def get_store(store_dir: str | Path | None = None) -> ProgramStore:
    directory = Path(store_dir) if store_dir else default_store_dir()
    return ProgramStore(directory / "bugrap_programs.json")


def _normalize_program_name(program: str | None) -> str | None:
    if not program:
        return None
    if ":" in program:
        _platform, _, name = program.partition(":")
        return name
    return program


def resolve_program_scope(
    platform: str | None, program: str | None, store_dir: str | Path | None = None
) -> Scope:
    name = _normalize_program_name(program)
    if not name:
        raise BLHawkError("a --program name is required (e.g. bugrap:example)")
    store = get_store(store_dir)
    prog = store.get(name)
    if prog is None:
        raise BLHawkError(
            f"program '{name}' not found in the local store; import it first "
            f"with --import-programs (store: {store.path})"
        )
    return prog.to_scope()


def import_programs_file(path: str, store_dir: str | Path | None = None) -> int:
    p = Path(path)
    if not p.exists():
        raise BLHawkError(f"program file not found: {p}")
    fmt = p.suffix.lstrip(".") or "json"
    programs = parse_programs(p.read_text(encoding="utf-8"), fmt)
    store = get_store(store_dir)
    changed = 0
    for program in programs:
        change = store.upsert(program)
        if change.changed:
            changed += 1
            status = "new" if change.is_new else "updated"
            print(f"  {status}: {program.name} (+{len(change.added)} -{len(change.removed)})")
    print(f"Imported {len(programs)} program(s); {changed} changed.")
    return 0


def list_programs_cli(platform: str | None, store_dir: str | Path | None = None) -> int:
    store = get_store(store_dir)
    programs = store.list()
    if platform:
        programs = [p for p in programs if p.platform.lower() == platform.lower()]
    if not programs:
        print(f"No programs in store ({store.path}). Import with --import-programs.")
        return 0
    print(f"{'PROGRAM':<28} {'ASSETS':>6} {'WILDCARD':>8} {'STATUS':<16} SCORE")
    for scored in prioritize(programs):
        p = scored.program
        print(
            f"{p.name[:27]:<28} {p.in_scope_domain_count():>6} "
            f"{'yes' if p.has_wildcard() else 'no':>8} "
            f"{p.research_status[:15]:<16} {scored.score}"
        )
    return 0

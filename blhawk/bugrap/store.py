"""On-disk cache of BugRap program metadata with change detection."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..core.errors import BLHawkError
from .models import Program


@dataclass
class ChangeSet:
    program: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    is_new: bool = False

    @property
    def changed(self) -> bool:
        return self.is_new or bool(self.added) or bool(self.removed)


class ProgramStore:
    """A JSON-file-backed store of programs keyed by name."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _load_raw(self) -> dict[str, dict]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BLHawkError(f"corrupt program store {self.path}: {exc}") from exc
        return data.get("programs", {})

    def load(self) -> dict[str, Program]:
        return {name: Program.from_dict(d) for name, d in self._load_raw().items()}

    def list(self) -> list[Program]:
        return sorted(self.load().values(), key=lambda p: p.name.lower())

    def get(self, name: str) -> Program | None:
        return self.load().get(name)

    def save(self, programs: dict[str, Program]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"programs": {name: p.to_dict() for name, p in programs.items()}}
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def upsert(self, program: Program) -> ChangeSet:
        """Insert or update a program, returning what changed."""
        programs = self.load()
        existing = programs.get(program.name)
        if existing is None:
            change = ChangeSet(
                program=program.name, is_new=True, added=sorted(program.asset_keys())
            )
        else:
            old_keys = existing.asset_keys()
            new_keys = program.asset_keys()
            change = ChangeSet(
                program=program.name,
                added=sorted(new_keys - old_keys),
                removed=sorted(old_keys - new_keys),
            )
        programs[program.name] = program
        self.save(programs)
        return change

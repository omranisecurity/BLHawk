"""BugRap program-intelligence tests (fixture-based; no live calls)."""
from __future__ import annotations

from pathlib import Path

import pytest

from blhawk.bugrap.integration import (
    get_store,
    import_programs_file,
    list_programs_cli,
    resolve_program_scope,
)
from blhawk.bugrap.models import Program, ProgramAsset
from blhawk.bugrap.parser import parse_program_html, parse_programs
from blhawk.bugrap.prioritize import prioritize
from blhawk.bugrap.store import ProgramStore
from blhawk.core.errors import BLHawkError
from blhawk.core.models import ScopeStatus
from blhawk.scope.matcher import classify_target

FIXTURE = Path(__file__).parent / "data" / "bugrap_programs.json"


def test_parse_programs_json():
    programs = parse_programs(FIXTURE.read_text(), "json")
    assert len(programs) == 2
    web3 = next(p for p in programs if p.name == "example-web3")
    assert web3.has_wildcard()
    assert web3.bounty_range == "up to 5000 USDC"
    assert any(a.scope == "out" for a in web3.assets)


def test_program_to_scope_enforces_exclusions():
    programs = parse_programs(FIXTURE.read_text(), "json")
    scope = next(p for p in programs if p.name == "example-web3").to_scope()
    assert classify_target("https://api.example.org/", scope).status == ScopeStatus.IN_SCOPE
    assert classify_target("https://admin.example.org/", scope).status == ScopeStatus.OUT_OF_SCOPE


def test_store_upsert_and_change_detection(tmp_path):
    store = ProgramStore(tmp_path / "programs.json")
    p1 = Program(name="p", assets=[ProgramAsset("a.com", "domain")])
    change = store.upsert(p1)
    assert change.is_new is True

    p2 = Program(name="p", assets=[ProgramAsset("a.com", "domain"),
                                   ProgramAsset("b.com", "domain")])
    change = store.upsert(p2)
    assert change.is_new is False
    assert any("b.com" in a for a in change.added)
    assert change.removed == []

    p3 = Program(name="p", assets=[ProgramAsset("b.com", "domain")])
    change = store.upsert(p3)
    assert any("a.com" in r for r in change.removed)


def test_import_and_resolve_roundtrip(tmp_path, capsys):
    rc = import_programs_file(str(FIXTURE), store_dir=tmp_path)
    assert rc == 0
    scope = resolve_program_scope("bugrap", "bugrap:example-web3", store_dir=tmp_path)
    assert scope.program == "example-web3"
    assert classify_target("https://x.example.org/", scope).status == ScopeStatus.IN_SCOPE


def test_resolve_unknown_program_raises(tmp_path):
    with pytest.raises(BLHawkError):
        resolve_program_scope("bugrap", "does-not-exist", store_dir=tmp_path)


def test_list_programs_cli(tmp_path, capsys):
    import_programs_file(str(FIXTURE), store_dir=tmp_path)
    capsys.readouterr()
    rc = list_programs_cli("bugrap", store_dir=tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "example-web3" in out
    assert "manual-only-app" in out


def test_prioritization_prefers_broader_supported_program(tmp_path):
    programs = parse_programs(FIXTURE.read_text(), "json")
    ranked = prioritize(programs)
    # The web3 program (wildcard + github repo support) should outrank the
    # manual-only mobile app program.
    assert ranked[0].program.name == "example-web3"
    manual = next(s for s in ranked if s.program.name == "manual-only-app")
    assert manual.score < ranked[0].score


def test_manual_program_flagged():
    programs = parse_programs(FIXTURE.read_text(), "json")
    manual = next(p for p in programs if p.name == "manual-only-app")
    assert manual.requires_manual() is True


def test_parse_program_html_best_effort():
    html = """
    <table><tr><td>In Scope</td></tr>
    <tr><td>Websites</td><td>*.initverse.org</td></tr>
    <tr><td>Websites</td><td>*.inichain.com</td></tr>
    <tr><td>Blockchain</td><td>https://github.com/initverse/contracts</td></tr>
    </table>
    """
    program = parse_program_html(html, "initverse", "https://bugrap.io/bounties/initverse")
    assets = {a.asset for a in program.assets}
    assert "*.initverse.org" in assets
    assert "https://github.com/initverse/contracts" in assets
    assert program.scope_last_checked is not None


def test_store_dir_get_store(tmp_path):
    store = get_store(tmp_path)
    assert store.path.parent == tmp_path

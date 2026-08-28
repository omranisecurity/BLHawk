"""CLI tests for the BugRap program workflow."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import responses

from blhawk.cli.main import main
from blhawk.core.ssrf import SSRFGuard

FIXTURE = str(Path(__file__).parent / "data" / "bugrap_programs.json")


@pytest.fixture
def offline_dns(monkeypatch):
    monkeypatch.setattr(SSRFGuard, "resolve", lambda self, host: ["93.184.216.34"])


def test_list_programs_empty(tmp_path, capsys):
    rc = main(["--list-programs", "--store-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No programs" in out


def test_import_then_list(tmp_path, capsys):
    rc = main(["--import-programs", FIXTURE, "--store-dir", str(tmp_path)])
    assert rc == 0
    capsys.readouterr()
    rc = main(["--list-programs", "--store-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "example-web3" in out


def test_program_scope_enforced_scan(tmp_path, capsys):
    main(["--import-programs", FIXTURE, "--store-dir", str(tmp_path)])
    capsys.readouterr()
    rc = main(
        [
            "--program",
            "bugrap:example-web3",
            "--store-dir",
            str(tmp_path),
            "-u",
            "https://api.example.org/x",
            "-u",
            "https://admin.example.org/x",
            "--dry-run",
            "--format",
            "json",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    data = {d["target"]: d["scope"]["status"] for d in json.loads(out)}
    assert data["https://api.example.org/x"] == "IN_SCOPE"
    assert data["https://admin.example.org/x"] == "OUT_OF_SCOPE"


def test_unknown_program_errors(tmp_path, capsys):
    rc = main(
        ["--program", "bugrap:nope", "--store-dir", str(tmp_path), "-u", "https://x.example.org/"]
    )
    err = capsys.readouterr().err
    assert rc == 2
    assert "not found" in err


@responses.activate
def test_fetch_program_cli(offline_dns, tmp_path, capsys):
    responses.add(
        responses.GET, "https://bugrap.io/robots.txt", status=200, body="User-agent: *\nAllow: /"
    )
    responses.add(
        responses.GET,
        "https://bugrap.io/bounties/demo",
        status=200,
        body="<table><tr><td>*.demo.org</td></tr></table>",
    )
    rc = main(
        [
            "--fetch-program",
            "https://bugrap.io/bounties/demo",
            "--program",
            "demo",
            "--store-dir",
            str(tmp_path),
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "VERIFY against official rules" in out

"""Output formatter tests."""
from __future__ import annotations

import csv
import io
import json

from blhawk.core.models import (
    Evidence,
    Finding,
    Reclaimability,
    ScopeResult,
    ScopeStatus,
    Severity,
    Target,
    Verdict,
)
from blhawk.output.formatters import format_findings


def _finding():
    return Finding(
        target=Target(raw="https://github.com/ghost", url="https://github.com/ghost",
                      host="github.com", provider="github"),
        provider="github",
        verdict=Verdict.POTENTIALLY_RECLAIMABLE,
        severity=Severity.MEDIUM,
        confidence=0.65,
        evidence=Evidence(http_status=404, resource_state="missing",
                          reclaimability=Reclaimability.POSSIBLE,
                          signals=["http-status=404"]),
        scope=ScopeResult(status=ScopeStatus.IN_SCOPE, program="Example"),
    )


def test_terminal_format_contains_key_fields():
    out = format_findings([_finding()], fmt="terminal", use_color=False)
    assert "github" in out
    assert "POTENTIALLY_RECLAIMABLE" in out
    assert "65%" in out
    assert "IN_SCOPE" in out


def test_silent_format_is_tab_separated():
    out = format_findings([_finding()], silent=True)
    assert out == "POTENTIALLY_RECLAIMABLE\thttps://github.com/ghost\n"


def test_json_format_roundtrips():
    out = format_findings([_finding()], fmt="json")
    data = json.loads(out)
    assert data[0]["status"] == "POTENTIALLY_RECLAIMABLE"
    assert data[0]["scope"]["status"] == "IN_SCOPE"
    assert data[0]["evidence"]["http_status"] == 404


def test_jsonl_one_object_per_line():
    out = format_findings([_finding(), _finding()], fmt="jsonl")
    lines = [ln for ln in out.splitlines() if ln]
    assert len(lines) == 2
    assert json.loads(lines[0])["provider"] == "github"


def test_csv_format_has_header_and_row():
    out = format_findings([_finding()], fmt="csv")
    rows = list(csv.DictReader(io.StringIO(out)))
    assert rows[0]["status"] == "POTENTIALLY_RECLAIMABLE"
    assert rows[0]["http_status"] == "404"


def test_markdown_table():
    out = format_findings([_finding()], fmt="markdown")
    assert "| Severity |" in out
    assert "github" in out


def test_empty_findings_terminal():
    assert "No findings" in format_findings([], fmt="terminal", use_color=False)

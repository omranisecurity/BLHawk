"""CLI tests. Network is either avoided (dry-run) or mocked (responses)."""

from __future__ import annotations

import json

import pytest
import responses

from blhawk.cli.main import main
from blhawk.core.ssrf import SSRFGuard


@pytest.fixture
def offline_dns(monkeypatch):
    monkeypatch.setattr(SSRFGuard, "resolve", lambda self, host: ["93.184.216.34"])


def test_list_providers(capsys):
    rc = main(["--list-providers"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "github" in out
    assert "pypi" in out


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_validate_scope_ok(tmp_path, capsys):
    f = tmp_path / "scope.txt"
    f.write_text("example.com\n*.example.com\n!secret.example.com\n")
    rc = main(["--validate-scope", str(f)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "2 in-scope, 1 excluded" in out


def test_validate_scope_bad(tmp_path, capsys):
    f = tmp_path / "scope.json"
    f.write_text("{not valid json")
    rc = main(["--validate-scope", str(f)])
    assert rc == 1


def test_no_targets_returns_error(capsys):
    rc = main([])
    err = capsys.readouterr().err
    assert rc == 2
    assert "no targets" in err


def test_dry_run_no_network(capsys):
    # No responses mock and no DNS patch: dry-run must not touch the network.
    rc = main(["-u", "https://github.com/whoever", "--dry-run", "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data[0]["status"] == "UNKNOWN"
    assert any("dry-run" in n for n in data[0]["research_notes"])


@responses.activate
def test_end_to_end_scan_json(offline_dns, capsys):
    responses.add(responses.GET, "https://github.com/ghost", status=404)
    rc = main(
        [
            "-u",
            "https://github.com/ghost",
            "--format",
            "json",
            "--no-soft404",
            "--no-color",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data[0]["status"] == "POTENTIALLY_RECLAIMABLE"


@responses.activate
def test_silent_output(offline_dns, capsys):
    responses.add(responses.GET, "https://github.com/ghost", status=404)
    rc = main(["-u", "github.com/ghost", "--silent", "--no-soft404"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out == "POTENTIALLY_RECLAIMABLE\thttps://github.com/ghost\n"


@responses.activate
def test_output_file_written(offline_dns, tmp_path, capsys):
    responses.add(responses.GET, "https://pypi.org/pypi/ghostpkg/json", status=404)
    out_file = tmp_path / "results.json"
    rc = main(
        [
            "-u",
            "https://pypi.org/project/ghostpkg/",
            "--output",
            str(out_file),
            "--no-soft404",
            "--silent",
        ]
    )
    assert rc == 0
    data = json.loads(out_file.read_text())
    assert data[0]["provider"] == "pypi"
    assert data[0]["status"] == "DEAD_RESOURCE"  # PyPI names not reclaimable


@responses.activate
def test_extract_links(offline_dns, capsys):
    page = (
        '<a href="https://github.com/ghostuser">x</a>'
        '<a href="https://pypi.org/project/req/">y</a>'
    )
    responses.add(responses.GET, "https://example.com/links", status=200, body=page)
    responses.add(responses.GET, "https://github.com/ghostuser", status=404)
    responses.add(responses.GET, "https://pypi.org/pypi/req/json", status=200, body="{}")
    rc = main(
        [
            "-u",
            "https://example.com/links",
            "--extract-links",
            "--format",
            "json",
            "--no-soft404",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    targets = {d["target"] for d in data}
    assert "https://github.com/ghostuser" in targets
    assert "https://pypi.org/project/req" in targets


def test_invalid_threads_returns_error(capsys):
    rc = main(["-u", "https://github.com/x", "--threads", "0"])
    assert rc == 2


@responses.activate
def test_provider_filter(offline_dns, capsys):
    responses.add(responses.GET, "https://github.com/a", status=404)
    rc = main(
        [
            "-u",
            "https://github.com/a",
            "-u",
            "https://gitlab.com/b",
            "--provider",
            "github",
            "--format",
            "json",
            "--no-soft404",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert len(data) == 1
    assert data[0]["provider"] == "github"

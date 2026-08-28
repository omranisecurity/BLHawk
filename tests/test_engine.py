"""Scan engine tests: dedup, scope enforcement, dry-run, soft-404, ordering."""
from __future__ import annotations

import re

import responses

from blhawk.core.config import ScanConfig
from blhawk.core.engine import Scanner, prepare_targets
from blhawk.core.models import ScopeStatus, Verdict
from blhawk.scope.model import AssetType, Scope, ScopeEntry


def _scanner(client, scope=None, **cfg):
    cfg.setdefault("enable_soft404", False)
    cfg.setdefault("threads", 2)
    return Scanner(config=ScanConfig(**cfg), scope=scope, http_client=client)


def test_prepare_targets_dedup_and_normalize():
    targets = prepare_targets([
        "github.com/foo",
        "https://github.com/foo/",  # duplicate after normalization
        "https://github.com/bar#frag",
        "",
    ])
    urls = [t.url for t in targets]
    assert urls == ["https://github.com/foo", "https://github.com/bar"]
    assert targets[0].provider == "github"


@responses.activate
def test_scan_missing_github_user(client):
    responses.add(responses.GET, "https://github.com/ghost", status=404)
    scanner = _scanner(client)
    findings = scanner.scan(["https://github.com/ghost"])
    assert len(findings) == 1
    assert findings[0].verdict == Verdict.POTENTIALLY_RECLAIMABLE


@responses.activate
def test_scan_present_is_not_vulnerable(client):
    responses.add(responses.GET, "https://github.com/torvalds", status=200, body="ok")
    findings = _scanner(client).scan(["https://github.com/torvalds"])
    assert findings[0].verdict == Verdict.NOT_VULNERABLE


def test_dry_run_makes_no_requests(client):
    # No responses registered; a real request would raise ConnectionError.
    scanner = _scanner(client, dry_run=True)
    findings = scanner.scan(["https://github.com/whoever"])
    assert findings[0].verdict == Verdict.UNKNOWN
    assert any("dry-run" in n for n in findings[0].research_notes)


def test_scope_enforcement_skips_out_of_scope(client):
    scope = Scope(program="P")
    scope.add(ScopeEntry(asset="in-scope.example", type=AssetType.DOMAIN, scope="in"))
    scanner = _scanner(client, scope=scope)
    findings = scanner.scan(["https://github.com/foo"])  # not in scope
    assert findings[0].scope.status == ScopeStatus.UNKNOWN
    assert any("skipped" in n for n in findings[0].research_notes)


@responses.activate
def test_scope_in_scope_is_scanned(client):
    responses.add(responses.GET, "https://github.com/ghost", status=404)
    scope = Scope(program="P")
    scope.add(ScopeEntry(asset="github.com", type=AssetType.DOMAIN, scope="in"))
    scanner = _scanner(client, scope=scope)
    findings = scanner.scan(["https://github.com/ghost"])
    assert findings[0].scope.status == ScopeStatus.IN_SCOPE
    assert findings[0].verdict == Verdict.POTENTIALLY_RECLAIMABLE


@responses.activate
def test_no_provider_target_is_unknown(client):
    responses.add(responses.GET, "https://unknown.example/x", status=404)
    findings = _scanner(client).scan(["https://unknown.example/x"])
    assert findings[0].verdict == Verdict.UNKNOWN
    assert any("no provider" in n for n in findings[0].research_notes)


@responses.activate
def test_soft404_catchall_downgrades_present(client):
    body = "<html><body>generic catch-all page</body></html>"
    responses.add(responses.GET, "https://github.com/realish", status=200, body=body)
    responses.add(
        responses.GET,
        re.compile(r"https://github\.com/blhawk-nonexistent-.*"),
        status=200,
        body=body,
    )
    scanner = _scanner(client, enable_soft404=True)
    findings = scanner.scan(["https://github.com/realish"])
    assert findings[0].verdict == Verdict.UNKNOWN
    assert findings[0].evidence.soft_404 is True


@responses.activate
def test_deterministic_ordering(client):
    responses.add(responses.GET, "https://github.com/a", status=404)
    responses.add(responses.GET, "https://gitlab.com/b", status=200, body="ok")
    responses.add(responses.GET, "https://pypi.org/pypi/c/json", status=404)
    scanner = _scanner(client, threads=3)
    order = ["https://github.com/a", "https://gitlab.com/b", "https://pypi.org/project/c/"]
    findings = scanner.scan(order)
    assert [f.target.url for f in findings] == [
        "https://github.com/a",
        "https://gitlab.com/b",
        "https://pypi.org/project/c",
    ]


def test_cancellation_is_graceful(client, monkeypatch):
    scanner = _scanner(client, threads=1)
    calls = {"n": 0}
    real = scanner.scan_target

    def flaky(target):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise KeyboardInterrupt
        return real(target)

    monkeypatch.setattr(scanner, "scan_target", flaky)
    # Should not propagate KeyboardInterrupt; returns partial results.
    findings = scanner.scan(["https://github.com/a", "https://github.com/b"])
    assert isinstance(findings, list)

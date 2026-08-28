"""Discovery input tests: files, stdin, scope-derived targets, link extraction."""

from __future__ import annotations

import io

import pytest

from blhawk.core.errors import ConfigError
from blhawk.discovery.inputs import read_stdin, read_target_file, targets_from_scope
from blhawk.discovery.urls import extract_links
from blhawk.scope.model import AssetType, Scope, ScopeEntry


def test_read_target_file(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("# comment\nhttps://github.com/a\n\nhttps://gitlab.com/b\n")
    assert read_target_file(f) == ["https://github.com/a", "https://gitlab.com/b"]


def test_read_target_file_missing(tmp_path):
    with pytest.raises(ConfigError):
        read_target_file(tmp_path / "nope.txt")


def test_read_stdin(monkeypatch):
    fake = io.StringIO("https://github.com/a\n# c\nhttps://gitlab.com/b\n")
    fake.isatty = lambda: False  # type: ignore[assignment]
    monkeypatch.setattr("sys.stdin", fake)
    assert read_stdin() == ["https://github.com/a", "https://gitlab.com/b"]


def test_targets_from_scope_only_concrete_assets():
    scope = Scope(program="P")
    scope.add(ScopeEntry(asset="*.example.com", type=AssetType.WILDCARD, scope="in"))
    scope.add(
        ScopeEntry(asset="https://github.com/org/repo", type=AssetType.REPOSITORY, scope="in")
    )
    scope.add(ScopeEntry(asset="https://example.com/api", type=AssetType.URL, scope="in"))
    targets = targets_from_scope(scope)
    assert "https://github.com/org/repo" in targets
    assert "https://example.com/api" in targets
    # Wildcards/domains describe ranges, not concrete probe URLs.
    assert "*.example.com" not in targets


def test_extract_links_fixes_trailing_markup():
    html = (
        '<a href="https://www.youtube.com/@handle">x</a>'
        " bare https://github.com/user, and (https://pypi.org/project/req/)"
    )
    links = extract_links(html)
    assert "https://www.youtube.com/@handle" in links
    assert "https://github.com/user" in links  # trailing comma stripped
    assert "https://pypi.org/project/req/" in links  # trailing ")" stripped
    # The original bug captured trailing markup like "</a"; ensure it does not.
    assert all("</a" not in link for link in links)


def test_extract_links_dedup():
    html = "https://x.com/a https://x.com/a https://x.com/a"
    assert extract_links(html) == ["https://x.com/a"]

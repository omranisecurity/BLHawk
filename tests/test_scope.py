"""Scope engine tests: normalization, matching matrix, precedence, parsers."""
from __future__ import annotations

import pytest

from blhawk.core.models import ScopeStatus
from blhawk.scope import classify_target, parse_scope
from blhawk.scope.hostnames import host_in_wildcard, normalize_host
from blhawk.scope.model import AssetType, Scope, ScopeEntry, infer_asset_type


# -- hostname normalization -------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("[::1]", "::1"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),
    ],
)
def test_normalize_host(raw, expected):
    assert normalize_host(raw) == expected


# -- wildcard matching security cases --------------------------------------
@pytest.mark.parametrize(
    "host,matches",
    [
        ("example.com", True),
        ("www.example.com", True),
        ("api.example.com", True),
        ("foo.bar.example.com", True),
        ("EXAMPLE.com", True),
        ("example.com.evil.com", False),
        ("evil-example.com", False),
        ("example.org", False),
        ("notexample.com", False),
    ],
)
def test_wildcard_matching(host, matches):
    assert host_in_wildcard(host, "example.com") is matches


# -- asset type inference --------------------------------------------------
@pytest.mark.parametrize(
    "asset,expected",
    [
        ("*.example.com", AssetType.WILDCARD),
        ("example.com", AssetType.DOMAIN),
        ("https://example.com/api/v1", AssetType.URL),
        ("https://example.com", AssetType.DOMAIN),
        ("10.0.0.0/8", AssetType.CIDR),
        ("192.168.1.1", AssetType.IP),
        ("2001:db8::/32", AssetType.CIDR),
        ("pkg:pypi/requests", AssetType.PACKAGE),
    ],
)
def test_infer_asset_type(asset, expected):
    assert infer_asset_type(asset) == expected


# -- classification matrix -------------------------------------------------
def _scope(*assets, excludes=(), types=None):
    scope = Scope(program="Test")
    for a in assets:
        scope.add(ScopeEntry(asset=a, type=infer_asset_type(a), scope="in"))
    for a in excludes:
        scope.add(ScopeEntry(asset=a, type=infer_asset_type(a), scope="out"))
    return scope


def test_exact_domain_matches_only_apex():
    scope = _scope("example.com")
    assert classify_target("https://example.com/x", scope).status == ScopeStatus.IN_SCOPE
    assert classify_target("https://api.example.com/x", scope).status == ScopeStatus.UNKNOWN


def test_wildcard_matches_subdomains():
    scope = _scope("*.example.com")
    for host in ["example.com", "www.example.com", "a.b.example.com"]:
        assert classify_target(f"https://{host}/", scope).status == ScopeStatus.IN_SCOPE
    assert classify_target("https://example.com.evil.com/", scope).status == ScopeStatus.UNKNOWN


def test_exclude_precedence_beats_include():
    scope = _scope("*.example.com", excludes=["secret.example.com"])
    assert classify_target("https://secret.example.com/", scope).status == ScopeStatus.OUT_OF_SCOPE
    assert classify_target("https://ok.example.com/", scope).status == ScopeStatus.IN_SCOPE


def test_url_path_scope():
    scope = _scope("https://example.com/api")
    assert classify_target("https://example.com/api/users", scope).status == ScopeStatus.IN_SCOPE
    assert classify_target("https://example.com/other", scope).status == ScopeStatus.UNKNOWN


def test_cidr_matching():
    scope = _scope("10.0.0.0/24")
    assert classify_target("http://10.0.0.5/", scope).status == ScopeStatus.IN_SCOPE
    assert classify_target("http://10.0.1.5/", scope).status == ScopeStatus.UNKNOWN


def test_ipv6_cidr_matching():
    scope = _scope("2001:db8::/32")
    assert classify_target("http://[2001:db8::1]/", scope).status == ScopeStatus.IN_SCOPE
    assert classify_target("http://[2001:dead::1]/", scope).status == ScopeStatus.UNKNOWN


def test_case_and_trailing_dot_normalization():
    scope = _scope("example.com")
    assert classify_target("https://EXAMPLE.com./x", scope).status == ScopeStatus.IN_SCOPE


def test_punycode_scope_matches_unicode_target():
    scope = _scope("xn--mnchen-3ya.de")
    assert classify_target("https://münchen.de/x", scope).status == ScopeStatus.IN_SCOPE


def test_unknown_when_no_rule():
    scope = _scope("example.com")
    assert classify_target("https://other.org/", scope).status == ScopeStatus.UNKNOWN


def test_mobile_app_asset_requires_manual_review():
    scope = Scope(program="T")
    scope.add(ScopeEntry(asset="com.example.app", type=AssetType.MOBILE_APP, scope="in"))
    # A mobile app asset is not host-addressable; a URL target won't match it.
    assert classify_target("https://example.com/", scope).status == ScopeStatus.UNKNOWN


def test_restriction_marks_manual_review():
    scope = Scope(program="T")
    scope.add(ScopeEntry(asset="example.com", type=AssetType.DOMAIN, scope="in",
                         restrictions=["manual testing only"]))
    result = classify_target("https://example.com/", scope)
    assert result.status == ScopeStatus.REQUIRES_MANUAL_REVIEW


def test_malformed_target_is_unknown():
    scope = _scope("example.com")
    assert classify_target("not a url", scope).status == ScopeStatus.UNKNOWN


# -- parsers ---------------------------------------------------------------
def test_parse_txt_with_excludes():
    text = "# comment\nexample.com\n*.example.com\n!secret.example.com\n"
    scope = parse_scope(text, "txt")
    assert len(scope.includes) == 2
    assert len(scope.excludes) == 1
    assert scope.excludes[0].asset == "secret.example.com"


def test_parse_json():
    text = (
        '{"program":"P","assets":["example.com",'
        '{"asset":"*.api.example.com","type":"wildcard"}],'
        '"out_of_scope":["no.example.com"]}'
    )
    scope = parse_scope(text, "json")
    assert scope.program == "P"
    assert len(scope.includes) == 2
    assert scope.excludes[0].asset == "no.example.com"


def test_parse_yaml():
    text = "program: P\nassets:\n  - example.com\n  - asset: '*.example.com'\n    type: wildcard\n"
    scope = parse_scope(text, "yaml")
    assert scope.program == "P"
    assert any(e.type == AssetType.WILDCARD for e in scope.includes)


def test_parse_csv():
    text = "asset,type,scope\nexample.com,domain,in\nsecret.example.com,domain,out\n"
    scope = parse_scope(text, "csv")
    assert len(scope.includes) == 1
    assert len(scope.excludes) == 1


def test_yaml_uses_safe_load():
    # A YAML tag that would execute under unsafe load must be rejected/ignored.
    import pytest as _pytest

    from blhawk.core.errors import ScopeError

    text = "assets: !!python/object/apply:os.system ['echo pwned']"
    with _pytest.raises(ScopeError):
        parse_scope(text, "yaml")

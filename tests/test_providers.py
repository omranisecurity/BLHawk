"""Tests for the built-in providers and the registry."""

from __future__ import annotations

import pytest
import responses

from blhawk.core.models import Reclaimability, Target
from blhawk.providers.base import (
    STATE_BLOCKED,
    STATE_MISSING,
    STATE_PRESENT,
    STATE_UNKNOWN,
    ProviderContext,
)
from blhawk.providers.registry import find_provider, get_provider, get_providers


def _ctx(url, client):
    provider = find_provider(url)
    assert provider is not None, f"no provider for {url}"
    target = Target(raw=url, url=url, host="", provider=provider.name)
    return provider, ProviderContext(target=target, http=client)


# -- registry --------------------------------------------------------------
def test_registry_loads_expected_providers():
    names = {p.name for p in get_providers()}
    expected = {
        "github",
        "gitlab",
        "npm",
        "pypi",
        "youtube",
        "vimeo",
        "twitch",
        "soundcloud",
        "telegram",
        "pinterest",
        "googleplay",
        "myket",
        "cafebazaar",
        "medium",
        "dev",
        "buymeacoffee",
        "dribbble",
    }
    assert expected <= names


def test_find_provider_normalizes_www():
    assert find_provider("https://www.youtube.com/@x").name == "youtube"
    assert find_provider("https://youtube.com/@x").name == "youtube"


def test_find_provider_unknown_host():
    assert find_provider("https://unknown-platform.example/foo") is None


def test_normalize_strips_fragment_and_trailing_slash():
    p = get_provider("github")
    assert p.normalize("HTTPS://GitHub.com/Example/#frag") == "https://github.com/Example"


# -- status-based providers -------------------------------------------------
@responses.activate
def test_github_missing_user(client):
    responses.add(responses.GET, "https://github.com/ghostuser", status=404)
    provider, ctx = _ctx("https://github.com/ghostuser", client)
    signals = provider.evaluate(ctx)
    assert signals.state == STATE_MISSING
    assert signals.reclaimability == Reclaimability.POSSIBLE


@responses.activate
def test_github_present_user(client):
    responses.add(responses.GET, "https://github.com/torvalds", status=200, body="ok")
    provider, ctx = _ctx("https://github.com/torvalds", client)
    assert provider.evaluate(ctx).state == STATE_PRESENT


@responses.activate
def test_github_reserved_namespace_not_reclaimable(client):
    responses.add(responses.GET, "https://github.com/features", status=404)
    provider, ctx = _ctx("https://github.com/features", client)
    signals = provider.evaluate(ctx)
    assert signals.state == STATE_PRESENT
    assert signals.reclaimability == Reclaimability.IMPOSSIBLE


@responses.activate
def test_github_403_is_blocked_not_missing(client):
    responses.add(responses.GET, "https://github.com/x", status=403)
    provider, ctx = _ctx("https://github.com/x", client)
    assert provider.evaluate(ctx).state == STATE_BLOCKED


# -- gitlab sign-in ambiguity ----------------------------------------------
@responses.activate
def test_gitlab_signin_redirect_is_unknown(client):
    responses.add(
        responses.GET,
        "https://gitlab.com/private-group",
        status=302,
        headers={"Location": "https://gitlab.com/users/sign_in"},
    )
    responses.add(responses.GET, "https://gitlab.com/users/sign_in", status=200, body="login")
    provider, ctx = _ctx("https://gitlab.com/private-group", client)
    # The client follows the redirect; gitlab provider must see the ambiguity.
    signals = provider.evaluate(ctx)
    assert signals.state == STATE_UNKNOWN


@responses.activate
def test_gitlab_404_missing(client):
    responses.add(responses.GET, "https://gitlab.com/ghost", status=404)
    provider, ctx = _ctx("https://gitlab.com/ghost", client)
    assert provider.evaluate(ctx).state == STATE_MISSING


# -- package registries (reclaimability nuance) ----------------------------
@responses.activate
def test_pypi_missing_is_impossible_reclaim(client):
    responses.add(responses.GET, "https://pypi.org/pypi/nonexistent-pkg-xyz/json", status=404)
    provider, ctx = _ctx("https://pypi.org/project/nonexistent-pkg-xyz/", client)
    signals = provider.evaluate(ctx)
    assert signals.state == STATE_MISSING
    assert signals.reclaimability == Reclaimability.IMPOSSIBLE


@responses.activate
def test_pypi_present(client):
    responses.add(responses.GET, "https://pypi.org/pypi/requests/json", status=200, body="{}")
    provider, ctx = _ctx("https://pypi.org/project/requests/", client)
    assert provider.evaluate(ctx).state == STATE_PRESENT


@responses.activate
def test_npm_missing_is_unlikely_reclaim(client):
    responses.add(responses.GET, "https://registry.npmjs.org/ghost-pkg", status=404)
    provider, ctx = _ctx("https://www.npmjs.com/package/ghost-pkg", client)
    signals = provider.evaluate(ctx)
    assert signals.state == STATE_MISSING
    assert signals.reclaimability == Reclaimability.UNLIKELY


# -- telegram false-positive guard -----------------------------------------
@responses.activate
def test_telegram_live_account_not_missing(client):
    body = '<div class="tgme_page_title">Channel</div> If you have Telegram right away'
    responses.add(responses.GET, "https://t.me/livechannel", status=200, body=body)
    provider, ctx = _ctx("https://t.me/livechannel", client)
    assert provider.evaluate(ctx).state == STATE_PRESENT


@responses.activate
def test_telegram_missing(client):
    responses.add(responses.GET, "https://t.me/ghost", status=200, body="<html>generic</html>")
    provider, ctx = _ctx("https://t.me/ghost", client)
    signals = provider.evaluate(ctx)
    assert signals.state == STATE_MISSING
    assert signals.reclaimability == Reclaimability.UNKNOWN


# -- app stores (impossible reclaim) ---------------------------------------
@responses.activate
def test_googleplay_missing_impossible(client):
    responses.add(responses.GET, "https://play.google.com/store/apps/details?id=x", status=404)
    provider, ctx = _ctx("https://play.google.com/store/apps/details?id=x", client)
    signals = provider.evaluate(ctx)
    assert signals.state == STATE_MISSING
    assert signals.reclaimability == Reclaimability.IMPOSSIBLE


# -- content / design body fingerprints ------------------------------------
@responses.activate
def test_medium_generic_title_missing(client):
    responses.add(
        responses.GET,
        "https://medium.com/@ghost",
        status=200,
        body='<title data-rh="true">Medium</title>',
    )
    provider, ctx = _ctx("https://medium.com/@ghost", client)
    assert provider.evaluate(ctx).state == STATE_MISSING


@responses.activate
def test_dribbble_page_gone(client):
    responses.add(responses.GET, "https://dribbble.com/ghost", status=404, body="that page is gone")
    provider, ctx = _ctx("https://dribbble.com/ghost", client)
    assert provider.evaluate(ctx).state == STATE_MISSING


# -- probe error handling ---------------------------------------------------
def test_provider_probe_error_is_unknown(monkeypatch):
    from blhawk.core.http_client import SafeHTTPClient
    from blhawk.core.ssrf import SSRFGuard

    guard = SSRFGuard()
    monkeypatch.setattr(guard, "resolve", lambda host: ["10.0.0.1"])  # blocked
    client = SafeHTTPClient(guard=guard, retries=0)
    provider, ctx = _ctx("https://github.com/x", client)
    signals = provider.evaluate(ctx)
    assert signals.state == STATE_UNKNOWN
    assert signals.error


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/Example/", "Example"),
        ("https://www.youtube.com/@handle", "handle"),
        ("https://t.me/mychannel", "mychannel"),
    ],
)
def test_extract_identifier(url, expected):
    provider = find_provider(url)
    assert provider.extract_identifier(url) == expected

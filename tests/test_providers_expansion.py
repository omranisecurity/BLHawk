"""Tests for the curated provider expansion (Phase 8)."""

from __future__ import annotations

import responses

from blhawk.core.models import Reclaimability, Target
from blhawk.providers.base import STATE_MISSING, STATE_PRESENT, STATE_UNKNOWN, ProviderContext
from blhawk.providers.registry import find_provider, get_providers


def _eval(url, client):
    provider = find_provider(url)
    assert provider is not None, url
    target = Target(raw=url, url=url, host="", provider=provider.name)
    return provider.evaluate(ProviderContext(target=target, http=client))


def test_expected_new_providers_registered():
    names = {p.name for p in get_providers()}
    expected = {
        "bitbucket",
        "rubygems",
        "packagist",
        "crates",
        "hashnode",
        "substack",
        "behance",
        "appstore",
        "fdroid",
        "reddit",
        "bluesky",
        "twitter",
        "facebook",
        "linkedin",
        "discord",
    }
    assert expected <= names


@responses.activate
def test_bitbucket_missing(client):
    responses.add(responses.GET, "https://bitbucket.org/ghostws", status=404)
    signals = _eval("https://bitbucket.org/ghostws", client)
    assert signals.state == STATE_MISSING
    assert signals.reclaimability == Reclaimability.POSSIBLE


@responses.activate
def test_rubygems_api_probe(client):
    responses.add(responses.GET, "https://rubygems.org/api/v1/gems/ghostgem.json", status=404)
    signals = _eval("https://rubygems.org/gems/ghostgem", client)
    assert signals.state == STATE_MISSING
    assert signals.reclaimability == Reclaimability.UNLIKELY


@responses.activate
def test_packagist_vendor_name_probe(client):
    responses.add(responses.GET, "https://packagist.org/packages/acme/widget.json", status=404)
    signals = _eval("https://packagist.org/packages/acme/widget", client)
    assert signals.state == STATE_MISSING


@responses.activate
def test_crates_missing_is_reclaimable(client):
    responses.add(responses.GET, "https://crates.io/api/v1/crates/ghostcrate", status=404)
    signals = _eval("https://crates.io/crates/ghostcrate", client)
    assert signals.state == STATE_MISSING
    assert signals.reclaimability == Reclaimability.POSSIBLE


@responses.activate
def test_substack_subdomain_matched(client):
    responses.add(responses.GET, "https://ghost.substack.com/", status=404)
    provider = find_provider("https://ghost.substack.com/")
    assert provider.name == "substack"
    signals = _eval("https://ghost.substack.com/", client)
    assert signals.state == STATE_MISSING


@responses.activate
def test_appstore_missing_impossible(client):
    responses.add(responses.GET, "https://apps.apple.com/us/app/x/id999", status=404)
    signals = _eval("https://apps.apple.com/us/app/x/id999", client)
    assert signals.state == STATE_MISSING
    assert signals.reclaimability == Reclaimability.IMPOSSIBLE


@responses.activate
def test_reddit_present_has_note(client):
    responses.add(responses.GET, "https://reddit.com/user/spez", status=200, body="ok")
    signals = _eval("https://reddit.com/user/spez", client)
    assert signals.state == STATE_PRESENT
    assert any("rate-limit" in n for n in signals.notes)


def test_manual_providers_do_not_request(client):
    # No responses registered: a request would raise. Manual providers must not
    # issue any request and must return UNKNOWN with a manual-review note.
    for url in [
        "https://twitter.com/someone",
        "https://x.com/someone",
        "https://facebook.com/someone",
        "https://linkedin.com/in/someone",
        "https://discord.gg/abcd",
    ]:
        signals = _eval(url, client)
        assert signals.state == STATE_UNKNOWN
        assert any("manual" in n.lower() for n in signals.notes)


def test_provider_count_is_substantial():
    # 17 original + curated expansion.
    assert len(get_providers()) >= 30

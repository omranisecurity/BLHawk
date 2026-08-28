"""Package-registry providers (npm, PyPI).

Important nuance: most package registries do NOT allow re-registering the
name of a deleted/yanked package (PyPI forbids it outright; npm reserves
unpublished names). So a missing package is usually a *dead resource*, not a
takeover candidate. Reclaimability is set accordingly and the detection
engine will not escalate these to takeover on a 404 alone.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from ..core.http_client import HTTPResponse
from ..core.models import Reclaimability, Severity, Target
from .base import (
    STATE_MISSING,
    STATE_PRESENT,
    STATE_UNKNOWN,
    InterpretResult,
    ProviderContext,
    StatusProvider,
)
from .registry import register


def _path_segments(url: str) -> list[str]:
    return [seg for seg in urlsplit(url).path.split("/") if seg]


def _first_path_segment(url: str) -> str | None:
    segments = _path_segments(url)
    if not segments:
        return None
    # Registry web URLs prefix the name with a route segment.
    if segments[0] in ("package", "project", "crates", "gems", "packages") and len(segments) > 1:
        if segments[0] == "packages" and len(segments) > 2:  # packagist vendor/name
            return f"{segments[1]}/{segments[2]}"
        return segments[1]
    return segments[0]


@register
class NpmProvider(StatusProvider):
    name = "npm"
    hosts = ("npmjs.com", "www.npmjs.com")
    resource_type = "package"
    default_reclaimability = Reclaimability.UNLIKELY
    default_severity = Severity.LOW

    def probe_url(self, target: Target) -> str:
        pkg = _first_path_segment(target.url)
        return f"https://registry.npmjs.org/{pkg}" if pkg else target.url

    def interpret(self, resp: HTTPResponse, ctx: ProviderContext) -> InterpretResult:
        result = super().interpret(resp, ctx)
        if result.state == STATE_MISSING:
            result.notes.append("npm reserves unpublished names; reclaim is unlikely")
        return result


@register
class PyPIProvider(StatusProvider):
    name = "pypi"
    hosts = ("pypi.org",)
    resource_type = "project"
    default_reclaimability = Reclaimability.IMPOSSIBLE
    default_severity = Severity.LOW

    def probe_url(self, target: Target) -> str:
        pkg = _first_path_segment(target.url)
        return f"https://pypi.org/pypi/{pkg}/json" if pkg else target.url

    def interpret(self, resp: HTTPResponse, ctx: ProviderContext) -> InterpretResult:
        status = resp.status_code
        if status == 404:
            return InterpretResult(
                state=STATE_MISSING,
                signals=["pypi-json=404"],
                notes=["PyPI forbids re-registering deleted names; not reclaimable"],
            )
        if status == 200:
            return InterpretResult(state=STATE_PRESENT, signals=["pypi-json=200"])
        return InterpretResult(state=STATE_UNKNOWN, signals=[f"http-status={status}"])


@register
class RubyGemsProvider(StatusProvider):
    name = "rubygems"
    hosts = ("rubygems.org",)
    resource_type = "gem"
    default_reclaimability = Reclaimability.UNLIKELY
    default_severity = Severity.LOW

    def probe_url(self, target: Target) -> str:
        gem = _first_path_segment(target.url)
        return f"https://rubygems.org/api/v1/gems/{gem}.json" if gem else target.url


@register
class PackagistProvider(StatusProvider):
    name = "packagist"
    hosts = ("packagist.org",)
    resource_type = "package"
    default_reclaimability = Reclaimability.UNLIKELY
    default_severity = Severity.LOW

    def probe_url(self, target: Target) -> str:
        pkg = _first_path_segment(target.url)
        return f"https://packagist.org/packages/{pkg}.json" if pkg else target.url


@register
class CratesProvider(StatusProvider):
    name = "crates"
    hosts = ("crates.io",)
    resource_type = "crate"
    # crates.io never deletes published crates, so a 404 means the name was
    # never taken and is therefore registerable.
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM

    def probe_url(self, target: Target) -> str:
        crate = _first_path_segment(target.url)
        return f"https://crates.io/api/v1/crates/{crate}" if crate else target.url

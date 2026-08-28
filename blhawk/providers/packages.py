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


def _first_path_segment(url: str) -> str | None:
    segments = [seg for seg in urlsplit(url).path.split("/") if seg]
    if not segments:
        return None
    if segments[0] == "package" and len(segments) > 1:  # npmjs.com/package/<name>
        return segments[1]
    if segments[0] == "project" and len(segments) > 1:  # pypi.org/project/<name>
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

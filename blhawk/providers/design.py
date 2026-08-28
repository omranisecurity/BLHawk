"""Design/creative providers (Dribbble)."""

from __future__ import annotations

from ..core.http_client import HTTPResponse
from ..core.models import Reclaimability, Severity
from .base import (
    STATE_MISSING,
    STATE_PRESENT,
    STATE_UNKNOWN,
    InterpretResult,
    Provider,
    ProviderContext,
    StatusProvider,
)
from .registry import register


@register
class DribbbleProvider(Provider):
    name = "dribbble"
    hosts = ("dribbble.com",)
    resource_type = "user"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.LOW

    def interpret(self, resp: HTTPResponse, ctx: ProviderContext) -> InterpretResult:
        body = resp.text.lower()
        if resp.status_code == 404 or "that page is gone" in body:
            return InterpretResult(state=STATE_MISSING, signals=["dribbble-page-gone"])
        if resp.status_code == 200:
            return InterpretResult(state=STATE_PRESENT, signals=["http-status=200"])
        return InterpretResult(state=STATE_UNKNOWN, signals=[f"http-status={resp.status_code}"])


@register
class BehanceProvider(StatusProvider):
    name = "behance"
    hosts = ("behance.net", "www.behance.net")
    resource_type = "user"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM

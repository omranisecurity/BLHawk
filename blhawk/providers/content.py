"""Content/publishing providers (Medium, DEV, Buy Me a Coffee)."""
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
class MediumProvider(Provider):
    name = "medium"
    hosts = ("medium.com",)
    resource_type = "user/publication"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM

    def interpret(self, resp: HTTPResponse, ctx: ProviderContext) -> InterpretResult:
        if resp.status_code == 404:
            return InterpretResult(state=STATE_MISSING, signals=["http-status=404"])
        body = resp.text
        # Missing Medium users render the generic shell whose title is just
        # "Medium"; a live profile has a personalized <title>.
        if '<title data-rh="true">Medium</title>' in body:
            return InterpretResult(state=STATE_MISSING, signals=["generic-medium-title"])
        if resp.status_code == 200:
            return InterpretResult(state=STATE_PRESENT, signals=["http-status=200"])
        return InterpretResult(state=STATE_UNKNOWN, signals=[f"http-status={resp.status_code}"])


@register
class DevToProvider(StatusProvider):
    name = "dev"
    hosts = ("dev.to",)
    resource_type = "user/organization"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM


@register
class BuyMeACoffeeProvider(StatusProvider):
    name = "buymeacoffee"
    hosts = ("buymeacoffee.com",)
    resource_type = "creator page"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.LOW


@register
class HashnodeProvider(StatusProvider):
    name = "hashnode"
    hosts = ("hashnode.com",)
    host_suffixes = (".hashnode.dev",)
    resource_type = "user/blog"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM


@register
class SubstackProvider(StatusProvider):
    name = "substack"
    hosts = ("substack.com",)
    host_suffixes = (".substack.com",)
    resource_type = "publication"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM

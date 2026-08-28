"""Social-platform providers (Telegram, Pinterest).

Telegram is a good example of why a naive check is dangerous: t.me returns
HTTP 200 for both existing and non-existing usernames, so status alone is
useless and the presence of the "contact right away" block actually marks a
*live* account. We fingerprint the body instead and stay conservative about
reclaimability.
"""

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

_TELEGRAM_PRESENT_MARKERS = (
    "tgme_page_title",
    "tgme_page_extra",
    "tgme_page_photo",
)
_TELEGRAM_CONTACT_MARKER = ("if you have", "right away")


@register
class TelegramProvider(Provider):
    name = "telegram"
    hosts = ("t.me", "telegram.me", "telegram.dog")
    resource_type = "channel/user"
    default_reclaimability = Reclaimability.UNKNOWN
    default_severity = Severity.LOW

    def interpret(self, resp: HTTPResponse, ctx: ProviderContext) -> InterpretResult:
        body = resp.text.lower()
        if resp.status_code != 200:
            return InterpretResult(state=STATE_UNKNOWN, signals=[f"http-status={resp.status_code}"])
        if any(marker in body for marker in _TELEGRAM_PRESENT_MARKERS):
            return InterpretResult(state=STATE_PRESENT, signals=["tgme-preview-present"])
        if all(part in body for part in _TELEGRAM_CONTACT_MARKER):
            return InterpretResult(
                state=STATE_PRESENT,
                signals=["telegram-contact-block-present"],
                notes=["contact block indicates a LIVE account (not a takeover)"],
            )
        return InterpretResult(
            state=STATE_MISSING,
            signals=["no-telegram-preview"],
            notes=["Telegram username reuse is not straightforward; reclaim unknown"],
        )


@register
class RedditProvider(StatusProvider):
    name = "reddit"
    hosts = ("reddit.com", "www.reddit.com", "old.reddit.com")
    resource_type = "user/subreddit"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM

    def interpret(self, resp: HTTPResponse, ctx: ProviderContext) -> InterpretResult:
        result = super().interpret(resp, ctx)
        result.notes.append("Reddit rate-limits aggressively; keep concurrency low")
        return result


@register
class BlueskyProvider(StatusProvider):
    name = "bluesky"
    hosts = ("bsky.app",)
    resource_type = "handle"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM


@register
class PinterestProvider(StatusProvider):
    name = "pinterest"
    hosts = ("pinterest.com", "www.pinterest.com")
    resource_type = "user"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM

    def interpret(self, resp: HTTPResponse, ctx: ProviderContext) -> InterpretResult:
        body = resp.text.lower()
        if "user not found" in body or resp.status_code == 404:
            return InterpretResult(state=STATE_MISSING, signals=["pinterest-user-not-found"])
        if resp.status_code == 200:
            return InterpretResult(state=STATE_PRESENT, signals=["http-status=200"])
        return InterpretResult(state=STATE_UNKNOWN, signals=[f"http-status={resp.status_code}"])

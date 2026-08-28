"""Manual-only providers for platforms with strict anti-automation controls.

X/Twitter, Facebook, LinkedIn and Discord aggressively rate-limit and block
automated access. BLHawk refuses to probe them automatically (it will not try
to bypass those controls). These providers only recognize the URLs and flag
them for manual, authorized review — they never issue requests.
"""

from __future__ import annotations

from ..core.models import Reclaimability, Severity
from .base import Provider
from .registry import register


class ManualProvider(Provider):
    """A provider that classifies from the URL only and never sends requests."""

    manual_only = True
    default_reclaimability = Reclaimability.UNKNOWN
    default_severity = Severity.INFO

    def interpret(self, resp, ctx):  # pragma: no cover - never called
        raise NotImplementedError


@register
class TwitterProvider(ManualProvider):
    name = "twitter"
    hosts = ("twitter.com", "x.com", "www.twitter.com", "www.x.com")
    resource_type = "account (manual review)"


@register
class FacebookProvider(ManualProvider):
    name = "facebook"
    hosts = ("facebook.com", "www.facebook.com", "fb.com")
    resource_type = "page/profile (manual review)"


@register
class LinkedInProvider(ManualProvider):
    name = "linkedin"
    hosts = ("linkedin.com", "www.linkedin.com")
    resource_type = "profile/company (manual review)"


@register
class DiscordProvider(ManualProvider):
    name = "discord"
    hosts = ("discord.com", "discord.gg", "discordapp.com")
    resource_type = "invite/server (manual review)"

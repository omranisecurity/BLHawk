"""Media-platform providers (YouTube, Vimeo, Twitch, SoundCloud).

Deleted channels/handles can sometimes be re-registered, letting an attacker
capture links embedded in old content or documentation.
"""

from __future__ import annotations

from ..core.models import Reclaimability, Severity
from .base import StatusProvider
from .registry import register


@register
class YouTubeProvider(StatusProvider):
    name = "youtube"
    hosts = ("youtube.com", "www.youtube.com", "m.youtube.com")
    resource_type = "channel/handle"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM


@register
class VimeoProvider(StatusProvider):
    name = "vimeo"
    hosts = ("vimeo.com",)
    resource_type = "user/video"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM


@register
class TwitchProvider(StatusProvider):
    name = "twitch"
    hosts = ("twitch.tv",)
    resource_type = "channel"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM


@register
class SoundCloudProvider(StatusProvider):
    name = "soundcloud"
    hosts = ("soundcloud.com",)
    resource_type = "user"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM

"""App-store providers (Google Play, Myket, CafeBazaar).

App identifiers (package names) generally cannot be reused once published, so
a removed app is a dead resource rather than a takeover candidate. This is a
deliberate example of not treating every 404 as vulnerable.
"""

from __future__ import annotations

from ..core.models import Reclaimability, Severity
from .base import StatusProvider
from .registry import register


@register
class GooglePlayProvider(StatusProvider):
    name = "googleplay"
    hosts = ("play.google.com",)
    resource_type = "app/developer"
    default_reclaimability = Reclaimability.IMPOSSIBLE
    default_severity = Severity.LOW


@register
class MyketProvider(StatusProvider):
    name = "myket"
    hosts = ("myket.ir",)
    resource_type = "app"
    default_reclaimability = Reclaimability.IMPOSSIBLE
    default_severity = Severity.LOW


@register
class CafeBazaarProvider(StatusProvider):
    name = "cafebazaar"
    hosts = ("cafebazaar.ir",)
    resource_type = "app"
    default_reclaimability = Reclaimability.IMPOSSIBLE
    default_severity = Severity.LOW


@register
class AppleAppStoreProvider(StatusProvider):
    name = "appstore"
    hosts = ("apps.apple.com", "itunes.apple.com")
    resource_type = "app"
    default_reclaimability = Reclaimability.IMPOSSIBLE
    default_severity = Severity.LOW


@register
class FDroidProvider(StatusProvider):
    name = "fdroid"
    hosts = ("f-droid.org",)
    resource_type = "app package"
    default_reclaimability = Reclaimability.IMPOSSIBLE
    default_severity = Severity.LOW

# Providers

A provider evaluates URLs for one platform. Providers live in
`blhawk/providers/` and self-register via the `@register` decorator.

## Supported platforms

- **Code hosting:** GitHub, GitLab, Bitbucket
- **Package registries:** npm, PyPI, RubyGems, Packagist, crates.io
- **Content/publishing:** Medium, DEV, Hashnode, Substack, Buy Me a Coffee
- **Media:** YouTube, Vimeo, Twitch, SoundCloud
- **Social:** Telegram, Pinterest, Reddit, Bluesky
- **App stores:** Google Play, Apple App Store, F-Droid, Myket, CafeBazaar
- **Design:** Dribbble, Behance
- **Manual-only (anti-bot):** X/Twitter, Facebook, LinkedIn, Discord — recognized
  but never probed automatically; flagged for manual, authorized review.

Run `blhawk --list-providers` for the live list.

## Reclaimability matters

Providers declare a `default_reclaimability` that the detection engine uses to
decide whether a missing resource is a takeover candidate:

- **Impossible/Unlikely** (PyPI, Google Play, app stores, npm): a 404 is a
  `DEAD_RESOURCE`, not a takeover.
- **Possible** (GitHub/GitLab/Bitbucket handles, media handles, crates.io names
  that were never taken): `POTENTIALLY_RECLAIMABLE`.

## False-positive guards

- GitHub reserved namespaces (e.g. `/features`) are treated as present.
- GitLab sign-in redirects are ambiguous (private vs. missing) → `UNKNOWN`.
- Telegram returns 200 for both live and missing usernames, so BLHawk
  fingerprints the body rather than trusting status; the "contact right away"
  block marks a *live* account.

## Adding a provider

```python
from ..core.models import Reclaimability, Severity
from .base import StatusProvider
from .registry import register


@register
class ExampleProvider(StatusProvider):
    name = "example"
    hosts = ("example.com", "www.example.com")
    host_suffixes = (".example.com",)     # optional wildcard host match
    resource_type = "user"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM
```

For non-status logic, subclass `Provider` and implement `interpret(resp, ctx)`
returning an `InterpretResult` (`STATE_PRESENT/MISSING/UNKNOWN/BLOCKED`). Use
`probe_url(target)` to hit an API endpoint instead of the web URL (see
`packages.py`).

Every provider must ship with tests covering present/missing/edge cases (see
`tests/test_providers.py`).

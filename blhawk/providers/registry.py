"""Provider registry and lookup.

Providers register themselves with :func:`register`. ``load_builtin_providers``
imports the built-in provider modules so their registrations run, then
``get_providers`` / ``find_provider`` expose them.
"""

from __future__ import annotations

import importlib
import pkgutil
from urllib.parse import urlsplit

from .base import Provider

_REGISTRY: dict[str, type[Provider]] = {}
_LOADED = False


def register(cls: type[Provider]) -> type[Provider]:
    """Class decorator that registers a provider by its ``name``."""
    if not cls.name:
        raise ValueError(f"provider {cls!r} must define a name")
    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        raise ValueError(f"duplicate provider name: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


def load_builtin_providers() -> None:
    """Import all provider submodules so their ``@register`` calls execute."""
    global _LOADED
    if _LOADED:
        return
    package = importlib.import_module(__package__)
    for module in pkgutil.iter_modules(package.__path__):
        if module.name in {"base", "registry"}:
            continue
        importlib.import_module(f"{__package__}.{module.name}")
    _LOADED = True


def get_provider_classes() -> list[type[Provider]]:
    load_builtin_providers()
    return sorted(_REGISTRY.values(), key=lambda c: c.name)


def get_providers() -> list[Provider]:
    return [cls() for cls in get_provider_classes()]


def get_provider(name: str) -> Provider | None:
    load_builtin_providers()
    cls = _REGISTRY.get(name)
    return cls() if cls else None


def find_provider(url: str) -> Provider | None:
    """Return the first provider that handles the URL's host."""
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return None
    for provider in get_providers():
        if provider.matches(host):
            return provider
    return None

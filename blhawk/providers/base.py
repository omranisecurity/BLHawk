"""Provider interface and helpers.

A provider is a small, declarative plugin describing how to evaluate URLs
for a single platform. The base class implements the common flow (host
matching, normalization, a safe probe request) so concrete providers only
implement the platform-specific interpretation of a response.

The design deliberately avoids one giant ``if/elif`` chain: providers are
registered and matched by host, and adding a platform means adding one file.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from ..core.errors import BLHawkError
from ..core.http_client import HTTPResponse, SafeHTTPClient
from ..core.models import Reclaimability, Severity, Target

# Resource states a provider can report after interpreting a response.
STATE_PRESENT = "present"
STATE_MISSING = "missing"
STATE_UNKNOWN = "unknown"
STATE_BLOCKED = "blocked"


@dataclass
class ProviderContext:
    """Everything a provider needs to evaluate a target."""

    target: Target
    http: SafeHTTPClient


@dataclass
class InterpretResult:
    """A provider's interpretation of a probe response."""

    state: str
    reclaimability: Reclaimability | None = None
    severity: Severity | None = None
    signals: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class ProviderSignals:
    """Structured output of :meth:`Provider.evaluate`.

    The detection engine consumes these signals (together with generic
    soft-404 detection) to produce a final verdict and confidence.
    """

    provider: str
    state: str = STATE_UNKNOWN
    reclaimability: Reclaimability = Reclaimability.UNKNOWN
    severity: Severity = Severity.INFO
    http_status: int | None = None
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    content_type: str | None = None
    title: str | None = None
    body_sample: str = ""
    signals: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None


def strip_www(host: str) -> str:
    host = (host or "").lower().strip().rstrip(".")
    return host[4:] if host.startswith("www.") else host


class Provider(ABC):
    """Base class for all providers."""

    #: Stable provider identifier (e.g. ``"github"``).
    name: str = ""
    #: Exact hostnames handled (``www.`` is normalized away automatically).
    hosts: tuple[str, ...] = ()
    #: Host suffixes handled (e.g. ``".substack.com"`` matches any subdomain).
    host_suffixes: tuple[str, ...] = ()
    #: Human label for the kind of resource (used in evidence/reports).
    resource_type: str = "resource"
    #: Default reclaimability for a confirmed-missing resource on this platform.
    default_reclaimability: Reclaimability = Reclaimability.UNKNOWN
    #: Default severity for a security-relevant finding.
    default_severity: Severity = Severity.MEDIUM
    #: HTTP method used for the probe request.
    http_method: str = "GET"
    #: If True this provider never issues automated requests (anti-bot / manual
    #: platforms); it classifies only from the URL structure.
    manual_only: bool = False

    # -- identification --------------------------------------------------
    def matches(self, host: str) -> bool:
        norm = strip_www(host)
        if norm in {strip_www(h) for h in self.hosts}:
            return True
        return any(norm == s.lstrip(".") or norm.endswith(s) for s in self.host_suffixes)

    def normalize(self, url: str) -> str:
        """Canonicalize a URL: lowercase host, drop fragment, strip trailing slash."""
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        netloc = host
        if parts.port:
            netloc = f"{host}:{parts.port}"
        path = parts.path.rstrip("/") or "/"
        return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))

    def extract_identifier(self, url: str) -> str | None:
        """Return the primary identifier (e.g. username) from a URL, if any."""
        parts = urlsplit(url)
        segments = [seg for seg in parts.path.split("/") if seg]
        if not segments:
            return None
        return segments[0].lstrip("@")

    def probe_url(self, target: Target) -> str:
        """URL to request when evaluating. API-based providers override this."""
        return target.url

    # -- evaluation ------------------------------------------------------
    @abstractmethod
    def interpret(self, resp: HTTPResponse, ctx: ProviderContext) -> InterpretResult:
        """Interpret a probe response into a resource state."""

    def evaluate(self, ctx: ProviderContext) -> ProviderSignals:
        signals = ProviderSignals(provider=self.name)
        if self.manual_only:
            signals.state = STATE_UNKNOWN
            signals.notes.append(
                "manual-only provider: automated probing disabled; supply verified data"
            )
            return signals
        url = self.probe_url(ctx.target)
        try:
            resp = ctx.http.request(self.http_method, url)
        except BLHawkError as exc:
            signals.state = STATE_UNKNOWN
            signals.error = str(exc)
            signals.signals.append(f"probe-error: {exc}")
            return signals

        signals.http_status = resp.status_code
        signals.final_url = resp.url
        signals.redirect_chain = list(resp.history)
        signals.content_type = resp.header("Content-Type") or None
        signals.body_sample = resp.text[:4096]
        result = self.interpret(resp, ctx)
        signals.state = result.state
        signals.reclaimability = (
            result.reclaimability
            if result.reclaimability is not None
            else self.default_reclaimability
        )
        signals.severity = result.severity if result.severity is not None else self.default_severity
        signals.signals.extend(result.signals)
        signals.notes.extend(result.notes)
        return signals


class StatusProvider(Provider):
    """Convenience base for providers whose signal is mainly the HTTP status.

    ``missing_statuses`` mark a deleted/absent resource; ``present_statuses``
    (if set) mark a live resource. Anything else is ``unknown``. A generic
    soft-404 guard in the detection engine still applies on top of this.
    """

    missing_statuses: frozenset[int] = frozenset({404})
    present_statuses: frozenset[int] = frozenset({200})

    def interpret(self, resp: HTTPResponse, ctx: ProviderContext) -> InterpretResult:
        status = resp.status_code
        if status in self.missing_statuses:
            return InterpretResult(state=STATE_MISSING, signals=[f"http-status={status}"])
        if status in self.present_statuses:
            return InterpretResult(state=STATE_PRESENT, signals=[f"http-status={status}"])
        if status in (401, 403):
            return InterpretResult(
                state=STATE_BLOCKED,
                signals=[f"http-status={status} (access restricted)"],
            )
        if status in (429, 500, 502, 503, 504):
            return InterpretResult(
                state=STATE_UNKNOWN,
                signals=[f"http-status={status} (transient/unavailable)"],
            )
        return InterpretResult(state=STATE_UNKNOWN, signals=[f"http-status={status}"])

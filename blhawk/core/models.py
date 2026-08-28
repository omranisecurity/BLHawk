"""Core data models: verdicts, severities, scope status, targets, findings.

These models are intentionally serialization-friendly (``to_dict``) so that
the same objects drive terminal, JSON, JSONL, CSV and Markdown output.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class Verdict(enum.Enum):
    """Confidence-ordered classification of a target.

    The ordering (via :attr:`rank`) is meaningful: higher rank means a
    stronger/more security-relevant finding. A bare ``HTTP 404`` must never
    yield a verdict stronger than :attr:`DEAD_RESOURCE`.
    """

    NOT_VULNERABLE = "NOT_VULNERABLE"
    UNKNOWN = "UNKNOWN"
    DEAD_RESOURCE = "DEAD_RESOURCE"
    POTENTIALLY_RECLAIMABLE = "POTENTIALLY_RECLAIMABLE"
    RECLAIMABILITY_UNCONFIRMED = "RECLAIMABILITY_UNCONFIRMED"
    LIKELY_TAKEOVER = "LIKELY_TAKEOVER"
    CONFIRMED_BY_SAFE_VERIFICATION = "CONFIRMED_BY_SAFE_VERIFICATION"

    @property
    def rank(self) -> int:
        return _VERDICT_ORDER.index(self)

    def is_at_least(self, other: Verdict) -> bool:
        return self.rank >= other.rank


_VERDICT_ORDER: list[Verdict] = [
    Verdict.NOT_VULNERABLE,
    Verdict.UNKNOWN,
    Verdict.DEAD_RESOURCE,
    Verdict.POTENTIALLY_RECLAIMABLE,
    Verdict.RECLAIMABILITY_UNCONFIRMED,
    Verdict.LIKELY_TAKEOVER,
    Verdict.CONFIRMED_BY_SAFE_VERIFICATION,
]


class Severity(enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Reclaimability(enum.Enum):
    """How likely an identifier can be re-registered by an attacker."""

    UNKNOWN = "unknown"
    IMPOSSIBLE = "impossible"
    UNLIKELY = "unlikely"
    POSSIBLE = "possible"
    LIKELY = "likely"


class ScopeStatus(enum.Enum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"
    REQUIRES_MANUAL_REVIEW = "REQUIRES_MANUAL_REVIEW"


@dataclass
class ScopeResult:
    """Result of classifying a target against a scope."""

    status: ScopeStatus = ScopeStatus.UNKNOWN
    program: str | None = None
    matched_rule: str | None = None
    source: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "program": self.program,
            "matched_rule": self.matched_rule,
            "source": self.source,
            "reason": self.reason,
        }


@dataclass
class Target:
    """A single thing BLHawk may evaluate."""

    raw: str
    url: str
    host: str = ""
    provider: str | None = None
    identifier: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "url": self.url,
            "host": self.host,
            "provider": self.provider,
            "identifier": self.identifier,
            "metadata": self.metadata,
        }


@dataclass
class Evidence:
    """Signals gathered while evaluating a target.

    ``signals`` is a free-form ordered list of short, human-readable strings
    describing *why* a verdict was reached, so reports can show the reasoning.
    """

    http_status: int | None = None
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    resource_state: str | None = None
    reclaimability: Reclaimability = Reclaimability.UNKNOWN
    soft_404: bool | None = None
    content_type: str | None = None
    title: str | None = None
    signals: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def add_signal(self, signal: str) -> None:
        self.signals.append(signal)

    def to_dict(self) -> dict[str, Any]:
        return {
            "http_status": self.http_status,
            "final_url": self.final_url,
            "redirect_chain": list(self.redirect_chain),
            "resource_state": self.resource_state,
            "reclaimability": self.reclaimability.value,
            "soft_404": self.soft_404,
            "content_type": self.content_type,
            "title": self.title,
            "signals": list(self.signals),
            "notes": list(self.notes),
            "extra": dict(self.extra),
        }


@dataclass
class Finding:
    """The full result for one target."""

    target: Target
    provider: str | None
    verdict: Verdict = Verdict.UNKNOWN
    severity: Severity = Severity.INFO
    confidence: float = 0.0
    evidence: Evidence = field(default_factory=Evidence)
    scope: ScopeResult = field(default_factory=ScopeResult)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_ms: int | None = None
    errors: list[str] = field(default_factory=list)
    research_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.url,
            "raw_target": self.target.raw,
            "provider": self.provider,
            "status": self.verdict.value,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 4),
            "evidence": self.evidence.to_dict(),
            "scope": self.scope.to_dict(),
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
            "errors": list(self.errors),
            "research_notes": list(self.research_notes),
        }

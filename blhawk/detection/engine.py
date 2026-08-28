"""Detection engine: turn provider signals into a verdict + confidence.

Design principles:

* A bare ``HTTP 404`` never yields more than ``DEAD_RESOURCE``.
* Reclaimability drives escalation toward takeover verdicts.
* Passive detection never emits ``LIKELY_TAKEOVER`` or
  ``CONFIRMED_BY_SAFE_VERIFICATION`` — those require the (opt-in) safe
  verification step, so the tool never fabricates confirmation.
* When evidence is ambiguous the engine prefers ``UNKNOWN`` over a false
  vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.models import Evidence, Reclaimability, Severity, Verdict
from ..providers.base import (
    STATE_BLOCKED,
    STATE_MISSING,
    STATE_PRESENT,
    STATE_UNKNOWN,
    ProviderSignals,
)


@dataclass
class Classification:
    verdict: Verdict
    severity: Severity
    confidence: float
    signals: list[str]
    notes: list[str]


# Reclaimability -> (verdict, confidence, severity cap) for a missing resource.
_MISSING_MAP = {
    Reclaimability.IMPOSSIBLE: (Verdict.DEAD_RESOURCE, 0.9, Severity.INFO),
    Reclaimability.UNLIKELY: (Verdict.DEAD_RESOURCE, 0.8, Severity.LOW),
    Reclaimability.UNKNOWN: (Verdict.DEAD_RESOURCE, 0.55, Severity.LOW),
    Reclaimability.POSSIBLE: (Verdict.POTENTIALLY_RECLAIMABLE, 0.65, Severity.MEDIUM),
    Reclaimability.LIKELY: (Verdict.RECLAIMABILITY_UNCONFIRMED, 0.75, Severity.HIGH),
}


class DetectionEngine:
    def classify(
        self, signals: ProviderSignals, soft404_catch_all: bool | None = None
    ) -> Classification:
        notes = list(signals.notes)
        extra_signals: list[str] = []

        if signals.state == STATE_PRESENT:
            if soft404_catch_all:
                extra_signals.append("soft-404 catch-all detected")
                notes.append("presence unreliable: host is a soft-404 catch-all")
                return Classification(Verdict.UNKNOWN, Severity.INFO, 0.3, extra_signals, notes)
            return Classification(Verdict.NOT_VULNERABLE, Severity.INFO, 0.9, extra_signals, notes)

        if signals.state == STATE_BLOCKED:
            notes.append("access restricted (401/403); cannot determine state")
            return Classification(Verdict.UNKNOWN, Severity.INFO, 0.3, extra_signals, notes)

        if signals.state == STATE_UNKNOWN:
            return Classification(Verdict.UNKNOWN, Severity.INFO, 0.2, extra_signals, notes)

        if signals.state == STATE_MISSING:
            verdict, confidence, sev_cap = _MISSING_MAP.get(
                signals.reclaimability,
                (Verdict.DEAD_RESOURCE, 0.5, Severity.LOW),
            )
            # If the "missing" was inferred from a non-404 body fingerprint on a
            # catch-all host, we cannot trust it -> downgrade to UNKNOWN.
            if soft404_catch_all and signals.http_status not in (404, 410):
                notes.append("missing inferred on a soft-404 catch-all host; unreliable")
                return Classification(Verdict.UNKNOWN, Severity.INFO, 0.25, extra_signals, notes)
            severity = _min_severity(signals.severity, sev_cap)
            return Classification(verdict, severity, confidence, extra_signals, notes)

        return Classification(Verdict.UNKNOWN, Severity.INFO, 0.1, extra_signals, notes)

    def build_evidence(
        self,
        signals: ProviderSignals,
        classification: Classification,
        soft404_catch_all: bool | None = None,
    ) -> Evidence:
        return Evidence(
            http_status=signals.http_status,
            final_url=signals.final_url,
            redirect_chain=list(signals.redirect_chain),
            resource_state=signals.state,
            reclaimability=signals.reclaimability,
            soft_404=soft404_catch_all,
            content_type=signals.content_type,
            signals=list(signals.signals) + list(classification.signals),
            notes=list(classification.notes),
        )


_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def _min_severity(a: Severity, b: Severity) -> Severity:
    return a if _SEVERITY_ORDER.index(a) <= _SEVERITY_ORDER.index(b) else b

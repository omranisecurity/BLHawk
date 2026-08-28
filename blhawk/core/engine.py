"""The scan engine.

Ties providers, detection, scope and the safe HTTP client together with
bounded concurrency, per-host + global rate limiting, deduplication,
deterministic ordering, and graceful cancellation (Ctrl+C).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..detection.engine import DetectionEngine
from ..providers.base import (
    STATE_MISSING,
    STATE_PRESENT,
    Provider,
    ProviderContext,
    ProviderSignals,
)
from ..providers.registry import find_provider
from ..scope.matcher import classify_target
from ..scope.model import Scope
from .config import ScanConfig
from .http_client import SafeHTTPClient
from .logging import get_logger, sanitize
from .models import (
    Evidence,
    Finding,
    ScopeResult,
    ScopeStatus,
    Target,
    Verdict,
)
from .rate_limiter import RateLimiter
from .soft404 import Soft404Detector, random_control_url
from .ssrf import SSRFGuard

_log = get_logger("engine")

_SOFT404_STATUSES = {200, 202, 203}


def prepare_targets(raw_targets: Iterable[str]) -> list[Target]:
    """Normalize and de-duplicate raw targets, assigning providers.

    Order of first appearance is preserved for deterministic output.
    """
    seen: set[str] = set()
    targets: list[Target] = []
    for raw in raw_targets:
        raw = (raw or "").strip()
        if not raw:
            continue
        if "://" not in raw:
            raw_url = "https://" + raw
        else:
            raw_url = raw
        provider = find_provider(raw_url)
        normalized = provider.normalize(raw_url) if provider else raw_url
        if normalized in seen:
            continue
        seen.add(normalized)
        from urllib.parse import urlsplit

        host = (urlsplit(normalized).hostname or "").lower()
        targets.append(
            Target(
                raw=raw,
                url=normalized,
                host=host,
                provider=provider.name if provider else None,
            )
        )
    return targets


class Scanner:
    def __init__(
        self,
        config: ScanConfig | None = None,
        scope: Scope | None = None,
        http_client: SafeHTTPClient | None = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.config.validate()
        self.scope = scope
        self.detection = DetectionEngine()
        self.soft404 = Soft404Detector()
        self._cancel = threading.Event()
        if http_client is not None:
            self.http = http_client
        else:
            guard = SSRFGuard(allow_private=self.config.allow_private)
            limiter = RateLimiter(
                global_rate=self.config.global_rate,
                per_host_rate=self.config.per_host_rate,
            )
            self.http = SafeHTTPClient(
                guard=guard,
                rate_limiter=limiter,
                timeout=self.config.timeout,
                max_redirects=self.config.max_redirects,
                max_bytes=self.config.max_bytes,
                retries=self.config.retries,
                user_agent=self.config.user_agent,
            )

    def cancel(self) -> None:
        self._cancel.set()

    # -- scope ----------------------------------------------------------
    def _scope_result(self, target: Target) -> ScopeResult:
        if self.scope is None:
            return ScopeResult(status=ScopeStatus.UNKNOWN, reason="no scope provided")
        return classify_target(target.url, self.scope)

    def _should_scan(self, scope_result: ScopeResult) -> bool:
        if self.scope is None:
            return True  # no scope supplied -> user is responsible for input
        if not self.config.enforce_scope:
            return True
        return scope_result.status == ScopeStatus.IN_SCOPE

    # -- soft 404 -------------------------------------------------------
    def _soft404_catch_all(self, target: Target, signals: ProviderSignals) -> bool | None:
        if not self.config.enable_soft404:
            return None
        if signals.http_status not in _SOFT404_STATUSES:
            return None
        if signals.state not in (STATE_PRESENT, STATE_MISSING):
            return None
        try:
            control = self.http.get(random_control_url(target.url))
        except Exception as exc:  # noqa: BLE001 - soft404 is best-effort
            _log.debug("soft404 control failed for %s: %s", sanitize(target.url), sanitize(exc))
            return None
        result = self.soft404.analyze(
            signals.http_status or 0,
            signals.body_sample,
            control.status_code,
            control.text[:4096],
        )
        return result.is_catch_all

    # -- single target --------------------------------------------------
    def scan_target(self, target: Target) -> Finding:
        started = time.monotonic()
        scope_result = self._scope_result(target)
        finding = Finding(target=target, provider=target.provider, scope=scope_result)

        if self.config.dry_run:
            finding.verdict = Verdict.UNKNOWN
            finding.research_notes.append("dry-run: no request issued")
            finding.evidence.notes.append("dry-run")
            finding.duration_ms = 0
            return finding

        if not self._should_scan(scope_result):
            finding.verdict = Verdict.UNKNOWN
            finding.research_notes.append(f"skipped: scope status {scope_result.status.value}")
            finding.duration_ms = 0
            return finding

        provider: Provider | None = find_provider(target.url)
        if provider is None:
            finding.verdict = Verdict.UNKNOWN
            finding.research_notes.append("no provider handles this host")
            finding.duration_ms = int((time.monotonic() - started) * 1000)
            return finding

        ctx = ProviderContext(target=target, http=self.http)
        signals = provider.evaluate(ctx)
        soft404 = self._soft404_catch_all(target, signals)
        classification = self.detection.classify(signals, soft404_catch_all=soft404)
        evidence: Evidence = self.detection.build_evidence(signals, classification, soft404)

        finding.provider = signals.provider
        finding.verdict = classification.verdict
        finding.severity = classification.severity
        finding.confidence = classification.confidence
        finding.evidence = evidence
        if signals.error:
            finding.errors.append(signals.error)
        finding.duration_ms = int((time.monotonic() - started) * 1000)
        return finding

    # -- batch ----------------------------------------------------------
    def scan(self, raw_targets: Iterable[str]) -> list[Finding]:
        targets = prepare_targets(raw_targets)
        results: dict[int, Finding] = {}
        self._cancel.clear()

        def work(index: int, target: Target) -> tuple[int, Finding]:
            if self._cancel.is_set():
                cancelled = Finding(
                    target=target,
                    provider=target.provider,
                    scope=self._scope_result(target),
                )
                cancelled.research_notes.append("cancelled before execution")
                return index, cancelled
            return index, self.scan_target(target)

        try:
            with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
                futures = [pool.submit(work, i, t) for i, t in enumerate(targets)]
                try:
                    for future in as_completed(futures):
                        index, finding = future.result()
                        results[index] = finding
                except KeyboardInterrupt:
                    _log.warning("cancellation requested; stopping scan")
                    self._cancel.set()
                    for f in futures:
                        f.cancel()
                    raise
        except KeyboardInterrupt:
            pass

        return [results[i] for i in sorted(results)]

"""Detection engine + soft-404 tests, with a focus on false positives."""

from __future__ import annotations

from blhawk.core.models import Reclaimability, Severity, Verdict
from blhawk.core.soft404 import Soft404Detector, body_similarity, random_control_url
from blhawk.detection.engine import DetectionEngine
from blhawk.providers.base import (
    STATE_BLOCKED,
    STATE_MISSING,
    STATE_PRESENT,
    STATE_UNKNOWN,
    ProviderSignals,
)


def sig(state, **kw):
    return ProviderSignals(provider="test", state=state, **kw)


engine = DetectionEngine()


# -- verdict mapping --------------------------------------------------------
def test_present_is_not_vulnerable():
    c = engine.classify(sig(STATE_PRESENT))
    assert c.verdict == Verdict.NOT_VULNERABLE


def test_missing_impossible_reclaim_is_dead_resource_only():
    c = engine.classify(sig(STATE_MISSING, reclaimability=Reclaimability.IMPOSSIBLE))
    assert c.verdict == Verdict.DEAD_RESOURCE
    # A 404 on a non-reclaimable name must never be a takeover.
    assert c.verdict.rank < Verdict.LIKELY_TAKEOVER.rank


def test_missing_possible_reclaim_is_potentially_reclaimable():
    c = engine.classify(sig(STATE_MISSING, reclaimability=Reclaimability.POSSIBLE))
    assert c.verdict == Verdict.POTENTIALLY_RECLAIMABLE


def test_missing_likely_reclaim_tops_out_at_unconfirmed():
    c = engine.classify(sig(STATE_MISSING, reclaimability=Reclaimability.LIKELY))
    # Passive detection must never claim confirmed takeover.
    assert c.verdict == Verdict.RECLAIMABILITY_UNCONFIRMED
    assert c.verdict.rank < Verdict.CONFIRMED_BY_SAFE_VERIFICATION.rank


def test_missing_unknown_reclaim_stays_dead_resource():
    c = engine.classify(sig(STATE_MISSING, reclaimability=Reclaimability.UNKNOWN))
    assert c.verdict == Verdict.DEAD_RESOURCE


# -- false positive guards --------------------------------------------------
def test_blocked_403_is_unknown_not_vulnerable():
    c = engine.classify(sig(STATE_BLOCKED, http_status=403))
    assert c.verdict == Verdict.UNKNOWN


def test_transient_5xx_is_unknown():
    c = engine.classify(sig(STATE_UNKNOWN, http_status=503))
    assert c.verdict == Verdict.UNKNOWN


def test_soft404_catchall_makes_present_unknown():
    c = engine.classify(sig(STATE_PRESENT, http_status=200), soft404_catch_all=True)
    assert c.verdict == Verdict.UNKNOWN


def test_soft404_catchall_downgrades_body_inferred_missing():
    c = engine.classify(
        sig(STATE_MISSING, http_status=200, reclaimability=Reclaimability.POSSIBLE),
        soft404_catch_all=True,
    )
    assert c.verdict == Verdict.UNKNOWN


def test_soft404_catchall_does_not_downgrade_hard_404():
    c = engine.classify(
        sig(STATE_MISSING, http_status=404, reclaimability=Reclaimability.POSSIBLE),
        soft404_catch_all=True,
    )
    assert c.verdict == Verdict.POTENTIALLY_RECLAIMABLE


def test_severity_capped_by_reclaimability():
    # Provider claims HIGH severity but impossible reclaim caps it low.
    c = engine.classify(
        sig(STATE_MISSING, reclaimability=Reclaimability.IMPOSSIBLE, severity=Severity.HIGH)
    )
    assert c.severity in (Severity.INFO, Severity.LOW)


# -- soft404 detector ------------------------------------------------------
def test_soft404_detector_flags_catchall():
    det = Soft404Detector()
    page = "<html><body>Welcome generic page</body></html>"
    res = det.analyze(200, page, 200, page)
    assert res.is_catch_all is True


def test_soft404_detector_distinct_pages_not_catchall():
    det = Soft404Detector()
    res = det.analyze(200, "<html>real profile of alice</html>", 404, "<html>not found</html>")
    assert res.is_catch_all is False


def test_body_similarity_ignores_digits():
    assert body_similarity("user 123 profile", "user 456 profile") > 0.95


def test_random_control_url_is_sibling():
    url = random_control_url("https://example.com/users/alice")
    assert url.startswith("https://example.com/users/")
    assert "blhawk-nonexistent-" in url


def test_evidence_built_from_signals():
    s = sig(
        STATE_MISSING,
        http_status=404,
        reclaimability=Reclaimability.POSSIBLE,
        final_url="https://x/y",
        signals=["http-status=404"],
    )
    c = engine.classify(s)
    ev = engine.build_evidence(s, c)
    assert ev.http_status == 404
    assert ev.resource_state == STATE_MISSING
    assert "http-status=404" in ev.signals

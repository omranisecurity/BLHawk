"""Rate limiter tests using a virtual clock (no real sleeping)."""
from __future__ import annotations

import pytest

from blhawk.core.rate_limiter import RateLimiter, TokenBucket


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def time(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


def test_token_bucket_allows_burst_up_to_capacity():
    clock = FakeClock()
    bucket = TokenBucket(rate=1.0, capacity=3.0, clock=clock.time, sleep=clock.sleep)
    assert bucket.acquire() == 0.0
    assert bucket.acquire() == 0.0
    assert bucket.acquire() == 0.0


def test_token_bucket_throttles_after_capacity():
    clock = FakeClock()
    bucket = TokenBucket(rate=2.0, capacity=1.0, clock=clock.time, sleep=clock.sleep)
    assert bucket.acquire() == 0.0
    waited = bucket.acquire()
    assert waited == pytest.approx(0.5, rel=1e-3)


def test_token_bucket_refills_over_time():
    clock = FakeClock()
    bucket = TokenBucket(rate=1.0, capacity=1.0, clock=clock.time, sleep=clock.sleep)
    bucket.acquire()
    clock.t += 1.0  # one token refilled
    assert bucket.acquire() == 0.0


def test_rate_limiter_combines_global_and_per_host():
    clock = FakeClock()
    limiter = RateLimiter(
        global_rate=100.0,
        per_host_rate=1.0,
        clock=clock.time,
        sleep=clock.sleep,
    )
    assert limiter.acquire("a.example") == 0.0
    waited = limiter.acquire("a.example")
    assert waited > 0.0
    # A different host has its own bucket and is not throttled yet.
    assert limiter.acquire("b.example") == 0.0


def test_invalid_rate_rejected():
    with pytest.raises(ValueError):
        TokenBucket(rate=0)

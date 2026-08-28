"""Token-bucket rate limiting (global + per-host).

The default configuration is deliberately conservative so BLHawk behaves
politely against research targets. Users may raise the limits explicitly.
"""

from __future__ import annotations

import threading
import time
from typing import Callable


class TokenBucket:
    """A thread-safe token bucket."""

    def __init__(
        self,
        rate: float,
        capacity: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else max(1.0, rate))
        self._tokens = self.capacity
        self._clock = clock
        self._sleep = sleep
        self._last = clock()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._last = now

    def acquire(self, tokens: float = 1.0) -> float:
        """Block until ``tokens`` are available. Returns seconds waited."""
        waited = 0.0
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return waited
                deficit = tokens - self._tokens
                delay = deficit / self.rate
            self._sleep(delay)
            waited += delay


class RateLimiter:
    """Combines a global bucket with per-host buckets."""

    def __init__(
        self,
        global_rate: float = 5.0,
        per_host_rate: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._clock = clock
        self._sleep = sleep
        self._global = TokenBucket(global_rate, clock=clock, sleep=sleep)
        self._per_host_rate = per_host_rate
        self._hosts: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def _host_bucket(self, host: str) -> TokenBucket:
        with self._lock:
            bucket = self._hosts.get(host)
            if bucket is None:
                bucket = TokenBucket(self._per_host_rate, clock=self._clock, sleep=self._sleep)
                self._hosts[host] = bucket
            return bucket

    def acquire(self, host: str) -> float:
        waited = self._global.acquire()
        if host:
            waited += self._host_bucket(host).acquire()
        return waited

"""Scan configuration.

Defaults are intentionally conservative ("safe research behavior first"):
low concurrency, gentle rate limits, SSRF guard enabled, scope enforced.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScanConfig:
    threads: int = 5
    global_rate: float = 5.0
    per_host_rate: float = 2.0
    timeout: float = 15.0
    max_redirects: int = 5
    max_bytes: int = 2_000_000
    retries: int = 2
    user_agent: str = "BLHawk/1.0 (+https://github.com/omranisecurity/BLHawk)"

    #: Disable the SSRF guard (controlled-testing mode only).
    allow_private: bool = False
    #: Perform the extra soft-404 control request.
    enable_soft404: bool = True
    #: Show what would be tested without issuing security-testing requests.
    dry_run: bool = False
    #: Only scan IN_SCOPE targets when a scope is provided.
    enforce_scope: bool = True

    def validate(self) -> None:
        if self.threads < 1:
            raise ValueError("threads must be >= 1")
        if self.global_rate <= 0 or self.per_host_rate <= 0:
            raise ValueError("rate limits must be > 0")
        if self.timeout <= 0:
            raise ValueError("timeout must be > 0")

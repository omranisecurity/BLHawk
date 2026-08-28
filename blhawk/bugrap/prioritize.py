"""Program prioritization for research suitability.

Scoring balances coverage (in-scope assets, wildcards, provider support) with
practicality (freshness, restrictions). It deliberately does not optimize for
bounty size alone.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..providers.registry import get_providers
from .models import Program


@dataclass
class ScoredProgram:
    program: Program
    score: float
    reasons: list[str]


def _provider_support(program: Program, provider_hosts: set[str]) -> int:
    supported = 0
    for asset in program.in_scope_assets:
        host = asset.asset.lower().lstrip("*.")
        if any(host == h or host.endswith("." + h) for h in provider_hosts):
            supported += 1
    return supported


def score_program(program: Program, provider_hosts: set[str] | None = None) -> ScoredProgram:
    if provider_hosts is None:
        provider_hosts = _all_provider_hosts()
    reasons: list[str] = []
    score = 0.0

    domains = program.in_scope_domain_count()
    score += min(domains, 20) * 1.0
    reasons.append(f"in-scope assets: {domains}")

    if program.has_wildcard():
        score += 5.0
        reasons.append("wildcard scope (+5)")

    support = _provider_support(program, provider_hosts)
    if support:
        score += support * 2.0
        reasons.append(f"provider-supported assets: {support} (+{support * 2})")

    if program.bounty_range:
        score += 2.0
        reasons.append("bounty published (+2)")

    if program.requires_manual():
        score -= 5.0
        reasons.append("manual testing required (-5)")

    if program.scope_last_checked:
        score += 1.0
        reasons.append("scope freshness recorded (+1)")

    return ScoredProgram(program=program, score=round(score, 2), reasons=reasons)


def prioritize(
    programs: list[Program], provider_hosts: set[str] | None = None
) -> list[ScoredProgram]:
    if provider_hosts is None:
        provider_hosts = _all_provider_hosts()
    scored = [score_program(p, provider_hosts) for p in programs]
    return sorted(scored, key=lambda s: (-s.score, s.program.name.lower()))


def _all_provider_hosts() -> set[str]:
    hosts: set[str] = set()
    for provider in get_providers():
        hosts.update(h.lower() for h in provider.hosts)
        hosts.update(s.lower().lstrip(".") for s in provider.host_suffixes)
    return hosts

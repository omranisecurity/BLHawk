"""Hostname normalization and matching primitives.

Correct, defensive hostname handling is the crux of scope safety: a wildcard
like ``*.example.com`` must never accidentally match ``example.com.evil.com``.
"""
from __future__ import annotations

import ipaddress


def normalize_host(host: str) -> str:
    """Return a normalized ASCII hostname.

    Lowercases, strips a trailing dot, removes brackets around IPv6 literals,
    and converts IDN/Unicode labels to punycode. Returns ``""`` for empty
    input.
    """
    if not host:
        return ""
    host = host.strip().strip("[]").rstrip(".").lower()
    if not host:
        return ""
    # IP literals are returned as-is (already ASCII).
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def host_matches_exact(host: str, domain: str) -> bool:
    return normalize_host(host) == normalize_host(domain)


def host_in_wildcard(host: str, base: str) -> bool:
    """True if ``host`` is ``base`` or a subdomain of ``base``.

    ``base`` is the domain part of a ``*.base`` rule. This deliberately
    matches the apex and any subdomain while rejecting look-alikes such as
    ``base.evil.com`` or ``evil-base``.
    """
    h = normalize_host(host)
    b = normalize_host(base)
    if not h or not b:
        return False
    return h == b or h.endswith("." + b)


def ip_in_cidr(host: str, cidr: str) -> bool:
    try:
        addr = ipaddress.ip_address(normalize_host(host))
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return addr.version == network.version and addr in network

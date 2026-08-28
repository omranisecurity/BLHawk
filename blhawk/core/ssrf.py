"""SSRF protection.

Every outbound request target (including each redirect hop) is validated
here. By default BLHawk refuses to connect to private, loopback, link-local,
reserved, or cloud-metadata addresses so that it can never be turned into an
SSRF primitive. Users may opt into an explicit controlled-testing mode.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field

from .errors import SSRFBlockedError

# Address ranges that are never safe to reach from an internet scanner.
_BLOCKED_NETWORKS: list[ipaddress._BaseNetwork] = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # unique local
    ipaddress.ip_network("fe80::/10"),  # link-local
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped IPv6
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IMDS over IPv6
]

# Hostnames that must never be resolved/allowed regardless of DNS answers.
_BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
}

ALLOWED_SCHEMES = {"http", "https"}


@dataclass
class SSRFGuard:
    """Validates hostnames/IPs against the blocklist.

    When ``allow_private`` is True the guard is disabled (controlled-testing
    mode). ``extra_blocked_hosts`` lets callers add program-specific
    exclusions.
    """

    allow_private: bool = False
    extra_blocked_hosts: set = field(default_factory=set)

    def is_ip_blocked(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # not a parseable IP -> refuse
        if addr.is_unspecified or addr.is_loopback or addr.is_link_local:
            return True
        if addr.is_multicast or addr.is_reserved:
            return True
        for net in _BLOCKED_NETWORKS:
            if addr.version == net.version and addr in net:
                return True
        return False

    def resolve(self, host: str) -> list[str]:
        """Resolve ``host`` to a list of IP strings (may raise socket.gaierror)."""
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips: list[str] = []
        for info in infos:
            sockaddr = info[4]
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
        return ips

    def check_host(self, host: str) -> tuple[bool, str]:
        """Return (allowed, reason). Never raises."""
        if self.allow_private:
            return True, "ssrf-guard-disabled"
        if not host:
            return False, "empty host"
        lowered = host.lower().rstrip(".")
        if lowered in _BLOCKED_HOSTNAMES or lowered in self.extra_blocked_hosts:
            return False, f"blocked hostname: {lowered}"
        # A bare IP literal in the host: validate directly.
        try:
            ipaddress.ip_address(lowered.strip("[]"))
            if self.is_ip_blocked(lowered.strip("[]")):
                return False, f"blocked IP literal: {lowered}"
            return True, "ip literal allowed"
        except ValueError:
            pass
        # Hostname: resolve and validate every answer.
        try:
            ips = self.resolve(lowered)
        except socket.gaierror as exc:
            return False, f"dns resolution failed: {exc}"
        if not ips:
            return False, "no DNS answers"
        for ip in ips:
            if self.is_ip_blocked(ip):
                return False, f"resolves to blocked address {ip}"
        return True, "ok"

    def enforce(self, host: str) -> None:
        """Raise :class:`SSRFBlockedError` if ``host`` is not allowed."""
        allowed, reason = self.check_host(host)
        if not allowed:
            raise SSRFBlockedError(f"{host}: {reason}")

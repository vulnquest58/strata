"""Wildcard DNS base detection.

Ported concept from echoforge's resolver/pool.go wildcard step (main.go Layer 2):
before brute-forcing, probe canary labels; if they resolve, record the wildcard
IP set so engine results whose addresses match it are filtered instead of
reported as real hosts.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from strata.core.dns.resolver import NxDomain, Resolver

CANARY_PREFIX = "strata-wildcard-canary"


@dataclass(frozen=True)
class WildcardBase:
    domain: str
    ips: tuple[str, ...]

    def matches(self, ips: tuple[str, ...]) -> bool:
        """True when every resolved address is one of the wildcard addresses."""
        return bool(ips) and all(ip in self.ips for ip in ips)


def canary_labels(domain: str, n: int = 2) -> tuple[str, ...]:
    """Deterministic canary labels derived from the domain (stable per target)."""
    digest = hashlib.sha256(domain.encode()).hexdigest()
    return tuple(f"{CANARY_PREFIX}-{digest[:10]}-{i}.{domain}" for i in range(n))


async def detect_wildcard(resolver: Resolver, domain: str, n: int = 2) -> WildcardBase | None:
    """Return the wildcard base for `domain`, or None if canaries don't resolve."""
    ips: set[str] = set()
    for label in canary_labels(domain, n):
        host = await resolver.resolve(label)
        if host is None:
            # any non-resolving canary means no wildcard base
            return None
        ips.update(host.ips)
    if not ips:
        return None
    return WildcardBase(domain=domain, ips=tuple(sorted(ips)))


def is_wildcard_hit(base: WildcardBase | None, ips: tuple[str, ...]) -> bool:
    if base is None:
        return False
    try:
        return base.matches(ips)
    except NxDomain:
        return False

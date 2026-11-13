"""Async DNS resolution with an injectable transport.

The transport is the only network seam: every engine above this layer
(wildcard detection, brute force, verification) goes through Resolver,
which goes through a DnsTransport. Tests inject a stub; production uses
dnspython with resolver rotation (ported from dnsphantom's ResolverPool).
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol


class DnsError(Exception):
    """Base class for DNS failures."""


class NxDomain(DnsError):
    """The queried name does not exist."""


class NoAnswer(DnsError):
    """The name exists but has no records of the requested type."""


class DnsTransport(Protocol):
    async def query(self, host: str, rtype: str) -> tuple[str, ...]:
        """Return record values (trailing dot stripped) or raise DnsError."""
        ...


@dataclass(frozen=True)
class ResolvedHost:
    host: str
    a: tuple[str, ...]
    aaaa: tuple[str, ...]
    cname: str | None

    @property
    def ips(self) -> tuple[str, ...]:
        return self.a + self.aaaa


class Resolver:
    """High-level resolver: parallel A/AAAA/CNAME resolution over a transport."""

    def __init__(self, transport: DnsTransport):
        self._transport = transport

    async def resolve(self, host: str) -> ResolvedHost | None:
        """Resolve a host, or return None if the name does not exist."""
        try:
            a, aaaa, cnames = await asyncio.gather(
                self._safe_query(host, "A"),
                self._safe_query(host, "AAAA"),
                self._safe_query(host, "CNAME"),
            )
        except NxDomain:
            return None
        host = ResolvedHost(
            host=host,
            a=a,
            aaaa=aaaa,
            cname=cnames[0] if cnames else None,
        )
        # A name that answers no A/AAAA/CNAME data is not a live subdomain.
        # Some resolvers return empty NOERROR instead of NXDOMAIN for junk
        # names; without this guard those pollute the candidate set.
        if not host.a and not host.aaaa and host.cname is None:
            return None
        return host

    async def cname_chain(self, host: str, limit: int = 6) -> tuple[str, ...]:
        """Follow CNAME records iteratively (ported from origintrace probe.cname_chain)."""
        chain: list[str] = []
        current = host
        for _ in range(limit):
            try:
                values = await self._safe_query(current, "CNAME")
            except (NxDomain, NoAnswer):
                break
            if not values:
                break
            current = values[0]
            chain.append(current)
        return tuple(chain)

    async def _safe_query(self, host: str, rtype: str) -> tuple[str, ...]:
        """Query one record type, normalizing NoAnswer/NxDomain into empties.

        NxDomain on the A query means the name itself is absent (re-raised so
        resolve() can drop the host). For AAAA/CNAME an NxDomain is treated as
        a miss on that type: existence is defined by the A-side answer, and
        stub transports raise NxDomain for any unlisted entry.
        """
        try:
            return await self._transport.query(host, rtype)
        except NoAnswer:
            return ()
        except NxDomain:
            if rtype != "A":
                return ()
            raise


class DnspythonTransport:
    """Live transport: dnspython with resolver rotation and retries.

    Ported from dnsphantom core/resolver.py ResolverPool: default public
    resolvers, rotate on each retry, 3 attempts, NXDOMAIN short-circuits.
    """

    DEFAULT_RESOLVERS: Sequence[str] = (
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "9.9.9.9",
        "208.67.222.222",
    )

    def __init__(
        self,
        resolvers: Sequence[str] | None = None,
        timeout: float = 5.0,
        max_retries: int = 3,
    ):
        import dns.asyncresolver
        import dns.exception
        import dns.resolver

        self._dns_asyncresolver = dns.asyncresolver
        self._dns_resolver = dns.resolver
        self._dns_exception = dns.exception
        self._resolvers = tuple(resolvers or self.DEFAULT_RESOLVERS)
        self._timeout = timeout
        self._max_retries = max_retries
        self._idx = 0

    def _next_resolver(self):
        nameserver = self._resolvers[self._idx % len(self._resolvers)]
        self._idx += 1
        resolver = self._dns_asyncresolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = self._timeout
        resolver.lifetime = self._timeout
        return resolver

    async def query(self, host: str, rtype: str) -> tuple[str, ...]:
        last_exc: Exception | None = None
        for _ in range(self._max_retries):
            resolver = self._next_resolver()
            try:
                answer = await asyncio.wait_for(
                    resolver.resolve(host, rtype), timeout=self._timeout
                )
                # dnspython yields rdata objects (no .rstrip); CNAME rdata
                # renders as "target." with a trailing dot.
                texts = [
                    (r if isinstance(r, str) else r.to_text()).rstrip(".") for r in answer
                ]
                return tuple(texts)
            except self._dns_resolver.NXDOMAIN:
                raise NxDomain(host) from None
            except self._dns_resolver.NoAnswer:
                raise NoAnswer(host) from None
            except (
                TimeoutError,
                self._dns_resolver.NoNameservers,
                self._dns_resolver.LifetimeTimeout,
                self._dns_exception.DNSException,
            ) as exc:
                last_exc = exc
        raise DnsError(f"{host} {rtype}: {last_exc}") from last_exc

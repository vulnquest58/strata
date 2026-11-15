"""Subdomain takeover verification (P1).

A dangling CNAME — an alias pointing at a third-party service record that
no longer resolves — is the classic takeover precondition. But *dangling*
is only half the evidence: exploitability depends on the service returning
its unclaimed-resource error page at the subdomain.

Strata's claim ladder is strict and honest:

1. DNS evidence: CNAME chain resolves to a third-party service whose
   target has no A/AAAA answer  ->  `dangling` precondition met.
2. Fingerprint evidence: the service's own error page (NoSuchBucket,
   GitHub's "no site here", Heroku's "No such app", ...) is observed over
   HTTP at that subdomain  ->  takeover-confirmed claim, `verified`.
3. Neither marker nor known service  ->  surfaced as a decommission-risk
   candidate for manual review. We never claim exploitability without the
   service fingerprint, and we never suppress a dangling alias.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from strata.core.content.fetch import FetchResponse, HttpTransport
from strata.core.dns.resolver import DnsError, Resolver
from strata.core.policy.scope import ScopePolicy
from strata.core.schema.models import (
    Confidence,
    ConfidenceMethod,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)


@dataclass(frozen=True)
class TakeoverService:
    """A third-party hosting service with a known unclaimed-resource page."""

    suffix: str
    provider: str
    markers: tuple[str, ...]           # lowercase body markers; any match confirms
    confidence: float                  # belief in exploitable takeover on match
    dns_only: bool = False             # service with no HTTP error page to match


TAKEOVER_SERVICES: tuple[TakeoverService, ...] = (
    TakeoverService(
        "s3.amazonaws.com", "AWS S3", ("nosuchbucket",), 85.0
    ),
    TakeoverService(
        "cloudfront.net", "AWS CloudFront",
        ("the request could not be satisfied",), 75.0
    ),
    TakeoverService(
        "github.io", "GitHub Pages",
        ("there isn't a github pages site here.",), 85.0
    ),
    TakeoverService(
        "herokuapp.com", "Heroku",
        ("no such app", "there's nothing here, yet."), 85.0
    ),
    TakeoverService(
        "herokudns.com", "Heroku SSL", (), 50.0, dns_only=True
    ),
    TakeoverService(
        "azurewebsites.net", "Azure App Service",
        ("404 web site not found.",), 80.0
    ),
    TakeoverService(
        "myshopify.com", "Shopify",
        ("sorry, this shop is currently unavailable.",), 80.0
    ),
    TakeoverService(
        "zendesk.com", "Zendesk", ("help center closed",), 70.0
    ),
    TakeoverService(
        "fastly.net", "Fastly",
        ("fastly error: unknown domain:",), 80.0
    ),
    TakeoverService(
        "ghost.io", "Ghost(Pro)",
        ("the thing you were looking for is no longer here, or never was",), 80.0
    ),
    TakeoverService(
        "pantheon.io", "Pantheon",
        ("the gods are wise, but do not know of the site which you seek.",), 65.0
    ),
    TakeoverService(
        "surge.sh", "Surge.sh", ("project not found",), 80.0
    ),
    TakeoverService(
        "bitbucket.io", "Bitbucket", ("repository not found",), 75.0
    ),
    TakeoverService(
        "webflow.io", "Webflow",
        ("the page you are looking for doesn't exist or has been moved.",), 60.0
    ),
)


def match_service(cname_target: str) -> TakeoverService | None:
    target = cname_target.lower().rstrip(".")
    for service in TAKEOVER_SERVICES:
        if target == service.suffix or target.endswith(f".{service.suffix}"):
            return service
    return None


@dataclass
class TakeoverStats:
    checked: int = 0
    no_alias: int = 0
    not_dangling: int = 0
    dangling: int = 0
    confirmed: int = 0
    candidates: int = 0
    errors: int = 0


@dataclass
class TakeoverResult:
    findings: list[UnifiedFinding] = field(default_factory=list)
    stats: TakeoverStats = field(default_factory=TakeoverStats)


class TakeoverEngine:
    """Verify dangling CNAMEs and fingerprint unclaimed service pages."""

    def __init__(
        self,
        resolver: Resolver,
        transport: HttpTransport,
        *,
        timeout: float = 10.0,
        max_hosts: int = 100,
    ):
        self._resolver = resolver
        self._transport = transport
        self._timeout = timeout
        self._max_hosts = max_hosts
        self._stats = TakeoverStats()

    async def run(
        self,
        findings: Iterable[UnifiedFinding],
        *,
        policy: ScopePolicy | None = None,
    ) -> TakeoverResult:
        result = TakeoverResult()
        self._stats = result.stats
        hosts = self._hosts(findings, policy)
        for host in hosts:
            result.stats.checked += 1
            finding = await self._assess_host(host)
            if finding is None:
                continue
            result.findings.append(finding)
            if finding.status is FindingStatus.VERIFIED:
                result.stats.confirmed += 1
            else:
                result.stats.candidates += 1
        return result

    def _hosts(
        self,
        findings: Iterable[UnifiedFinding],
        policy: ScopePolicy | None,
    ) -> list[str]:
        hosts: list[str] = []
        seen: set[str] = set()
        for finding in findings:
            if finding.kind not in (FindingClass.SUBDOMAIN, FindingClass.LIVE_HOST):
                continue
            if finding.status not in (FindingStatus.VERIFIED, FindingStatus.CANDIDATE):
                continue
            if policy is not None and not policy.allows_host(finding.asset_value):
                continue
            value = finding.asset_value.strip()
            host = value.replace("https://", "").replace("http://", "").rstrip("/").lower()
            if not host or host in seen:
                continue
            seen.add(host)
            hosts.append(host)
            if len(hosts) >= self._max_hosts:
                break
        return hosts

    async def _assess_host(self, host: str) -> UnifiedFinding | None:
        try:
            chain = await self._resolver.cname_chain(host)
        except DnsError:
            self._stats.errors += 1
            return None
        if not chain:
            self._stats.no_alias += 1
            return None
        target = chain[-1].lower()
        try:
            resolved = await self._resolver.resolve(target)
        except DnsError:
            self._stats.errors += 1
            return None
        if resolved is not None and resolved.ips:
            self._stats.not_dangling += 1
            return None  # alias is live: no takeover precondition
        self._stats.dangling += 1
        return await self._fingerprint(host, chain)

    async def _fingerprint(self, host: str, chain: tuple[str, ...]):
        target = chain[-1]
        service = match_service(target)
        url = f"https://{host}"
        try:
            response: FetchResponse = await self._transport.get(
                url, timeout=self._timeout, max_bytes=100_000
            )
        except Exception:
            self._stats.errors += 1
            return self._candidate_finding(
                host, chain, service,
                "dangling CNAME; HTTP fingerprint failed (manual review)",
            )
        if service is None:
            return self._candidate_finding(
                host, chain, None,
                f"dangling CNAME to unknown third-party {target}; "
                "decommission risk (manual review)",
            )
        if service.dns_only:
            return self._candidate_finding(
                host, chain, service,
                f"dangling CNAME to {service.provider} DNS-only endpoint; "
                "manual verification required",
            )
        body = response.body.decode("utf-8", errors="replace").lower()
        matched = next((m for m in service.markers if m in body), None)
        if matched is None:
            return self._candidate_finding(
                host, chain, service,
                f"dangling CNAME to {service.provider} but error page does not "
                "match the known unclaimed-resource fingerprint",
            )
        return self._confirmed_finding(host, chain, service, matched, response.status)

    def _finding(
        self,
        host: str,
        chain: tuple[str, ...],
        observation: str,
        *,
        status: FindingStatus,
        confidence: float,
        strength: EvidenceStrength,
        meta_extra: dict[str, object],
    ) -> UnifiedFinding:
        digest = hashlib.sha256(f"takeover|{host}".encode()).hexdigest()[:16]
        meta = {
            "cnames": list(chain),
            "dangling": True,
            "takeover_confirmed": status is FindingStatus.VERIFIED,
            **meta_extra,
        }
        return UnifiedFinding(
            finding_id=f"takeover:{digest}",
            run_id="takeover",
            kind=FindingClass.VULN,
            status=status,
            asset_value=f"https://{host}",
            parent=host,
            confidence=Confidence(
                value=confidence,
                method=ConfidenceMethod.BAYESIAN,
                components={"takeover": confidence},
            ),
            evidence=[
                Evidence(
                    engine="takeover",
                    technique="dangling_cname_fingerprint",
                    observation=observation,
                    strength=strength,
                    meta=meta,
                )
            ],
            discovered_at=datetime.now(UTC),
            metadata=meta,
        )

    def _confirmed_finding(
        self,
        host: str,
        chain: tuple[str, ...],
        service: TakeoverService,
        marker: str,
        status_code: int,
    ) -> UnifiedFinding:
        return self._finding(
            host,
            chain,
            f"dangling CNAME to {service.provider} ({chain[-1]}); unclaimed-resource "
            f"page observed (HTTP {status_code}, marker '{marker}')",
            status=FindingStatus.VERIFIED,
            confidence=service.confidence,
            strength=EvidenceStrength.STRONG,
            meta_extra={
                "provider": service.provider,
                "marker": marker,
                "service": service.suffix,
            },
        )

    def _candidate_finding(
        self,
        host: str,
        chain: tuple[str, ...],
        service: TakeoverService | None,
        observation: str,
    ) -> UnifiedFinding:
        provider = service.provider if service else None
        return self._finding(
            host,
            chain,
            observation,
            status=FindingStatus.CANDIDATE,
            confidence=50.0 if service else 35.0,
            strength=EvidenceStrength.WEAK,
            meta_extra={"provider": provider, "manual_review": True},
        )


__all__ = [
    "TAKEOVER_SERVICES",
    "TakeoverEngine",
    "TakeoverResult",
    "TakeoverService",
    "TakeoverStats",
    "match_service",
]

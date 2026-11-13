"""DNS discovery engine: wordlist brute force + echo mutation passes.

Absorbs dnsphantom's subenum (wordlist brute, resolver rotation) and
echoforge's evolution loop (mutate confirmed labels and re-resolve), with
the wildcard-base filtering both originals lacked, origin classification
from core.dns.origin, and UnifiedFinding output with per-host evidence.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from importlib import resources

from strata.core.dns.origin import OriginType, classify_origin
from strata.core.dns.resolver import NxDomain, Resolver
from strata.core.dns.wildcard import WildcardBase, detect_wildcard, is_wildcard_hit
from strata.core.policy.scope import ScopePolicy
from strata.core.schema.models import (
    Confidence,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)
from strata.engines.echoforge import generate_mutations, token_frequencies, tokenize

# echoforge scorer.go weights (deterministic subset)
WEIGHT_DNS_RESOLVES = 25.0
WEIGHT_WORDLIST_HIT = 5.0
WEIGHT_ECHO_RESOLVED = 15.0
WEIGHT_ORIGIN_KNOWN = 10.0
MAX_MUTATIONS_PER_SEED = 20


def load_wordlist(name: str) -> tuple[str, ...]:
    """Load a packaged wordlist (blank lines and # comments stripped)."""
    text = (
        resources.files("strata")
        .joinpath(f"data/wordlists/{name}.txt")
        .read_text(encoding="utf-8")
    )
    lines: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        word = line.strip()
        if not word or word.startswith("#") or word in seen:
            continue
        seen.add(word)
        lines.append(word)
    return tuple(lines)


@dataclass
class DnsRunStats:
    candidates_tested: int = 0
    resolved: int = 0
    wildcard_filtered: int = 0
    mutation_candidates: int = 0
    errors: int = 0
    findings: int = 0


@dataclass
class DnsRunResult:
    domain: str
    findings: list[UnifiedFinding] = field(default_factory=list)
    stats: DnsRunStats = field(default_factory=DnsRunStats)
    wildcard: WildcardBase | None = None


class DnsDiscoveryEngine:
    def __init__(
        self,
        resolver: Resolver,
        policy: ScopePolicy,
        wordlist: str = "base",
        max_concurrency: int = 50,
        mutate: bool = True,
        max_depth: int = 2,
        known: set[str] | None = None,
    ):
        self._resolver = resolver
        self._policy = policy
        self._wordlist = wordlist
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._mutate = mutate
        self._max_depth = max_depth
        self._known = known or set()

    async def run(self, domain: str) -> DnsRunResult:
        if not self._policy.allows_domain(domain):
            raise PermissionError(f"domain {domain} is out of scope")

        result = DnsRunResult(domain=domain)
        result.wildcard = await detect_wildcard(self._resolver, domain)
        words = load_wordlist(self._wordlist)
        candidates = [f"{w}.{domain}" for w in words]

        confirmed: list[UnifiedFinding] = []
        depth = 0
        while candidates and depth < self._max_depth:
            if depth > 0:
                result.stats.mutation_candidates += len(candidates)
            resolved_hosts = await self._resolve_batch(candidates, result, is_echo=depth > 0)
            for host, candidate, is_echo in resolved_hosts:
                finding = self._to_finding(domain, host, candidate, depth, is_echo)
                if finding is None:
                    continue
                result.stats.resolved += 1
                confirmed.append(finding)
            result.stats.findings += len(resolved_hosts)
            depth += 1
            if not self._mutate or depth >= self._max_depth:
                break
            labels = [f.asset_value for f in confirmed]
            freqs = token_frequencies(labels)
            # echoforge gates seeds on token frequency; with a brute-force
            # pass every token is usually unique, so gate at >= 1 and take
            # the top 5 labels by their strongest token frequency
            seeds = [
                label
                for label in sorted(
                    labels,
                    key=lambda lab: max(
                        (freqs.get(t, 0) for t in tokenize(lab)), default=0
                    ),
                    reverse=True,
                )[:5]
                if tokenize(label)
            ]
            candidates = list(
                generate_mutations(seeds, max_per_seed=MAX_MUTATIONS_PER_SEED, domain=domain)
            )
            already = {f.asset_value for f in confirmed}
            candidates = [c for c in candidates if c not in already]
        result.findings = confirmed
        return result

    def _to_finding(
        self,
        domain: str,
        host,
        candidate: str,
        depth: int,
        is_echo: bool,
    ) -> UnifiedFinding | None:
        origin = classify_origin(host.cname, host.ips)
        confidence = WEIGHT_DNS_RESOLVES
        if not is_echo:
            confidence += WEIGHT_WORDLIST_HIT
        else:
            confidence += WEIGHT_ECHO_RESOLVED
        if origin.origin_type is not OriginType.DIRECT:
            confidence += WEIGHT_ORIGIN_KNOWN
        confidence += 8.0 * max(0.0, 1.0 - depth * 0.15)  # echoforge depth bonus
        confidence = round(min(confidence, 100.0), 1)

        meta = {
            "a_records": list(host.a),
            "aaaa_records": list(host.aaaa),
            "cname": host.cname,
            "origin_type": origin.origin_type.value,
            "origin_provider": origin.provider,
            "origin_confidence": origin.confidence,
            "origin_via": origin.via,
            "echo_depth": depth,
        }
        return UnifiedFinding(
            run_id=f"dns:{domain}",
            kind=FindingClass.SUBDOMAIN,
            status=FindingStatus.CANDIDATE,
            asset_value=host.host,
            parent=domain,
            confidence=Confidence(
                value=confidence,
                method="imported",
                components={
                    "dns_resolves": WEIGHT_DNS_RESOLVES,
                    "source_hit": WEIGHT_ECHO_RESOLVED if is_echo else WEIGHT_WORDLIST_HIT,
                    "depth_bonus": round(8.0 * max(0.0, 1.0 - depth * 0.15), 1),
                    "origin_known": (
                        WEIGHT_ORIGIN_KNOWN
                        if origin.origin_type is not OriginType.DIRECT
                        else 0.0
                    ),
                },
            ),
            evidence=[
                Evidence(
                    engine="dns_brute",
                    technique="echo_mutation" if is_echo else "wordlist_a_probe",
                    observation=(
                        f"{host.host} resolves to {len(host.ips)} address(es); "
                        f"origin={origin.origin_type.value}"
                        + (f"/{origin.provider}" if origin.provider else "")
                    ),
                    strength=(
                        EvidenceStrength.CORROBORATED
                        if origin.origin_type in (OriginType.CDN, OriginType.CLOUD, OriginType.PAAS)
                        else EvidenceStrength.WEAK
                    ),
                    meta=meta,
                )
            ],
        )

    async def _resolve_batch(
        self, candidates: list[str], result: DnsRunResult, is_echo: bool = False
    ) -> list[tuple]:
        async def probe(candidate: str):
            if candidate in self._known:
                return None
            result.stats.candidates_tested += 1
            try:
                async with self._semaphore:
                    host = await self._resolver.resolve(candidate)
            except (TimeoutError, NxDomain):
                return None
            if host is None:
                return None
            if is_wildcard_hit(result.wildcard, host.ips):
                result.stats.wildcard_filtered += 1
                return None
            return (host, candidate)

        probes = [probe(candidate) for candidate in candidates]
        outcomes = await asyncio.gather(*probes, return_exceptions=True)
        resolved = []
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                result.stats.errors += 1
                continue
            if outcome is not None:
                resolved.append((outcome[0], outcome[1], is_echo))
        return resolved

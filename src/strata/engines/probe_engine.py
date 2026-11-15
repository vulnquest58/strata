"""Global EIG probe engine: verify the most uncertain claims on the surface.

This is the verification half of the belief engine. `core.schedule` decides
*which* claims to probe (stratified by kind, ranked by expected information
gain); this engine performs the HTTP probes with soft-404 discrimination and
updates each claim's status and confidence provenance.

Every probe stamps ``metadata["prior_confidence"]`` before a status
transition, so the truth ledger records candidate→verified/dead outcomes and
calibration improves every run.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from strata.core.content.fetch import HttpTransport
from strata.core.content.soft404 import (
    Soft404Profile,
    classify_response,
    fetch_baseline,
)
from strata.core.content.urls import host_of
from strata.core.schedule import select_probes
from strata.core.schema.models import (
    Confidence,
    Evidence,
    EvidenceStrength,
    FindingStatus,
    UnifiedFinding,
)

PROBE_MAX_BYTES = 400_000
_MAX_BASELINES = 5


@dataclass
class ProbeRunStats:
    eligible: int = 0
    selected: int = 0
    probed: int = 0
    verified: int = 0
    dead: int = 0
    soft404: int = 0
    baselines: int = 0
    out_of_scope: int = 0
    errors: int = 0
    expected_information_bits: float = 0.0


@dataclass
class ProbeRunResult:
    findings: list[UnifiedFinding] = field(default_factory=list)
    stats: ProbeRunStats = field(default_factory=ProbeRunStats)


def _probe_url(finding: UnifiedFinding) -> str:
    value = finding.asset_value
    if value.startswith(("http://", "https://")):
        return value
    return f"https://{value}"


class ProbeEngine:
    """HTTP-verify candidate claims across the whole surface."""

    def __init__(
        self,
        transport: HttpTransport,
        *,
        max_probe: int = 50,
        concurrency: int = 8,
        timeout: float = 10.0,
        run_id: str = "eig_probe",
    ):
        self._transport = transport
        self._max_probe = max_probe
        self._concurrency = concurrency
        self._timeout = timeout
        self._run_id = run_id

    async def run(
        self,
        findings: list[UnifiedFinding],
        *,
        policy=None,
    ) -> ProbeRunResult:
        result = ProbeRunResult()
        ranked = select_probes(findings, self._max_probe)
        result.stats.eligible = len(findings)
        result.stats.selected = len(ranked)
        if not ranked:
            return result

        semaphore = asyncio.Semaphore(self._concurrency)
        baselines: dict[str, Soft404Profile | None] = {}
        for finding, _ in ranked:
            host = host_of(_probe_url(finding))
            if host in baselines or len(baselines) >= _MAX_BASELINES:
                continue
            baselines[host] = await fetch_baseline(
                _probe_url(finding), self._transport, timeout=self._timeout
            )
            result.stats.baselines += 1

        async def probe(finding: UnifiedFinding, gain: float) -> None:
            url = _probe_url(finding)
            if policy is not None:
                host = host_of(url)
                if host and not policy.allows_host(host):
                    result.stats.out_of_scope += 1
                    return
            async with semaphore:
                try:
                    response = await self._transport.get(
                        url, timeout=self._timeout, max_bytes=PROBE_MAX_BYTES
                    )
                except Exception:
                    result.stats.errors += 1
                    return
            verdict = classify_response(response, baselines.get(host_of(url)))
            result.stats.probed += 1
            result.stats.expected_information_bits = round(
                result.stats.expected_information_bits + gain, 3
            )
            status = response.status
            finding.evidence.append(
                Evidence(
                    engine="eig_probe",
                    technique="http_probe",
                    observation=f"HTTP {status} from {url} ({verdict})",
                    strength=(
                        EvidenceStrength.STRONG
                        if 200 <= status < 400 and verdict == "live"
                        else EvidenceStrength.CORROBORATED
                    ),
                    meta={
                        "status": status,
                        "server": response.headers.get("server", ""),
                        "soft404_verdict": verdict,
                    },
                )
            )
            finding.metadata["probe_status"] = status
            finding.metadata["probe_verdict"] = verdict
            finding.metadata["prior_confidence"] = finding.confidence.value
            if 200 <= status < 400 and verdict == "live":
                finding.status = FindingStatus.VERIFIED
                finding.confidence = Confidence(
                    value=max(finding.confidence.value, 85.0),
                    method=finding.confidence.method,
                    components=dict(finding.confidence.components),
                )
                result.stats.verified += 1
            elif status in (404, 410) or verdict == "soft404":
                finding.status = FindingStatus.DEAD
                result.stats.dead += 1
                if verdict == "soft404":
                    result.stats.soft404 += 1
                    finding.metadata["soft404"] = True
            # "uncertain" keeps the claim at candidate

        await asyncio.gather(*(probe(finding, gain) for finding, gain in ranked))
        result.findings = [finding for finding, _ in ranked]
        return result


__all__ = ["ProbeEngine", "ProbeRunResult", "ProbeRunStats"]

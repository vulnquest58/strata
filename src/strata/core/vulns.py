"""Vulnerability layer: disclosed versions matched against known CVEs.

Strata's rule for vulnerability claims is deliberately strict:

1. The target itself must disclose a software version (Server /
   X-Powered-By headers, meta generator tags).
2. The disclosed version must fall inside a published advisory window
   (`since <= version < fixed`, compared numerically, branch-aware).
3. No version, no claim. We never assert "possibly vulnerable" for a
   technology alone — that is how scanners produce noise nobody reads.

Matches are emitted as `kind=VULN` findings with status `verified` (the
version disclosure is a direct observation) but evidence strength
`corroborated` (the CVE applicability is an inference from a published
window, not a confirmed exploitation).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from strata.core.schema.models import (
    Confidence,
    ConfidenceMethod,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "cve_map.json"

_VERSION_RE = re.compile(r"^(\d+(?:\.\d+){0,3})")
_BASE_CONFIDENCE = 70.0
_PARTIAL_VERSION_CONFIDENCE = 60.0


@dataclass(frozen=True)
class VulnMatch:
    cve: str
    tech: str
    version: str
    severity: str
    summary: str
    confidence: float
    window: tuple[str, str]

    @property
    def observation(self) -> str:
        since, fixed = self.window
        return (
            f"{self.tech} {self.version} in advisory window "
            f"[{since or 'any'}, {fixed}) -> {self.cve} ({self.severity})"
        )


@lru_cache(maxsize=1)
def load_cve_map() -> dict:
    return json.loads(_DATA_PATH.read_text(encoding="utf-8"))


def _parse_version(value: str) -> tuple[int, ...] | None:
    match = _VERSION_RE.match(value.strip())
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None


def _version_lt(left: str, right: str) -> bool | None:
    """Numeric-aware 'left < right'. None when either side is unparseable."""
    a, b = _parse_version(left), _parse_version(right)
    if a is None or b is None:
        return None
    width = max(len(a), len(b))
    a += (0,) * (width - len(a))
    b += (0,) * (width - len(b))
    return a < b


def version_in_window(
    version: str, since: str, fixed: str
) -> bool | None:
    """`since <= version < fixed` with numeric semantics; None if unsure."""
    if fixed:
        below = _version_lt(version, fixed)
        if below is None:
            return None
        if not below:
            return False
    if since:
        above = _version_lt(version, since)
        if above is None:
            return None
        if above:
            return False
    return True


def match_cves(
    tech_stack: list[str],
    versions: dict[str, str],
) -> list[VulnMatch]:
    """Every CVE window crossed by a disclosed version, most severe first."""
    if not versions:
        return []
    catalog = load_cve_map().get("technologies", {})
    matches: list[VulnMatch] = []
    for tech, disclosed in versions.items():
        entries = catalog.get(tech)
        if not entries:
            continue
        for entry in entries:
            since = str(entry.get("since", "0"))
            fixed = str(entry.get("fixed", ""))
            in_window = version_in_window(disclosed, since, fixed)
            if not in_window:
                continue
            partial = _parse_version(disclosed) is None
            matches.append(
                VulnMatch(
                    cve=entry["cve"],
                    tech=tech,
                    version=disclosed,
                    severity=entry.get("severity", "unknown"),
                    summary=entry.get("summary", ""),
                    confidence=(
                        _PARTIAL_VERSION_CONFIDENCE if partial else _BASE_CONFIDENCE
                    ),
                    window=(since, fixed),
                )
            )
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    matches.sort(key=lambda m: (severity_rank.get(m.severity, 4), m.cve))
    return matches


def cve_findings(
    host_finding: UnifiedFinding,
    *,
    run_id: str,
) -> list[UnifiedFinding]:
    """VULN findings derived from a fingerprinted live host's disclosed versions."""
    metadata = host_finding.metadata if isinstance(host_finding.metadata, dict) else {}
    versions = metadata.get("versions")
    if not isinstance(versions, dict) or not versions:
        return []
    tech_stack = metadata.get("tech_stack")
    matches = match_cves(
        tech_stack if isinstance(tech_stack, list) else [], versions
    )
    host = host_finding.asset_value
    findings: list[UnifiedFinding] = []
    for match in matches:
        digest_source = f"vuln|{host}|{match.cve}|{match.tech}".encode()
        digest = hashlib.sha256(digest_source).hexdigest()[:16]
        findings.append(
            UnifiedFinding(
                finding_id=f"vuln:{digest}",
                run_id=run_id,
                kind=FindingClass.VULN,
                status=FindingStatus.VERIFIED,
                asset_value=host,
                parent=host,
                confidence=Confidence(
                    value=match.confidence,
                    method=ConfidenceMethod.BAYESIAN,
                    components={"cve_map": match.confidence},
                ),
                evidence=[
                    Evidence(
                        engine="cve_map",
                        technique="version_match",
                        observation=match.observation,
                        strength=EvidenceStrength.CORROBORATED,
                        meta={
                            "cve": match.cve,
                            "severity": match.severity,
                            "tech": match.tech,
                            "version": match.version,
                            "window": list(match.window),
                            "summary": match.summary,
                        },
                    )
                ],
                metadata={
                    "cve": match.cve,
                    "severity": match.severity,
                    "summary": match.summary,
                    "tech": match.tech,
                    "version": match.version,
                },
            )
        )
    return findings


__all__ = [
    "VulnMatch",
    "cve_findings",
    "load_cve_map",
    "match_cves",
    "version_in_window",
]

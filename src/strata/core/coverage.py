"""Surface coverage estimation via capture-recapture.

Enumeration answers "what did we find?"; coverage estimation answers "how
much is still missing?". Independent discovery sources act as capture passes
over the same surface. When two sources both report n1 and n2 assets and
overlap on m of them, the Chapman-modified Lincoln-Petersen estimator

    N = (n1 + 1)(n2 + 1) / (m + 1) - 1

approximates the true surface size, with variance

    Var = (n1 + 1)(n2 + 1)(n1 - m)(n2 - m) / ((m + 1)^2 (m + 2)).

The pair with the largest overlap carries the most information and is used
for the estimate. Without redundant overlapping sources no estimate is
possible, and the estimator says so instead of inventing one.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from strata.core.reliability import VERIFIER_ENGINES
from strata.core.schema.models import FindingClass, FindingStatus, UnifiedFinding

MIN_OVERLAP = 3
Z_95 = 1.96


@dataclass(frozen=True)
class CoverageEstimate:
    kind: str
    observed: int
    estimate: int
    ci_low: int
    ci_high: int
    source_pair: tuple[str, str] | None
    overlap: int

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "observed": self.observed,
            "estimate": self.estimate,
            "ci_low": self.ci_low,
            "ci_high": self.ci_high,
            "source_pair": list(self.source_pair) if self.source_pair else None,
            "overlap": self.overlap,
        }


def discovery_sources(finding: UnifiedFinding) -> set[str]:
    """Independent capture passes that reported this asset."""
    return {
        evidence.engine
        for evidence in finding.evidence
        if evidence.engine and evidence.engine not in VERIFIER_ENGINES
    }


def _chapman(n1: int, n2: int, m: int) -> tuple[float, float]:
    estimate = (n1 + 1) * (n2 + 1) / (m + 1) - 1
    variance = (
        (n1 + 1) * (n2 + 1) * (n1 - m) * (n2 - m) / ((m + 1) ** 2 * (m + 2))
    )
    sd = math.sqrt(max(variance, 0.0))
    return estimate, sd


def _estimate_for_kind(kind: FindingClass, findings: list[UnifiedFinding]) -> CoverageEstimate:
    observed = len(findings)
    per_source: dict[str, set[int]] = defaultdict(set)
    for index, finding in enumerate(findings):
        for source in discovery_sources(finding):
            per_source[source].add(index)

    names = sorted(per_source)
    best_pair: tuple[str, str, int] | None = None
    best_key: tuple[int, int] = (0, 0)
    for i, s1 in enumerate(names):
        for s2 in names[i + 1:]:
            m = len(per_source[s1] & per_source[s2])
            if m < MIN_OVERLAP:
                continue
            key = (m, len(per_source[s1]) + len(per_source[s2]))
            if key > best_key:
                best_key = key
                best_pair = (s1, s2, m)

    if best_pair is None:
        return CoverageEstimate(
            kind=kind.value,
            observed=observed,
            estimate=observed,
            ci_low=observed,
            ci_high=observed,
            source_pair=None,
            overlap=0,
        )

    s1, s2, m = best_pair
    n1 = len(per_source[s1])
    n2 = len(per_source[s2])
    estimate, sd = _chapman(n1, n2, m)
    estimate_int = int(round(estimate))
    low = max(observed, int(round(estimate - Z_95 * sd)))
    high = max(observed, int(round(estimate + Z_95 * sd)))
    return CoverageEstimate(
        kind=kind.value,
        observed=observed,
        estimate=estimate_int,
        ci_low=low,
        ci_high=high,
        source_pair=(s1, s2),
        overlap=m,
    )


def estimate_coverage(
    findings: Iterable[UnifiedFinding],
) -> dict[str, CoverageEstimate]:
    grouped: dict[FindingClass, list[UnifiedFinding]] = defaultdict(list)
    for finding in findings:
        if finding.status is FindingStatus.DEAD:
            # Refuted claims are not part of the live surface; counting them
            # as a capture pass would shrink the estimate towards a phantom
            # population. Dead is an observation, not a source.
            continue
        grouped[finding.kind].append(finding)
    return {
        kind.value: _estimate_for_kind(kind, members)
        for kind, members in sorted(grouped.items(), key=lambda kv: kv[0].value)
    }


__all__ = [
    "MIN_OVERLAP",
    "CoverageEstimate",
    "discovery_sources",
    "estimate_coverage",
]

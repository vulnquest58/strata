"""Expected-information-gain probe scheduling.

Each HTTP probe of an extraction candidate is treated as a decisive binary
observation: the endpoint verifies (exists) or dies (does not). A probe of a
claim held with probability p therefore fully resolves the claim, and its
expected information gain is the binary entropy H(p). Probing the claims
closest to 0.5 maximises information per request, so within a fixed request
budget the scheduler spends probes where the surface is most uncertain, not
where it is most confident.
"""

from __future__ import annotations

import math
from collections.abc import Iterable

from strata.core.schema.models import UnifiedFinding


def information_gain_bits(probability: float) -> float:
    """Binary entropy H(p) in bits; maximal (1.0) at p = 0.5."""
    p = max(0.0, min(1.0, probability))
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p * math.log2(p) - (1.0 - p) * math.log2(1.0 - p)


def information_gain_from_confidence(confidence: float) -> float:
    """H(p) for a 0..100 confidence value."""
    return information_gain_bits(confidence / 100.0)


def rank_by_information_gain(
    findings: Iterable[UnifiedFinding],
) -> list[tuple[UnifiedFinding, float]]:
    """Order claims by expected information gain (descending).

    Ties break toward higher confidence, then asset value, so ordering is
    deterministic for identical priors.
    """
    ranked = [
        (finding, information_gain_from_confidence(finding.confidence.value))
        for finding in findings
    ]
    ranked.sort(key=lambda pair: (-pair[1], -pair[0].confidence.value, pair[0].asset_value))
    return ranked


__all__ = [
    "information_gain_bits",
    "information_gain_from_confidence",
    "rank_by_information_gain",
]

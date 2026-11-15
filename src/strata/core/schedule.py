"""Global probe scheduling: spend the verification budget where it buys the
most belief.

Strata's honest principle is that probes are a budget. Content discovery can
extract thousands of candidates but only `--max-probe` HTTP requests are
available to verify claims across the *whole* surface — endpoints, live
hosts, and subdomains compete for the same budget.

Allocation is stratified by kind with a square-root weight: a kind with 100x
more candidates gets ~10x the probes, not 100x. This prevents endpoint floods
(a few thousand URLs) from starving host and parameter verification, while
still respecting true abundance. Within each kind, claims are ranked by
expected information gain — probing p≈0.5 first — per `core.inference`.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable
from typing import TypeVar

from strata.core.inference import rank_by_information_gain
from strata.core.schema.models import FindingClass, FindingStatus, UnifiedFinding

PROBEABLE_KINDS = (FindingClass.ENDPOINT, FindingClass.LIVE_HOST, FindingClass.SUBDOMAIN)

T = TypeVar("T")


def _kind_weight(counts: dict[FindingClass, int], kind: FindingClass) -> float:
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return math.sqrt(counts[kind]) / math.sqrt(total)


def select_probes(
    findings: Iterable[UnifiedFinding],
    budget: int,
    *,
    kinds: Iterable[FindingClass] = PROBEABLE_KINDS,
) -> list[tuple[UnifiedFinding, float]]:
    """Choose up to `budget` findings to probe, (finding, expected gain) each.

    Only candidate/stale claims of probeable kinds are eligible. The result is
    a single global ordering: schedule order is exactly list order.
    """
    eligible = [
        finding
        for finding in findings
        if finding.kind in tuple(kinds)
        and finding.status in (FindingStatus.CANDIDATE, FindingStatus.STALE)
    ]
    if budget <= 0 or not eligible:
        return []

    by_kind: dict[FindingClass, list[UnifiedFinding]] = defaultdict(list)
    for finding in eligible:
        by_kind[finding.kind].append(finding)

    counts = {kind: len(members) for kind, members in by_kind.items()}
    quota: dict[FindingClass, int] = defaultdict(int)
    # Largest-remainder apportionment of the budget across kind weights,
    # with a floor of one probe per present kind so a handful of host
    # candidates cannot be crowded out entirely by an endpoint flood.
    raw = {kind: _kind_weight(counts, kind) * budget for kind in counts}
    assigned = 0
    remainders: list[tuple[float, FindingClass]] = []
    for kind, share in raw.items():
        quota[kind] = int(share)
        assigned += int(share)
        remainders.append((share - int(share), kind))
    leftover = budget - assigned
    for _, kind in sorted(remainders, key=lambda pair: -pair[0])[:leftover]:
        quota[kind] += 1
    if budget >= len(counts):
        for kind in counts:
            quota[kind] = max(quota[kind], 1)

    ranked: list[tuple[UnifiedFinding, float]] = []
    for kind in sorted(by_kind, key=lambda k: (-_kind_weight(counts, k), k.value)):
        take = min(quota[kind], len(by_kind[kind]))
        ranked.extend(rank_by_information_gain(by_kind[kind])[:take])
    return ranked


__all__ = ["PROBEABLE_KINDS", "select_probes"]

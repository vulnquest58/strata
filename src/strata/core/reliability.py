"""Source reliability scoring from the truth ledger.

Every recorded outcome carries the discovery sources that asserted the claim.
Aggregating outcomes per source yields a measured verify rate for each source,
which is used for two things:

1. fusion weights — sources that historically verify get louder votes in the
   noisy-OR combination;
2. poisoning defense — a source whose verify rate is far below the pool while
   the pool itself verifies well is statistically inconsistent with honest
   discovery, so it is flagged.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

VERIFIER_ENGINES = frozenset(
    {"content_probe", "dns_verify", "dns_resolve", "param_oracle", "fusion"}
)

# Discovery engines that share an evidence channel are correlated: two DNS
# sources both answering the question "does this name resolve?" cannot be
# combined as independent voters. Fusion therefore collapses components by
# family (keeping the strongest signal per family) before the noisy-OR, so
# only genuinely independent channels multiply.
SOURCE_FAMILIES: dict[str, str] = {
    "dns_brute": "dns",
    "dns_verify": "dns",
    "dns_resolve": "dns",
    "passive_dns": "dns",
    "crt_sh": "dns",
    "virustotal": "dns",
    "securitytrails": "dns",
    "hackertarget": "dns",
    "content_crawl": "content",
    "content_probe": "content",
    "robots_txt": "content",
    "sitemap": "content",
    "param_oracle": "param",
    "http_fp": "http_fp",
    "cve_map": "http_fp",
    "nuclei": "nuclei",
    "vulnharvest": "import",
    "aperture": "import",
    "jsast": "import",
    "triage-loom": "import",
    "import": "import",
}


def source_family(engine: str) -> str:
    """Evidence family a source belongs to (correlated sources share one).

    Engines we have no explicit correlation knowledge about are treated as
    their own family: unmodeled sources are assumed independent rather than
    silently merged into one bucket.
    """
    if not engine:
        return "other"
    base = engine.split(":", 1)[0]
    return SOURCE_FAMILIES.get(base, base)


def collapse_by_family(
    components: dict[str, float],
) -> tuple[dict[str, float], int]:
    """Reduce correlated signals to one strongest vote per family.

    Returns (family_components keyed by ``family:value``, raw signal count).
    """
    collapsed: dict[str, float] = {}
    for key, value in components.items():
        family = source_family(key)
        existing = collapsed.get(family)
        collapsed[family] = max(existing, value) if existing is not None else value
    return collapsed, len(components)


def claim_sources(finding_evidence_engines: Iterable[str]) -> list[str]:
    """Discovery engines that asserted a claim (verifier engines excluded)."""
    sources = {
        engine
        for engine in finding_evidence_engines
        if engine and engine not in VERIFIER_ENGINES
    }
    return sorted(sources)


def assess_source_reliability(
    rows: Iterable[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Aggregate outcomes per source.

    Each row needs ``sources`` (list of engine names), ``predicted`` and
    ``observed``. An outcome contributes to every source that asserted the
    claim. Sources with fewer than ``min_outcomes`` outcomes are reported but
    never flagged.
    """
    overall_rows = [
        (float(row["predicted"]), int(row["observed"]))
        for row in rows
        if row.get("sources")
    ]
    total = len(overall_rows)
    overall_verified = sum(observed for _, observed in overall_rows)

    stats: dict[str, dict[str, Any]] = {}
    for predicted, observed, sources in (
        (float(row["predicted"]), int(row["observed"]), row.get("sources") or [])
        for row in rows
    ):
        if not sources:
            continue
        for source in sources:
            entry = stats.setdefault(
                source,
                {"outcomes": 0, "verified": 0, "dead": 0, "predicted_sum": 0.0},
            )
            entry["outcomes"] += 1
            entry["verified" if observed else "dead"] += 1
            entry["predicted_sum"] += predicted

    result: dict[str, dict[str, Any]] = {}
    for source, entry in sorted(stats.items()):
        outcomes = entry["outcomes"]
        verified = entry["verified"]
        rate = verified / outcomes if outcomes else 0.0
        flagged = False
        reason: str | None = None
        if outcomes >= 20:
            # Compare the source against the rest of the pool: a poisoned or
            # low-quality source dies on claims the rest of the pool finds.
            rest_count = total - outcomes
            rest_rate = (
                (overall_verified - verified) / rest_count if rest_count else 0.0
            )
            if rate <= 0.3 and rest_count >= 10 and rest_rate >= 0.6:
                flagged = True
                reason = (
                    f"verify rate {rate:.0%} vs pool {rest_rate:.0%}; "
                    "possible poisoned or low-quality source"
                )
        result[source] = {
            "outcomes": outcomes,
            "verified": verified,
            "dead": entry["dead"],
            "observed_rate": round(rate * 100, 1),
            "mean_predicted": round(
                entry["predicted_sum"] / outcomes * 100, 1
            ) if outcomes else 0.0,
            "flagged": flagged,
            "flag_reason": reason,
        }
    return result


def reliability_weights(
    reliability: dict[str, dict[str, Any]],
    *,
    min_outcomes: int = 5,
) -> dict[str, float]:
    """Laplace-smoothed per-source vote weights for fusion.

    Sources with fewer than ``min_outcomes`` recorded outcomes keep the
    neutral weight of 1.0; measured sources vote with their smoothed verify
    rate in [0, 1].
    """
    weights: dict[str, float] = {}
    for source, entry in reliability.items():
        outcomes = entry.get("outcomes", 0)
        if outcomes < min_outcomes:
            continue
        verified = entry.get("verified", 0)
        weights[source] = round((verified + 1) / (outcomes + 2), 4)
    return weights


__all__ = [
    "SOURCE_FAMILIES",
    "VERIFIER_ENGINES",
    "assess_source_reliability",
    "claim_sources",
    "collapse_by_family",
    "reliability_weights",
    "source_family",
]

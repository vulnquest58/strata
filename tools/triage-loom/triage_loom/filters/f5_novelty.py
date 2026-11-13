"""
Filter 5: Novelty Ranking

Ranks assets by how much they merit manual investigation.
Crucially: novelty has ZERO relation to vulnerability likelihood.
The three components are purely structural/temporal/infrastructural:

1. infra_deviation (0–1)
   Does this asset use a different ASN/CDN than the majority of the
   organisation's assets? Outliers deserve attention because they may be
   shadow IT, acquired infrastructure, or forgotten services.

2. first_seen_recency (0–1)
   More recently observed = higher score. A subdomain first seen last week
   is more interesting than one that's been in Wayback since 2015.

3. structural_uniqueness (0–1)
   Inverse of cluster size: a URL pattern seen only 2 times is structurally
   unique; one seen 500 times is routine. Routine patterns deserve less
   manual time (one representative review covers the pattern).

Formula: novelty = 0.4 × infra_deviation + 0.3 × recency + 0.3 × uniqueness
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from triage_loom.filters.base import BaseFilter, FilterResult
from triage_loom.models import EndpointCluster, NoveltyScore


# Baseline reference age for recency scoring.
# URLs last seen > _MAX_AGE_DAYS ago get recency = 0.
_MAX_AGE_DAYS = 730  # 2 years


class NoveltyRankingFilter(BaseFilter):
    """Filter 5: Multi-factor novelty ranking (infra deviation + recency + uniqueness)."""

    @property
    def name(self) -> str:
        return "NoveltyRankingFilter"

    @property
    def stage(self) -> int:
        return 5

    async def run(
        self,
        asset_id: str,
        cluster: EndpointCluster | None = None,
        infra_baseline: dict[str, Any] | None = None,
        **_: Any,
    ) -> FilterResult:
        if not cluster:
            return FilterResult(passed=False, evidence={"reason": "no cluster provided"})

        score = self.score(cluster, infra_baseline or {})
        return FilterResult(
            passed=True,  # novelty filter never rejects — it only ranks
            evidence=score.model_dump(),
            metadata={"novelty_score": score.model_dump()},
        )

    def score(
        self,
        cluster: EndpointCluster,
        infra_baseline: dict[str, Any],
    ) -> NoveltyScore:
        """
        Compute the novelty score for an endpoint cluster.

        Args:
            cluster:        The EndpointCluster to score.
            infra_baseline: Dict with 'dominant_asn', 'dominant_cdn' keys
                            (the most common values across the organisation's assets).
        """
        deviation = self._infra_deviation(cluster, infra_baseline)
        recency, recency_is_default = self._recency_score(cluster.first_seen)
        uniqueness = self._structural_uniqueness(cluster.member_count)

        total = 0.4 * deviation + 0.3 * recency + 0.3 * uniqueness

        return NoveltyScore(
            infra_deviation=round(deviation, 4),
            recency=round(recency, 4),
            recency_is_default=recency_is_default,
            structural_uniqueness=round(uniqueness, 4),
            total=round(total, 4),
        )

    def _infra_deviation(self, cluster: EndpointCluster, baseline: dict[str, Any]) -> float:
        """
        Score 1.0 if both ASN and CDN differ from the baseline majority.
        Score 0.5 if only one differs.
        Score 0.0 if both match (infrastructure is typical for this organisation).
        """
        if not baseline:
            return 0.5  # no baseline = moderate uncertainty

        score = 0.0
        dominant_asn = baseline.get("dominant_asn")
        dominant_cdn = baseline.get("dominant_cdn")

        if dominant_asn and cluster.asn and cluster.asn != dominant_asn:
            score += 0.5
        if dominant_cdn and cluster.cdn and cluster.cdn != dominant_cdn:
            score += 0.5

        # If we have no CDN/ASN data for this cluster, partial score.
        if not cluster.asn and not cluster.cdn:
            score = 0.3

        return min(score, 1.0)

    def _recency_score(self, first_seen: datetime | None) -> tuple[float, bool]:
        """
        Score 1.0 for URLs first seen today, 0.0 for those > _MAX_AGE_DAYS old.
        Linear decay between those extremes.
        Returns (score, is_default).
        """
        if first_seen is None:
            return 0.5, True

        now = datetime.now(tz=timezone.utc)
        # Make first_seen timezone-aware if it isn't.
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)

        age_days = (now - first_seen).days
        if age_days <= 0:
            return 1.0, False
        return max(0.0, 1.0 - (age_days / _MAX_AGE_DAYS)), False

    def _structural_uniqueness(self, member_count: int) -> float:
        """
        Score 1.0 for singleton clusters (member_count=1), approaching 0 for large clusters.
        Uses 1/log(n+1) so the decay is gradual and large clusters still get some score.
        """
        import math
        if member_count <= 1:
            return 1.0
        return 1.0 / math.log(member_count + 1)

    def build_infra_baseline(self, clusters: list[EndpointCluster]) -> dict[str, Any]:
        """
        Compute the infra baseline for a set of clusters.
        The baseline is the modal (most common) ASN and CDN across all clusters.
        """
        from collections import Counter

        asn_counts: Counter[str] = Counter()
        cdn_counts: Counter[str] = Counter()

        for cluster in clusters:
            if cluster.asn:
                asn_counts[cluster.asn] += cluster.member_count
            if cluster.cdn:
                cdn_counts[cluster.cdn] += cluster.member_count

        baseline: dict[str, Any] = {}
        if asn_counts:
            baseline["dominant_asn"] = asn_counts.most_common(1)[0][0]
            baseline["asn_distribution"] = dict(asn_counts.most_common(10))
        if cdn_counts:
            baseline["dominant_cdn"] = cdn_counts.most_common(1)[0][0]
            baseline["cdn_distribution"] = dict(cdn_counts.most_common(10))

        return baseline

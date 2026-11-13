"""
Filter 4: Deduplication + Pattern Clustering

Solves a real bug bounty problem: hundreds of URLs with identical structure
(e.g., /api/v1/users/123, /api/v1/users/456) flood the output and make
manual triage impractical.

The approach is deliberately simple and fully transparent:
1. Normalize each URL path by replacing dynamic segments with placeholders
   (numeric IDs → {id}, UUIDs → {uuid}, hashes → {hash}).
2. Cluster by exact match on the normalized pattern — no ML needed.
3. Each cluster is represented by one example URL + total count.
4. In the final output, one row per cluster (not one per URL).

The regex normalization is intentionally deterministic: the same URL will
always produce the same pattern across runs, making diffs reliable.

Additionally, this filter detects "backend twins" — subdomains that return
identical content hashes from Filter 1 (same backend, different hostnames).
These are valuable for scope analysis but clustered separately.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from triage_loom.filters.base import BaseFilter, FilterResult
from triage_loom.models import EndpointCluster, ParameterRecord

# Regex patterns for URL segment normalization.
# Applied in order — first match wins.
_UUID_RE = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)",
    re.IGNORECASE,
)
_HASH_RE = re.compile(r"/[0-9a-f]{32,64}(?=/|$)", re.IGNORECASE)
_NUMERIC_RE = re.compile(r"/\d+(?=/|$)")
_SLUG_RE = re.compile(
    r"/[a-z0-9]{8,}(?:/|$)",  # long alphanumeric slugs (likely generated IDs)
)

# معاملات تتبع/تحليلات شائعة — تُحذف كلياً بدل تُطبَّع، لأنها ليست جزءاً
# من سطح الهجوم البرمجي وتُضخّم عدد الـ clusters بلا فائدة استطلاعية
TRACKING_PARAMS = {
    "ref", "source", "utm_source", "utm_medium", "utm_campaign",
    "utm_term", "utm_content", "fbclid", "gclid", "mc_cid", "mc_eid",
}

QUERY_VALUE_RE = re.compile(r'=[^&]*')


class PatternClusteringFilter(BaseFilter):
    """Filter 4: URL normalization and exact-match clustering."""

    @property
    def name(self) -> str:
        return "PatternClusteringFilter"

    @property
    def stage(self) -> int:
        return 4

    async def run(self, asset_id: str, urls: list[str] | None = None, **_: Any) -> FilterResult:
        """Cluster the given URLs and return cluster metadata."""
        if not urls:
            return FilterResult(passed=False, evidence={"reason": "no URLs to cluster"})

        clusters = self.cluster(urls)

        return FilterResult(
            passed=len(clusters) > 0,
            evidence={
                "cluster_count": len(clusters),
                "total_urls": len(urls),
                "patterns": list(clusters.keys())[:20],  # top 20 for evidence
            },
            metadata={"clusters": {k: v for k, v in clusters.items()}},
        )

    def normalize_query(self, query: str) -> str:
        if not query:
            return ""
        pairs = query.split("&")
        kept_pairs = []
        for pair in pairs:
            if not pair:
                continue
            key = pair.split("=")[0]
            if key.lower() in TRACKING_PARAMS:
                continue  # حذف كامل، ليس تطبيعاً
            kept_pairs.append(QUERY_VALUE_RE.sub("={value}", pair))
        kept_pairs.sort()  # ترتيب ثابت بغض النظر عن ترتيب الظهور الأصلي في الرابط
        return "&".join(kept_pairs)

    def _normalize_path(self, path: str) -> str:
        """
        Normalize a URL path by replacing dynamic segments with typed placeholders.
        """
        # Strip query string and fragment if present.
        path = path.split("?")[0].split("#")[0]

        path = _UUID_RE.sub("/{uuid}", path)
        path = _HASH_RE.sub("/{hash}", path)
        path = _NUMERIC_RE.sub("/{id}", path)
        return path or "/"

    def normalize(self, url: str) -> str:
        parsed = urlparse(url)
        path = self._normalize_path(parsed.path or "/")
        query = self.normalize_query(parsed.query)
        return f"{path}?{query}" if query else path

    def cluster(self, urls: list[str]) -> dict[str, list[str]]:
        """
        Group URLs by their normalized pattern.
        Returns {pattern: [url1, url2, ...]} ordered by cluster size descending.
        """
        clusters: dict[str, list[str]] = defaultdict(list)

        for url in urls:
            try:
                pattern = self.normalize(url) or "/"
            except Exception:
                pattern = "/"
            clusters[pattern].append(url)

        # Sort by cluster size descending (largest clusters first).
        return dict(
            sorted(clusters.items(), key=lambda kv: len(kv[1]), reverse=True)
        )

    def build_endpoint_clusters(
        self,
        urls: list[str],
        parameters_by_pattern: dict[str, list[ParameterRecord]] | None = None,
        first_seen_by_url: dict[str, datetime] | None = None,
    ) -> list[EndpointCluster]:
        """
        Convert clustered URLs into EndpointCluster objects for the output layer.

        Args:
            urls:                   All URLs to cluster.
            parameters_by_pattern:  Optional map of pattern → parameters (from Filter 3).
            first_seen_by_url:      Optional map of url → first_seen datetime.
        """
        raw_clusters = self.cluster(urls)
        result: list[EndpointCluster] = []

        for pattern, members in raw_clusters.items():
            # Pick the representative URL: the one seen most recently, or just the first.
            representative = members[0]
            if first_seen_by_url:
                # Sort by first_seen to pick the canonical example.
                members_sorted = sorted(
                    members,
                    key=lambda u: first_seen_by_url.get(u, datetime.min),
                )
                representative = members_sorted[0]

            first_seen: datetime | None = None
            if first_seen_by_url:
                dates = [first_seen_by_url[u] for u in members if u in first_seen_by_url]
                if dates:
                    first_seen = min(dates)

            params = (parameters_by_pattern or {}).get(pattern, [])

            result.append(
                EndpointCluster(
                    pattern=pattern,
                    representative_url=representative,
                    member_count=len(members),
                    member_urls=members[:50],  # cap stored members for output size
                    parameters=params,
                    first_seen=first_seen,
                )
            )

        return result

    def detect_backend_twins(
        self,
        asset_ids: list[str],
        content_hashes: dict[str, str | None],
    ) -> dict[str, list[str]]:
        """
        Group subdomains that return the same content hash (from Filter 1).
        Returns {content_hash: [asset1, asset2, ...]} for hashes with ≥2 assets.
        Used to identify subdomains sharing the same backend.
        """
        hash_groups: dict[str, list[str]] = defaultdict(list)
        for asset in asset_ids:
            h = content_hashes.get(asset)
            if h:
                hash_groups[h].append(asset)
        return {h: assets for h, assets in hash_groups.items() if len(assets) >= 2}

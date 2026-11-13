"""
Unit test suite for Triage Loom.
Covers models, filters 1-5, ranking/priority, explain, and database operations.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import pytest
import httpx

from triage_loom.models import (
    ApertureFinding,
    AssetType,
    CorroborationLayer,
    EndpointCluster,
    NoveltyScore,
    TriagedFinding,
)
from triage_loom.filters.f1_liveness import LivenessFilter
from triage_loom.filters.f2_archive import ArchiveCrossReferenceFilter, ArchiveSource
from triage_loom.filters.f3_params import ParameterCorroborationFilter
from triage_loom.filters.f4_clustering import PatternClusteringFilter
from triage_loom.filters.f5_novelty import NoveltyRankingFilter
from triage_loom.ranking.priority import investigation_priority, explain
from triage_loom.storage.db import DB


def test_aperture_finding_model():
    """Verify parsing and fields of ApertureFinding."""
    data = {
        "id": "test-id-123",
        "scan_id": "scan-1",
        "asset_id": "api.example.com",
        "asset_type": "subdomain",
        "parent_asset": "example.com",
        "source_plugin": "hackertarget,rapiddns",
        "raw_confidence": 65.0,
        "per_source_raw_confidence": {"hackertarget": 70.0, "rapiddns": 65.0},
        "combined_confidence": 84.0,
        "adjusted_confidence": 84.0,
        "consensus_count": 2,
        "temporal_stability": 1.0,
        "discovered_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    f = ApertureFinding(**data)
    assert f.asset_id == "api.example.com"
    assert f.per_source_raw_confidence["hackertarget"] == 70.0
    assert f.consensus_count == 2
    assert f.combined_confidence == 84.0


def test_corroboration_layers_no_novelty():
    """Verify that novelty is NOT a corroboration layer."""
    layers = [
        CorroborationLayer.liveness,
        CorroborationLayer.archive_commoncrawl,
        CorroborationLayer.archive_urlscan,
    ]
    # Novelty must not be in CorroborationLayer enum
    assert "novelty" not in [l.value for l in CorroborationLayer]

    tf = TriagedFinding(
        aperture_finding_id="fid-1",
        asset_id="api.example.com",
        root_domain="example.com",
        endpoint_pattern="/api/v1/users/{id}",
        representative_url="https://api.example.com/api/v1/users/42",
        cluster_size=5,
        corroboration_layers=layers,
        is_high_confidence=len(layers) >= 2,
    )
    assert tf.is_high_confidence is True
    assert tf.corroboration_count == 3


def test_pattern_clustering_normalization():
    """Verify Filter 4 path normalization of IDs, UUIDs, and Hashes."""
    f4 = PatternClusteringFilter()

    # Numeric IDs
    assert f4.normalize("/api/v1/users/12345") == "/api/v1/users/{id}"
    assert f4.normalize("/pull/4952") == "/pull/{id}"

    # UUIDs
    uuid_str = "c305d2d3-ad19-4a7b-8c59-86800014392e"
    assert f4.normalize(f"/items/{uuid_str}") == "/items/{uuid}"

    # Hashes (MD5/SHA1/SHA256)
    hash_str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert f4.normalize(f"/commits/{hash_str}") == "/commits/{hash}"

    # URL clustering
    urls = [
        "https://example.com/api/users/1",
        "https://example.com/api/users/2",
        "https://example.com/api/users/3",
        "https://example.com/api/status",
    ]
    clusters = f4.cluster(urls)
    assert "/api/users/{id}" in clusters
    assert len(clusters["/api/users/{id}"]) == 3
    assert "/api/status" in clusters
    assert len(clusters["/api/status"]) == 1


def test_novelty_score_calculation():
    """Verify Filter 5 novelty score computation."""
    f5 = NoveltyRankingFilter()
    cluster = EndpointCluster(
        pattern="/api/{id}",
        representative_url="https://sub.example.com/api/1",
        member_count=1,
        asn="AS13335",
        cdn="Cloudflare",
    )
    # Baseline with differing CDN/ASN
    baseline = {"dominant_asn": "AS16509", "dominant_cdn": "Amazon CloudFront"}
    score = f5.score(cluster, baseline)
    assert score.infra_deviation == 1.0  # Both differ
    assert score.structural_uniqueness == 1.0  # Singleton
    assert score.total > 0.6


def test_investigation_priority_and_explain():
    """Verify investigation priority and explain output."""
    nov = NoveltyScore(
        infra_deviation=0.5,
        recency=0.5,
        structural_uniqueness=1.0,
        total=0.65,
    )
    tf = TriagedFinding(
        aperture_finding_id="fid-99",
        asset_id="sub.example.com",
        root_domain="example.com",
        endpoint_pattern="/api/v1/auth",
        representative_url="https://sub.example.com/api/v1/auth",
        cluster_size=1,
        corroboration_layers=[CorroborationLayer.liveness, CorroborationLayer.archive_urlscan],
        parameters=["token", "redirect_uri"],
        novelty=nov,
        is_high_confidence=True,
    )
    p = investigation_priority(tf)
    tf.investigation_priority = p
    # priority = corroboration_count (2) * novelty.total (0.65) * min(params, 3.0) (2.0) = 2.6
    assert p == 2.6

    exp = explain(tf)
    assert exp["endpoint_pattern"] == "/api/v1/auth"
    assert exp["confidence_tier"] == "HIGH"
    assert exp["investigation_priority"] == 2.6
    assert exp["corroboration"]["total_layers"] == 2


def test_duckdb_storage_isolation(tmp_path):
    """Verify DuckDB storage correctly stores multiple endpoint patterns per asset without overwrite."""
    db_file = str(tmp_path / "test.duckdb")
    with DB(db_file) as db:
        # Ingest finding
        finding = ApertureFinding(
            id="aperture-1",
            scan_id="scan-1",
            asset_id="api.example.com",
            parent_asset="example.com",
            source_plugin="crtsh",
            discovered_at=datetime.now(tz=timezone.utc),
        )
        db.upsert_finding(finding)

        # Upsert two different endpoint patterns for the SAME aperture_finding_id / asset_id
        tf1 = TriagedFinding(
            aperture_finding_id="aperture-1",
            asset_id="api.example.com",
            root_domain="example.com",
            endpoint_pattern="/api/v1/users/{id}",
            representative_url="https://api.example.com/api/v1/users/1",
            cluster_size=10,
            corroboration_layers=[CorroborationLayer.liveness, CorroborationLayer.archive_urlscan],
            is_high_confidence=True,
            investigation_priority=2.0,
        )
        tf2 = TriagedFinding(
            aperture_finding_id="aperture-1",
            asset_id="api.example.com",
            root_domain="example.com",
            endpoint_pattern="/api/v1/orders/{id}",
            representative_url="https://api.example.com/api/v1/orders/5",
            cluster_size=3,
            corroboration_layers=[CorroborationLayer.liveness],
            is_high_confidence=False,
            investigation_priority=0.5,
        )
        db.upsert_triaged(tf1)
        db.upsert_triaged(tf2)

        # Both must exist!
        high = db.get_triaged_high_confidence("example.com")
        low = db.get_triaged_low_confidence("example.com")
        assert len(high) == 1
        assert high[0]["endpoint_pattern"] == "/api/v1/users/{id}"
        assert len(low) == 1
        assert low[0]["endpoint_pattern"] == "/api/v1/orders/{id}"


def test_archive_source_wayback_503_retry_and_transparency(monkeypatch):
    """
    Verify archive filter transparency on failure:
    - Wayback returns 503 repeatedly.
    - Retry logic executes and eventually flags archive_sources_failed == ['wayback'].
    - CommonCrawl and URLScan results are still captured and returned without halting.
    - Triaged finding and explain include archive_sources_failed.
    """
    async def _async_test():
        f2 = ArchiveCrossReferenceFilter()

        # Make retry fast for unit test
        monkeypatch.setattr("triage_loom.filters.f2_archive.RETRY_DELAY_SECONDS", 0.001)

        # Mock wayback to fail with 503
        request = httpx.Request("GET", "http://web.archive.org/cdx/search/cdx")
        response_503 = httpx.Response(503, request=request)
        mock_wayback_call_count = 0

        async def mock_wayback(domain: str) -> set[str]:
            nonlocal mock_wayback_call_count
            mock_wayback_call_count += 1
            raise httpx.HTTPStatusError("503 Service Unavailable", request=request, response=response_503)

        async def mock_commoncrawl(domain: str) -> set[str]:
            return {"https://example.com/api/users", "https://example.com/api/orders"}

        async def mock_urlscan(domain: str) -> set[str]:
            return {"https://example.com/api/users"}

        monkeypatch.setattr(f2, "_query_wayback", mock_wayback)
        monkeypatch.setattr(f2, "_query_commoncrawl", mock_commoncrawl)
        monkeypatch.setattr(f2, "_query_urlscan", mock_urlscan)

        results, failed_sources = await f2.cross_reference("example.com")

        # 1. Verify wayback retried (MAX_RETRIES = 1 means 2 calls total)
        assert mock_wayback_call_count == 2

        # 2. Verify failure was recorded transparently
        assert failed_sources == ["wayback"]
        assert results["wayback"] == set()

        # 3. Verify other sources succeeded
        assert "https://example.com/api/users" in results["commoncrawl"]
        assert "https://example.com/api/users" in results["urlscan"]

        # 4. Verify run() filter outcome: commoncrawl and urlscan still confirm the asset (>= 2)
        filter_res = await f2.run("example.com")
        assert filter_res.passed is True
        assert filter_res.evidence["failed_sources"] == ["wayback"]

        # 5. Verify TriagedFinding model and explain() integration
        tf = TriagedFinding(
            aperture_finding_id="fid-1",
            asset_id="example.com",
            root_domain="example.com",
            endpoint_pattern="/api/users",
            representative_url="https://example.com/api/users",
            cluster_size=1,
            corroboration_layers=[CorroborationLayer.archive_commoncrawl, CorroborationLayer.archive_urlscan],
            archive_sources_failed=failed_sources,
            is_high_confidence=True,
        )
        assert tf.archive_sources_failed == ["wayback"]

        explained = explain(tf)
        assert explained["archive_sources_failed"] == ["wayback"]
        assert explained["corroboration"]["archive_sources_failed"] == ["wayback"]

    asyncio.run(_async_test())


def test_pattern_clustering_query_string_normalization_and_tracking_params():
    """
    Verify Filter 4 query string normalization:
    - Tracking parameters (ref, utm_*, etc.) are stripped completely.
    - Functional parameters (client_id, return_to, query) are retained and normalized to ={value}.
    - URLs differing ONLY by tracking params collapse into the exact same pattern (e.g. /).
    - URLs with functional params collapse into normalized pattern with parameter names retained.
    """
    f4 = PatternClusteringFilter()

    # 1. Tracking parameters on homepage: stripped completely to "/"
    url_ref1 = "https://github.com/?ref=twitter.com"
    url_ref2 = "https://github.com/?ref=darkwebinformer.com"
    assert f4.normalize(url_ref1) == "/"
    assert f4.normalize(url_ref2) == "/"

    # 2. Tracking parameters with utm_*: stripped completely to "/"
    url_utm = "https://github.com/?utm_source=twitter&utm_medium=social"
    assert f4.normalize(url_utm) == "/"

    # 3. Functional auth/API params on /login: retained and normalized
    url_login_a = "https://github.com/login?client_id=client_AAA&return_to=%2Fsettings"
    url_login_b = "https://github.com/login?client_id=client_BBB&return_to=%2Fdashboard"
    expected_login = "/login?client_id={value}&return_to={value}"
    assert f4.normalize(url_login_a) == expected_login
    assert f4.normalize(url_login_b) == expected_login

    # 4. Advisories query parameter: retained as query={value}
    url_advisories = "https://github.com/advisories?query=cve-2024-1234"
    assert f4.normalize(url_advisories) == "/advisories?query={value}"

    # 5. Cluster behavior:
    # - ?ref URLs on root collapse together into "/"
    # - /login?client_id=A and /login?client_id=B collapse together into "/login?client_id={value}"
    urls = [
        "https://github.com/?ref=twitter.com",
        "https://github.com/?ref=darkwebinformer.com",
        "https://github.com/login?client_id=A",
        "https://github.com/login?client_id=B",
        "https://github.com/advisories?query=test",
    ]
    clusters = f4.cluster(urls)
    assert "/" in clusters
    assert len(clusters["/"]) == 2
    assert "/login?client_id={value}" in clusters
    assert len(clusters["/login?client_id={value}"]) == 2
    assert "/advisories?query={value}" in clusters
    assert len(clusters["/advisories?query={value}"]) == 1



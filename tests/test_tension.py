from strata.core.schema.models import (
    Confidence,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)
from strata.engines.tension import (
    TensionLabel,
    assess_tension,
    summarise_tension,
    tension_markdown,
)


def _finding(
    *,
    asset_value: str,
    kind: FindingClass = FindingClass.SUBDOMAIN,
    status: FindingStatus = FindingStatus.CANDIDATE,
    confidence: float = 50.0,
    engines: list[str] | None = None,
    metadata: dict | None = None,
) -> UnifiedFinding:
    return UnifiedFinding(
        run_id="r1",
        kind=kind,
        status=status,
        asset_value=asset_value,
        confidence=Confidence(value=confidence),
        evidence=[Evidence(engine=engine, technique="test") for engine in engines or []],
        metadata=metadata or {},
    )


def test_verified_with_live_probe_is_stable() -> None:
    finding = _finding(
        asset_value="api.example.com",
        status=FindingStatus.VERIFIED,
        confidence=80.0,
        engines=["content_probe", "dns_verify"],
        metadata={"source_count": 2},
    )
    assessment = assess_tension(finding)
    assert assessment.label == TensionLabel.STABLE
    assert assessment.score < 50


def test_high_confidence_unverified_is_hot() -> None:
    finding = _finding(
        asset_value="admin.example.com",
        confidence=70.0,
        engines=["content_crawl"],
        metadata={"source_count": 1},
    )
    assessment = assess_tension(finding)
    assert assessment.label == TensionLabel.HOT
    assert assessment.score >= 70
    assert "high-confidence but still unverified" in assessment.reasons


def test_dead_with_residual_confidence_is_ghost() -> None:
    finding = _finding(
        asset_value="legacy.example.com",
        status=FindingStatus.DEAD,
        confidence=60.0,
        engines=["content_crawl"],
    )
    assessment = assess_tension(finding)
    assert assessment.label == TensionLabel.GHOST
    assert "dead claim with residual confidence" in assessment.reasons


def test_low_confidence_single_source_is_shadow() -> None:
    finding = _finding(
        asset_value="maybe.example.com",
        confidence=30.0,
        engines=["content_crawl"],
    )
    assessment = assess_tension(finding)
    assert assessment.label == TensionLabel.SHADOW
    assert assessment.score >= 50


def test_summarise_counts_labels() -> None:
    findings = [
        _finding(
            asset_value="a.example.com",
            status=FindingStatus.VERIFIED,
            confidence=80.0,
            engines=["content_probe", "dns_verify"],
            metadata={"source_count": 2},
        ),
        _finding(asset_value="b.example.com", confidence=70.0, engines=["content_crawl"]),
        _finding(
            asset_value="c.example.com",
            status=FindingStatus.DEAD,
            confidence=60.0,
            engines=["content_crawl"],
        ),
    ]
    summary, items = summarise_tension(findings)
    assert summary.total == 3
    assert summary.hot == 1
    assert summary.ghost == 1
    assert summary.stable == 1
    assert len(items) == 3


def test_tension_markdown_includes_summary_and_findings() -> None:
    finding = _finding(asset_value="a.example.com", confidence=70.0, engines=["content_crawl"])
    rendered = tension_markdown([finding], title="Tension")
    assert "# Tension" in rendered
    assert "| Hot | 1 |" in rendered
    assert "| a.example.com |" in rendered


def test_contested_metadata_adds_tension() -> None:
    clean = assess_tension(
        _finding(asset_value="a.example.com", confidence=60.0, engines=["dns_brute"])
    )
    contested = assess_tension(
        _finding(
            asset_value="a.example.com",
            confidence=60.0,
            engines=["dns_brute"],
            metadata={"contested": True},
        )
    )
    assert contested.score >= clean.score + 15
    assert "sources conflict" in " ".join(contested.reasons).lower()


def test_dead_parents_add_tension() -> None:
    finding = _finding(
        asset_value="vpn.example.com", confidence=60.0, engines=["dns_brute"]
    )
    assessment = assess_tension(finding, dead_parents={"vpn.example.com"})
    assert assessment.score >= 50
    assert any("dead" in reason.lower() for reason in assessment.reasons)


def test_stale_claims_decay_in_tension() -> None:
    from datetime import UTC, datetime, timedelta

    now = datetime(2026, 11, 14, tzinfo=UTC)
    stale = _finding(
        asset_value="old.example.com", confidence=60.0, engines=["dns_brute"]
    )
    stale.discovered_at = now - timedelta(days=60)
    fresh = _finding(
        asset_value="new.example.com", confidence=60.0, engines=["dns_brute"]
    )
    stale_assessment = assess_tension(stale, now=now)
    fresh_assessment = assess_tension(fresh, now=now)
    assert stale_assessment.score > fresh_assessment.score
    assert stale_assessment.effective_confidence < 60.0
    assert fresh_assessment.effective_confidence == 60.0
    assert stale_assessment.age_days == 60.0

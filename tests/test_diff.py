from strata.core.diff import (
    SurfaceSnapshot,
    diff_markdown,
    diff_snapshots,
    snapshot_from_findings,
    snapshot_key,
)
from strata.core.schema.models import (
    Confidence,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)


def _finding(
    asset: str, *, status: FindingStatus, confidence: float
) -> UnifiedFinding:
    return UnifiedFinding(
        run_id="r1",
        kind=FindingClass.SUBDOMAIN,
        asset_value=asset,
        confidence=Confidence(value=confidence),
        evidence=[Evidence(engine="crtsh", technique="test")],
        status=status,
    )


def test_snapshot_key_normalises_hosts_and_params() -> None:
    assert (
        snapshot_key("endpoint", "https://Example.com/b?b=2&a=1")
        == snapshot_key("endpoint", "https://example.com/b?a=1&b=2")
    )
    assert (
        snapshot_key("endpoint", "https://example.com/api/")
        != snapshot_key("endpoint", "https://example.com/api")
    )


def test_diff_reports_added_removed_and_status_changes() -> None:
    baseline_findings = [
        _finding("kept.example.com", status=FindingStatus.CANDIDATE, confidence=50.0),
        _finding("gone.example.com", status=FindingStatus.CANDIDATE, confidence=50.0),
        _finding("died.example.com", status=FindingStatus.CANDIDATE, confidence=50.0),
    ]
    current_findings = [
        _finding("kept.example.com", status=FindingStatus.VERIFIED, confidence=85.0),
        _finding("new.example.com", status=FindingStatus.CANDIDATE, confidence=45.0),
        _finding("died.example.com", status=FindingStatus.DEAD, confidence=50.0),
    ]
    baseline = snapshot_from_findings(
        baseline_findings, target="example.com", strata_version="0.4.0"
    )
    current = snapshot_from_findings(
        current_findings, target="example.com", strata_version="0.4.0"
    )
    diff = diff_snapshots(baseline, current)

    assert diff.added == ["subdomain|new.example.com"]
    assert diff.removed == ["subdomain|gone.example.com"]
    assert diff.churn == 2
    assert ("subdomain|kept.example.com", "candidate", "verified") in (
        diff.status_changes
    )
    assert ("subdomain|died.example.com", "candidate", "dead") in (
        diff.status_changes
    )
    assert any(
        key == "subdomain|kept.example.com" and new == 85.0
        for key, _, new in diff.confidence_changes
    )


def test_snapshot_round_trips_through_dict() -> None:
    baseline = snapshot_from_findings(
        [_finding("a.example.com", status=FindingStatus.CANDIDATE, confidence=50.0)],
        target="example.com",
        strata_version="0.4.0",
    )
    restored = SurfaceSnapshot.from_dict(baseline.to_dict())
    assert restored.entries == baseline.entries
    assert restored.target == "example.com"


def test_diff_markdown_renders_sections() -> None:
    baseline = snapshot_from_findings(
        [_finding("old.example.com", status=FindingStatus.CANDIDATE, confidence=50.0)],
        target="example.com",
        strata_version="0.4.0",
    )
    current = snapshot_from_findings(
        [_finding("new.example.com", status=FindingStatus.CANDIDATE, confidence=50.0)],
        target="example.com",
        strata_version="0.4.0",
    )
    diff = diff_snapshots(baseline, current)
    rendered = diff_markdown(diff, baseline, current)
    assert "# Strata surface diff" in rendered
    assert "subdomain|new.example.com" in rendered
    assert "subdomain|old.example.com" in rendered
    assert "- churn: 2" in rendered

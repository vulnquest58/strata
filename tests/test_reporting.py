import json
from pathlib import Path

from strata.core.reporting import (
    ReportFormat,
    html_report,
    jsonl_lines,
    markdown_report,
    sarif_report,
    summarise,
    write_report,
)
from strata.core.schema.models import (
    Confidence,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)


def _finding(
    *,
    asset_value: str,
    kind: FindingClass = FindingClass.SUBDOMAIN,
    status: FindingStatus = FindingStatus.CANDIDATE,
    confidence: float = 50.0,
    parent: str | None = None,
    metadata: dict | None = None,
) -> UnifiedFinding:
    return UnifiedFinding(
        run_id="r1",
        kind=kind,
        status=status,
        asset_value=asset_value,
        parent=parent,
        confidence=Confidence(value=confidence),
        evidence=[Evidence(engine="test", technique="test")],
        metadata=metadata or {},
    )


def test_summarise_counts_status_and_kind() -> None:
    findings = [
        _finding(asset_value="a.example.com", status=FindingStatus.VERIFIED),
        _finding(asset_value="b.example.com", status=FindingStatus.CANDIDATE),
        _finding(
            asset_value="https://example.com/api",
            kind=FindingClass.ENDPOINT,
            status=FindingStatus.CANDIDATE,
        ),
    ]
    summary = summarise(findings)
    assert summary.findings == 3
    assert summary.verified == 1
    assert summary.candidate == 2
    assert summary.by_kind["subdomain"] == 2
    assert summary.by_kind["endpoint"] == 1


def test_markdown_report_is_deterministic_and_sorted() -> None:
    findings = [
        _finding(asset_value="b.example.com", confidence=60.0),
        _finding(asset_value="a.example.com", confidence=60.0),
    ]
    first = markdown_report(findings)
    second = markdown_report(list(reversed(findings)))
    assert first == second
    assert "| 60.0 | candidate | subdomain | a.example.com |" in first
    assert "| Findings | 2 |" in first


def test_html_report_includes_summary_and_rows() -> None:
    findings = [_finding(asset_value="a.example.com", confidence=80.0)]
    rendered = html_report(findings, title="Custom title")
    assert "<title>Custom title</title>" in rendered
    assert "<code>a.example.com</code>" in rendered
    assert "<div class=\"num\">0</div>Verified" in rendered


def test_sarif_report_is_valid_shape() -> None:
    findings = [
        _finding(
            asset_value="https://example.com/api",
            kind=FindingClass.ENDPOINT,
            confidence=90.0,
            parent="example.com",
        )
    ]
    report = sarif_report(findings)
    assert report["version"] == "2.1.0"
    assert report["runs"][0]["tool"]["driver"]["name"] == "strata"
    result = report["runs"][0]["results"][0]
    assert result["ruleId"] == "endpoint"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "https://example.com/api"
    )


def test_jsonl_lines_round_trip() -> None:
    finding = _finding(asset_value="a.example.com", confidence=70.0)
    lines = jsonl_lines([finding])
    assert len(lines) == 1
    assert json.loads(lines[0])["asset_value"] == "a.example.com"


def test_write_report_creates_each_format(tmp_path: Path) -> None:
    findings = [_finding(asset_value="a.example.com", confidence=70.0)]
    for fmt in ReportFormat:
        path = tmp_path / f"report.{fmt.value}"
        summary = write_report(findings, path, fmt, title="Test report")
        assert summary.findings == 1
        assert path.exists()
        assert path.stat().st_size > 0

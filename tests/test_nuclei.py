"""Tests for the nuclei adapter (import + target export)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strata.adapters.nuclei import (
    export_nuclei_targets,
    load_nuclei_json,
    load_nuclei_jsonl,
    parse_nuclei_result,
)
from strata.core.schema.models import (
    Confidence,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)


def _nuclei_record(**overrides):
    record = {
        "template-id": "CVE-2021-41773",
        "info": {
            "name": "Apache 2.4.49/2.4.50 - Path Traversal",
            "severity": "critical",
            "tags": ["apache", "lfi", "rce"],
            "classification": {"cve-id": "CVE-2021-41773", "cwe-id": "CWE-22"},
        },
        "host": "https://example.com",
        "matched-at": "https://example.com/cgi-bin/",
        "type": "http",
        "matcher-status": True,
        "timestamp": "2026-11-15T10:00:00Z",
        "extracted-results": ["/etc/passwd"],
    }
    record.update(overrides)
    return record


def test_parse_nuclei_result_full():
    finding = parse_nuclei_result(_nuclei_record())
    assert finding.kind is FindingClass.VULN
    assert finding.status is FindingStatus.VERIFIED
    assert finding.asset_value == "https://example.com"
    assert finding.finding_id.startswith("nuclei:")
    assert finding.metadata["template_id"] == "CVE-2021-41773"
    assert finding.metadata["severity"] == "critical"
    assert finding.metadata["cve"] == "CVE-2021-41773"
    assert "apache" in finding.metadata["tags"]
    assert finding.confidence.value == 90.0
    evidence = finding.evidence[0]
    assert evidence.engine == "nuclei"
    assert evidence.strength.value == "corroborated"
    assert "CVE-2021-41773" in evidence.observation


def test_parse_nuclei_result_no_matcher_status_is_candidate():
    finding = parse_nuclei_result(_nuclei_record(**{"matcher-status": False}))
    assert finding.status is FindingStatus.CANDIDATE
    assert finding.confidence.value == 90.0  # severity drives confidence


def test_parse_nuclei_result_severity_confidence():
    assert parse_nuclei_result(_nuclei_record(info={"severity": "high"})).confidence.value == 80.0
    assert parse_nuclei_result(_nuclei_record(info={"severity": "info"})).confidence.value == 40.0
    unknown = parse_nuclei_result(_nuclei_record(info={"severity": "unknown"}))
    assert unknown.confidence.value == 50.0


def test_parse_nuclei_result_requires_host():
    record = _nuclei_record()
    del record["host"]
    del record["matched-at"]
    with pytest.raises(ValueError):
        parse_nuclei_result(record)


def test_parse_nuclei_result_requires_template_id():
    record = _nuclei_record()
    del record["template-id"]
    with pytest.raises(ValueError):
        parse_nuclei_result(record)


def test_parse_nuclei_result_deterministic_id():
    a = parse_nuclei_result(_nuclei_record())
    b = parse_nuclei_result(_nuclei_record())
    assert a.finding_id == b.finding_id


def test_load_nuclei_jsonl(tmp_path: Path):
    path = tmp_path / "results.jsonl"
    lines = [
        json.dumps(_nuclei_record()),
        json.dumps(
            _nuclei_record(**{"template-id": "tech-detect", "host": "https://www.example.com"})
        ),
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    findings = list(load_nuclei_jsonl(path))
    assert len(findings) == 2
    assert findings[1].metadata["template_id"] == "tech-detect"
    assert findings[1].metadata["severity"] == "critical"  # info inherited


def test_load_nuclei_jsonl_invalid_line(tmp_path: Path):
    path = tmp_path / "results.jsonl"
    path.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="line 1"):
        list(load_nuclei_jsonl(path))


def test_load_nuclei_json_array(tmp_path: Path):
    path = tmp_path / "results.json"
    path.write_text(json.dumps([_nuclei_record(), _nuclei_record()]), encoding="utf-8")
    findings = list(load_nuclei_json(path))
    assert len(findings) == 2


def _finding(kind, status, value, parent=None):
    return UnifiedFinding(
        run_id="test",
        kind=kind,
        status=status,
        asset_value=value,
        parent=parent,
        confidence=Confidence(value=50.0),
        evidence=[Evidence(engine="x", technique="t", observation="o")],
        metadata={},
    )


def test_export_nuclei_targets_ranked_and_clean():
    findings = [
        _finding(FindingClass.LIVE_HOST, FindingStatus.VERIFIED, "example.com"),
        _finding(
            FindingClass.ENDPOINT,
            FindingStatus.VERIFIED,
            "https://example.com/api/users/",
        ),
        _finding(
            FindingClass.ENDPOINT,
            FindingStatus.DEAD,
            "https://example.com/dead",
        ),
        _finding(
            FindingClass.SUBDOMAIN,
            FindingStatus.CANDIDATE,
            "www.example.com",
        ),
        _finding(
            FindingClass.ENDPOINT,
            FindingStatus.CANDIDATE,
            "https://example.com/maybe",
        ),
    ]
    urls = export_nuclei_targets(findings)
    assert "https://example.com" in urls
    assert "https://example.com/api/users" in urls  # trailing slash stripped
    assert "https://example.com/dead" not in urls
    assert "https://www.example.com" not in urls  # candidate excluded by default

    urls_all = export_nuclei_targets(findings, include_candidates=True)
    assert "https://www.example.com" in urls_all
    assert "https://example.com/maybe" in urls_all
    # verified hosts sort before deeper endpoints
    assert urls_all[0] == "https://example.com"


def test_export_nuclei_targets_subdomain_host_only():
    findings = [_finding(FindingClass.SUBDOMAIN, FindingStatus.VERIFIED, "shop.example.com")]
    assert export_nuclei_targets(findings) == ["https://shop.example.com"]

import json
from pathlib import Path

import pytest

from strata.adapters.triage_loom import load_triage_loom_jsonl
from strata.core.schema.models import FindingClass, FindingStatus


def _record(**overrides):
    base = {
        "aperture_finding_id": "aperture-1",
        "asset_id": "api.example.com",
        "root_domain": "example.com",
        "endpoint_pattern": "/api/v1/users/{id}",
        "representative_url": "https://api.example.com/api/v1/users/42",
        "cluster_size": 3,
        "corroboration_layers": ["liveness", "archive_wayback"],
        "parameters": ["user_id", "include"],
        "novelty": {
            "infra_deviation": 0.5,
            "recency": 1.0,
            "structural_uniqueness": 0.7,
            "total": 0.7,
        },
        "investigation_priority": 1.4,
        "is_high_confidence": True,
    }
    base.update(overrides)
    return base


def _write_jsonl(tmp_path: Path, records: list[dict]) -> Path:
    path = tmp_path / "triage.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record) + "\n")
    return path


def test_loads_endpoint_and_parameter_findings(tmp_path: Path) -> None:
    path = _write_jsonl(tmp_path, [_record()])
    findings = list(load_triage_loom_jsonl(path))
    endpoint = findings[0]
    params = findings[1:]

    assert endpoint.kind is FindingClass.ENDPOINT
    assert endpoint.status is FindingStatus.VERIFIED
    assert endpoint.asset_value == "https://api.example.com/api/v1/users/42"
    assert endpoint.parent == "api.example.com"
    assert endpoint.confidence.method.value == "noisy_or"
    assert len(endpoint.evidence) == 2

    assert [param.asset_value for param in params] == ["user_id", "include"]
    assert all(param.kind is FindingClass.PARAM for param in params)
    assert all(param.parent == endpoint.asset_value for param in params)


def test_low_confidence_cluster_is_candidate(tmp_path: Path) -> None:
    path = _write_jsonl(
        tmp_path,
        [_record(corroboration_layers=["liveness"], is_high_confidence=False)],
    )
    findings = list(load_triage_loom_jsonl(path))
    assert len(findings) == 3
    endpoint = findings[0]
    assert endpoint.status is FindingStatus.CANDIDATE
    assert endpoint.confidence.value == 80.0
    assert all(param.status is FindingStatus.CANDIDATE for param in findings[1:])


def test_rejects_record_without_endpoint(tmp_path: Path) -> None:
    path = _write_jsonl(
        tmp_path,
        [_record(representative_url="", endpoint_pattern="")],
    )
    with pytest.raises(ValueError):
        list(load_triage_loom_jsonl(path))

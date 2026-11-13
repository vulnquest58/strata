from pathlib import Path

import pytest

from strata.adapters.vulnharvest import (
    load_vulnharvest_report,
    parse_vulnharvest_report,
)
from strata.core.schema.models import FindingClass, FindingStatus

FIXTURE = Path(__file__).parent / "fixtures" / "vulnharvest_sample.json"


def test_fixture_maps_all_items():
    findings = list(load_vulnharvest_report(FIXTURE))
    assert len(findings) == 5
    assert sum(finding.kind is FindingClass.ENDPOINT for finding in findings) == 4
    assert sum(finding.kind is FindingClass.SECRET for finding in findings) == 1
    assert {finding.run_id for finding in findings} == {"vulnharvest:hv-test-1"}


def test_tracking_params_removed_and_status_mapped():
    by_asset = {finding.asset_value: finding for finding in load_vulnharvest_report(FIXTURE)}
    live = by_asset["https://app.example.com/api/v1/users?id=42"]
    assert live.status is FindingStatus.VERIFIED
    assert live.confidence.value == 70.0
    assert live.evidence[0].engine == "vulnharvest"
    assert live.evidence[0].technique == "wayback"
    assert by_asset["https://app.example.com/admin/backup"].status is FindingStatus.DEAD
    login = by_asset["https://app.example.com/login"]
    assert login.status is FindingStatus.CANDIDATE
    assert login.metadata["discovery_context"]["line_number"] == 12


def test_secret_is_masked():
    secret = next(
        finding
        for finding in load_vulnharvest_report(FIXTURE)
        if finding.kind is FindingClass.SECRET
    )
    assert secret.asset_value.startswith("secret:jwt_token:")
    assert secret.evidence[0].meta["value_preview"] == "eyJhbG...sR8U"
    serialized = secret.model_dump_json()
    assert "eyJhbGciOiJIUzI1NiJ9" not in serialized


def test_discovered_at_uses_report_timestamp():
    findings = list(load_vulnharvest_report(FIXTURE))
    assert findings[0].discovered_at.isoformat().startswith("2026-11-13T10:00:00")


def test_endpoint_without_url_raises():
    with pytest.raises(ValueError, match="missing a url"):
        list(parse_vulnharvest_report({"meta": {}, "endpoints": [{}]}))


def test_non_list_endpoints_raises():
    with pytest.raises(ValueError, match="endpoints must be a list"):
        list(parse_vulnharvest_report({"meta": {}, "endpoints": "bad"}))

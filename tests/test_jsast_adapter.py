from pathlib import Path

import pytest

from strata.adapters.jsast import load_jsast_report, parse_jsast_report
from strata.core.schema.models import FindingClass, FindingStatus

FIXTURE = Path(__file__).parent / "fixtures" / "jsast_sample.json"


def test_endpoint_mapping():
    findings = list(load_jsast_report(FIXTURE))
    endpoint = next(
        finding for finding in findings if finding.kind is FindingClass.ENDPOINT
    )
    assert endpoint.asset_value == "https://app.example.com/api/v2/orders"
    assert endpoint.status is FindingStatus.CANDIDATE
    assert endpoint.confidence.value == 85.0
    evidence = endpoint.evidence[0]
    assert evidence.engine == "jsast"
    assert evidence.technique == "api"
    assert evidence.meta["method"] == "POST"
    assert evidence.meta["header_names"] == ["Authorization", "Content-Type"]
    assert "Bearer" not in endpoint.model_dump_json()


def test_secret_mapping_is_masked():
    secret = next(
        finding
        for finding in load_jsast_report(FIXTURE)
        if finding.kind is FindingClass.SECRET
    )
    assert secret.asset_value.startswith("secret:aws_access_key:")
    assert secret.status is FindingStatus.CANDIDATE
    assert secret.evidence[0].meta["value_preview"] == "AKIA...MPLE"


def test_preamble_before_json_is_tolerated(tmp_path):
    text = "[*] Analyzing https://app.example.com/app.js\n" + FIXTURE.read_text(
        encoding="utf-8"
    )
    path = tmp_path / "preamble.json"
    path.write_text(text, encoding="utf-8")
    assert len(list(load_jsast_report(path))) == 2


def test_missing_url_raises():
    with pytest.raises(ValueError, match="missing a url"):
        list(parse_jsast_report({"endpoints": [{"method": "GET"}], "secrets": []}))


def test_fractional_confidence_is_scaled():
    findings = list(
        parse_jsast_report(
            {
                "endpoints": [
                    {
                        "url": "https://app.example.com/a",
                        "method": "GET",
                        "confidence": 0.8,
                    }
                ],
                "secrets": [],
            }
        )
    )
    assert findings[0].confidence.value == 80.0

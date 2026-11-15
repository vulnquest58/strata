"""Tests for the disclosed-version -> CVE vulnerability layer."""

from __future__ import annotations

import pytest

from strata.core.schema.models import (
    Confidence,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)
from strata.core.vulns import (
    cve_findings,
    load_cve_map,
    match_cves,
    version_in_window,
)


def _host_finding(metadata: dict) -> UnifiedFinding:
    return UnifiedFinding(
        run_id="test",
        kind=FindingClass.LIVE_HOST,
        status=FindingStatus.VERIFIED,
        asset_value="https://example.com",
        confidence=Confidence(value=85.0),
        evidence=[
            Evidence(
                engine="http_fp",
                technique="response_analysis",
                observation="HTTP 200",
            )
        ],
        metadata=metadata,
    )


def test_cve_map_is_valid_and_well_formed():
    data = load_cve_map()
    assert data["schema"] == 1
    assert isinstance(data["technologies"], dict)
    for tech, entries in data["technologies"].items():
        assert entries, tech
        for entry in entries:
            assert entry["cve"].startswith("CVE-"), (tech, entry)
            assert entry["severity"] in {"critical", "high", "medium", "low"}
            assert entry["fixed"], (tech, entry)
            assert entry.get("summary"), (tech, entry)


def test_version_in_window_numeric():
    assert version_in_window("2.4.49", "2.4.49", "2.4.51") is True
    assert version_in_window("2.4.50", "2.4.49", "2.4.51") is True
    assert version_in_window("2.4.51", "2.4.49", "2.4.51") is False
    assert version_in_window("2.4.6", "2.4.49", "2.4.51") is False
    assert version_in_window("1.20.0", "1.9.10", "1.21.0") is True
    assert version_in_window("1.21.0", "1.9.10", "1.21.0") is False
    assert version_in_window("8.1.2", "8.1.0", "8.1.29") is True
    assert version_in_window("9.4", "0", "1.21.0") is False


def test_version_in_window_unparseable_is_none():
    assert version_in_window("banana", "0", "2.4.51") is None
    # below-fixed is decisive: not vulnerable regardless of an unreadable 'since'
    assert version_in_window("2.4.51", "banana", "2.4.51") is False
    # in the window but unreadable 'since' -> unsure
    assert version_in_window("2.4.50", "banana", "2.4.51") is None


def test_apache_traversal_window_branch_aware():
    # 2.4.6 predates the advisory window: NOT CVE-2021-41773
    matches = match_cves(["Apache HTTP Server"], {"Apache HTTP Server": "2.4.6"})
    assert matches == []
    # 2.4.49 and 2.4.50 are squarely in the window
    matches = match_cves(
        ["Apache HTTP Server"], {"Apache HTTP Server": "2.4.50"}
    )
    cves = {m.cve for m in matches}
    assert cves == {"CVE-2021-41773", "CVE-2021-42013"}
    # patched version claims nothing
    matches = match_cves(
        ["Apache HTTP Server"], {"Apache HTTP Server": "2.4.52"}
    )
    assert matches == []


def test_no_version_no_claim():
    assert match_cves(["Nginx", "PHP", "WordPress"], {}) == []


def test_unknown_tech_ignored():
    assert match_cves(["WeirdWare"], {"WeirdWare": "1.0"}) == []


def test_patch_versions_do_not_flag():
    matches = match_cves(["PHP"], {"PHP": "8.3.8"})
    assert matches == []
    matches = match_cves(["PHP"], {"PHP": "8.2.20"})
    assert matches == []


def test_php_cgi_injection_flags_vulnerable_branches():
    matches = match_cves(["PHP"], {"PHP": "8.2.3"})
    assert [m.cve for m in matches] == ["CVE-2024-4577"]
    assert matches[0].severity == "critical"


def test_match_cves_sorted_by_severity():
    matches = match_cves(
        ["Apache HTTP Server"],
        {"Apache HTTP Server": "2.4.50"},
    )
    assert matches[0].severity == "critical"


def test_cve_findings_from_host_finding():
    host = _host_finding(
        {
            "tech_stack": ["Nginx"],
            "versions": {"Nginx": "1.20.0"},
        }
    )
    findings = cve_findings(host, run_id="run1")
    assert len(findings) == 1
    vuln = findings[0]
    assert vuln.kind is FindingClass.VULN
    assert vuln.status is FindingStatus.VERIFIED
    assert vuln.parent == "https://example.com"
    assert vuln.asset_value == "https://example.com"
    assert vuln.metadata["cve"] == "CVE-2021-23017"
    assert vuln.metadata["severity"] == "high"
    assert vuln.evidence[0].engine == "cve_map"
    assert vuln.evidence[0].strength is EvidenceStrength.CORROBORATED
    assert 60.0 <= vuln.confidence.value <= 80.0


def test_cve_findings_empty_without_versions():
    host = _host_finding({"tech_stack": ["Nginx"]})
    assert cve_findings(host, run_id="run1") == []
    host = _host_finding({"versions": "not-a-dict"})
    assert cve_findings(host, run_id="run1") == []


def test_cve_findings_deterministic_id():
    host = _host_finding({"versions": {"Nginx": "1.20.0"}})
    a = cve_findings(host, run_id="r1")[0]
    b = cve_findings(host, run_id="r1")[0]
    assert a.finding_id == b.finding_id


def test_struts_windows_cover_both_branches():
    old = match_cves(["Apache Struts"], {"Apache Struts": "2.3.31"})
    assert [m.cve for m in old] == ["CVE-2017-5638"]
    new = match_cves(["Apache Struts"], {"Apache Struts": "2.5.10"})
    assert [m.cve for m in new] == ["CVE-2017-5638"]
    patched = match_cves(["Apache Struts"], {"Apache Struts": "2.5.26"})
    assert patched == []


def test_partial_version_lower_confidence():
    matches = match_cves(["Nginx"], {"Nginx": "not-a-version"})
    assert matches == []  # unparseable -> no claim at all


def test_body_generator_tech_extracts_version(monkeypatch: pytest.MonkeyPatch):
    # Build a minimal FetchResponse-like stub directly
    from strata.core.content.fetch import FetchResponse
    from strata.engines.http_fp import fingerprint_response

    response = FetchResponse(
        "https://example.com",
        200,
        {"content-type": "text/html"},
        b'<meta name="generator" content="WordPress 5.7.2" />',
    )
    result = fingerprint_response(response)
    assert result.versions is not None
    assert result.versions.get("WordPress") == "5.7.2"
    findings = cve_findings(result.finding, run_id="r1") if result.finding else []
    assert any(f.metadata.get("cve") == "CVE-2022-21661" for f in findings)


def test_server_header_versions_extracted():
    from strata.core.content.fetch import FetchResponse
    from strata.engines.http_fp import fingerprint_response

    response = FetchResponse(
        "https://example.com",
        200,
        {"server": "nginx/1.18.0 (Ubuntu)", "x-powered-by": "PHP/7.4.3"},
        b"",
    )
    result = fingerprint_response(response)
    assert result.versions == {"Nginx": "1.18.0", "PHP": "7.4.3"}
    assert result.finding is not None
    assert result.finding.metadata["versions"] == result.versions
    findings = cve_findings(result.finding, run_id="r1")
    cves = {f.metadata["cve"] for f in findings}
    assert "CVE-2021-23017" in cves


def test_tomcat_detected_and_mapped():
    from strata.core.content.fetch import FetchResponse
    from strata.engines.http_fp import fingerprint_response

    response = FetchResponse(
        "https://example.com",
        200,
        {"server": "Tomcat/9.0.65"},
        b"",
    )
    result = fingerprint_response(response)
    assert "Apache Tomcat" in (result.versions or {})
    assert result.versions["Apache Tomcat"] == "9.0.65"
    findings = cve_findings(result.finding, run_id="r1")
    assert any(f.metadata.get("cve") == "CVE-2025-24813" for f in findings)


def test_coyote_discloses_no_tomcat_version():
    from strata.core.content.fetch import FetchResponse
    from strata.engines.http_fp import fingerprint_response

    response = FetchResponse(
        "https://example.com",
        200,
        {"server": "Apache-Coyote/1.1"},
        b"",
    )
    result = fingerprint_response(response)
    # Coyote/1.1 is the protocol version, not the Tomcat version:
    # no version claim -> no CVE claim (never guess).
    assert result.versions in (None, {})
    assert "Apache Tomcat" in result.finding.metadata["tech_stack"]
    assert cve_findings(result.finding, run_id="r1") == []


def test_patched_nginx_no_vuln():
    from strata.core.content.fetch import FetchResponse
    from strata.engines.http_fp import fingerprint_response

    response = FetchResponse(
        "https://example.com", 200, {"server": "nginx/1.25.3"}, b""
    )
    result = fingerprint_response(response)
    findings = cve_findings(result.finding, run_id="r1")
    assert findings == []

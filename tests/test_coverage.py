from strata.core.coverage import MIN_OVERLAP, discovery_sources, estimate_coverage
from strata.core.schema.models import (
    Confidence,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)


def _finding(
    asset: str,
    *,
    kind: FindingClass = FindingClass.SUBDOMAIN,
    engines: list[str],
) -> UnifiedFinding:
    return UnifiedFinding(
        run_id="r1",
        kind=kind,
        asset_value=asset,
        confidence=Confidence(value=50.0),
        evidence=[Evidence(engine=engine, technique="test") for engine in engines],
    )


def test_no_overlap_reports_observed_honestly() -> None:
    findings = [
        _finding("a.example.com", engines=["crtsh"]),
        _finding("b.example.com", engines=["rapiddns"]),
    ]
    estimates = estimate_coverage(findings)
    estimate = estimates["subdomain"]
    assert estimate.estimate == estimate.observed == 2
    assert estimate.source_pair is None


def test_overlap_yields_estimate_above_observed() -> None:
    findings = [
        _finding(f"h{index}.example.com", engines=["crtsh"])
        for index in range(50)
    ]
    for index in range(20):
        findings[index].evidence.append(Evidence(engine="rapiddns", technique="test"))
    findings.extend(
        _finding(f"r{index}.example.com", engines=["rapiddns"])
        for index in range(10)
    )
    estimates = estimate_coverage(findings)
    estimate = estimates["subdomain"]
    assert estimate.source_pair == ("crtsh", "rapiddns")
    assert estimate.overlap == 20
    assert estimate.observed == 60
    assert estimate.estimate > estimate.observed
    assert estimate.ci_low >= estimate.observed
    assert estimate.ci_high > estimate.estimate


def test_small_overlap_is_not_trusted() -> None:
    findings = [
        _finding(f"x{index}.example.com", engines=["crtsh"])
        for index in range(10)
    ]
    for index in range(MIN_OVERLAP - 1):
        findings[index].evidence.append(
            Evidence(engine="rapiddns", technique="test")
        )
    estimates = estimate_coverage(findings)
    assert estimates["subdomain"].source_pair is None


def test_kinds_are_estimated_independently() -> None:
    findings = [
        _finding(
            f"https://example.com/{name}",
            kind=FindingClass.ENDPOINT,
            engines=["content_crawl", "jsast"],
        )
        for name in ("a", "b", "c", "d")
    ]
    estimates = estimate_coverage(findings)
    assert set(estimates) == {"endpoint"}
    assert estimates["endpoint"].observed == 4


def test_dead_claims_are_not_a_capture_pass() -> None:
    findings = [
        _finding(f"h{index}.example.com", engines=["crtsh"])
        for index in range(40)
    ]
    findings.extend(
        _finding(f"r{index}.example.com", engines=["rapiddns"]) for index in range(10)
    )
    for index in range(20):
        findings[index].evidence.append(Evidence(engine="rapiddns", technique="test"))
    estimates = estimate_coverage(findings)
    live = estimates["subdomain"]
    assert live.observed == 50

    # Engine-born dead rows (engine dns_resolve) and any dead status must
    # neither count towards the observed surface nor act as a source.
    dead_rows = [
        _finding(f"ghost{index}.example.com", engines=["dns_resolve"])
        for index in range(395)
    ]
    for row in dead_rows:
        row.status = FindingStatus.DEAD
    estimates_with_dead = estimate_coverage(findings + dead_rows)
    still_live = estimates_with_dead["subdomain"]
    assert still_live.observed == live.observed
    assert still_live.estimate == live.estimate
    assert still_live.source_pair == live.source_pair


def test_dns_resolve_is_a_verifier_not_a_source() -> None:
    findings = [
        _finding("a.example.com", engines=["dns_resolve", "dns_brute"]),
        _finding("b.example.com", engines=["dns_resolve"]),
    ]
    assert discovery_sources(findings[0]) == {"dns_brute"}

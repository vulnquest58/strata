from strata.core.attack_value import attack_value, rank_by_attack_value
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
    kind: FindingClass = FindingClass.ENDPOINT,
    status: FindingStatus = FindingStatus.CANDIDATE,
    confidence: float = 50.0,
    metadata: dict | None = None,
) -> UnifiedFinding:
    return UnifiedFinding(
        run_id="r1",
        kind=kind,
        status=status,
        asset_value=asset,
        confidence=Confidence(value=confidence),
        evidence=[Evidence(engine="test", technique="t")],
        metadata=metadata or {},
    )


def test_admin_surface_outranks_static_page():
    admin = attack_value(_finding("https://example.com/admin/login", status=FindingStatus.VERIFIED))
    static = attack_value(_finding("https://example.com/about-us", status=FindingStatus.VERIFIED))
    assert admin.value > static.value + 25
    assert any("admin" in reason for reason in admin.reasons)


def test_secret_claims_rank_at_top():
    secret = _finding(
        "https://example.com/config.env",
        kind=FindingClass.SECRET,
        status=FindingStatus.VERIFIED,
    )
    assessment = attack_value(secret)
    assert assessment.value >= 80


def test_dead_claims_are_floor_and_excluded_from_ranking():
    dead = _finding("https://example.com/admin", status=FindingStatus.DEAD)
    assert attack_value(dead).value <= 5
    ranked = rank_by_attack_value([dead])
    assert ranked == []


def test_disclosed_version_boosts_live_host():
    plain = attack_value(_finding("https://api.example.com", kind=FindingClass.LIVE_HOST))
    with_versions = attack_value(
        _finding(
            "https://api.example.com",
            kind=FindingClass.LIVE_HOST,
            metadata={"tech_stack": ["Nginx"], "versions": {"Nginx": "1.18.0"}},
        )
    )
    assert with_versions.value > plain.value
    assert any("version" in reason for reason in with_versions.reasons)


def test_missing_security_headers_add_value():
    with_headers = attack_value(
        _finding(
            "https://example.com",
            kind=FindingClass.LIVE_HOST,
            metadata={"missing_critical_headers": ["content-security-policy"]},
        )
    )
    assert any("security headers" in reason for reason in with_headers.reasons)


def test_ranking_is_descending_and_deterministic():
    findings = [
        _finding("https://example.com/about"),
        _finding("https://example.com/admin/login", status=FindingStatus.VERIFIED),
        _finding("https://example.com/api/v2"),
    ]
    ranked = rank_by_attack_value(findings)
    values = [assessment.value for _, assessment in ranked]
    assert values == sorted(values, reverse=True)
    assert ranked[0][0].asset_value == "https://example.com/admin/login"


def test_param_count_adds_bounded_value():
    one = attack_value(
        _finding(
            "https://x.com/?q=1", kind=FindingClass.PARAM, metadata={"param_count": 1}
        )
    )
    many = attack_value(
        _finding(
            "https://x.com/?q=1", kind=FindingClass.PARAM, metadata={"param_count": 10}
        )
    )
    assert many.value > one.value
    assert many.value - one.value <= 12

from strata.core.schema.models import (
    Confidence,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)
from strata.engines.fusion import (
    entity_key,
    fuse_findings,
    noisy_or_confidence,
    resolve_entities,
)


def _finding(
    *,
    run_id: str,
    kind: FindingClass,
    asset_value: str,
    confidence: float,
    parent: str | None = None,
    engine: str = "test",
    technique: str = "test",
    observation: str = "test",
) -> UnifiedFinding:
    return UnifiedFinding(
        run_id=run_id,
        kind=kind,
        status=FindingStatus.CANDIDATE,
        asset_value=asset_value,
        parent=parent,
        confidence=Confidence(value=confidence),
        evidence=[
            Evidence(
                engine=engine,
                technique=technique,
                observation=observation,
            )
        ],
    )


def test_noisy_or_confidence_combines_signals() -> None:
    assert noisy_or_confidence([50.0, 50.0]) == 75.0
    assert noisy_or_confidence([100.0, 50.0]) == 100.0
    assert noisy_or_confidence([0.0, 0.0]) == 0.0


def test_resolves_duplicate_subdomains_across_runs() -> None:
    first = _finding(
        run_id="dns:example.com",
        kind=FindingClass.SUBDOMAIN,
        asset_value="api.example.com",
        confidence=40.0,
        engine="dns_brute",
        technique="wordlist_a_probe",
        observation="dns resolves api.example.com",
    )
    second = _finding(
        run_id="aperture:abc",
        kind=FindingClass.SUBDOMAIN,
        asset_value="api.example.com",
        confidence=60.0,
        engine="crtsh",
        technique="certificate_transparency",
        observation="crtsh lists api.example.com",
    )
    unrelated = _finding(
        run_id="dns:example.com",
        kind=FindingClass.SUBDOMAIN,
        asset_value="mail.example.com",
        confidence=50.0,
        engine="dns_brute",
        technique="wordlist_a_probe",
        observation="dns resolves mail.example.com",
    )

    groups = resolve_entities([first, second, unrelated])
    fused = fuse_findings([first, second, unrelated])
    assert len(groups) == 2
    assert len(fused) == 2
    api = next(f for f in fused if f.asset_value == "api.example.com")
    assert api.kind is FindingClass.SUBDOMAIN
    assert api.status is FindingStatus.CANDIDATE
    assert api.confidence.value == 76.0
    assert api.confidence.method.value == "noisy_or"
    assert api.metadata["source_count"] == 2
    assert len(api.evidence) == 2


def test_params_group_by_endpoint() -> None:
    first = _finding(
        run_id="content:app.example.com",
        kind=FindingClass.PARAM,
        asset_value="user_id",
        confidence=50.0,
        parent="https://app.example.com/api/users",
        engine="js_extract",
        technique="js_static",
        observation="js extract user_id",
    )
    second = _finding(
        run_id="param_oracle:app.example.com",
        kind=FindingClass.PARAM,
        asset_value="user_id",
        confidence=70.0,
        parent="https://app.example.com/api/users",
        engine="param_oracle",
        technique="probe_value_reflection",
        observation="parameter reflected",
    )
    other = _finding(
        run_id="param_oracle:app.example.com",
        kind=FindingClass.PARAM,
        asset_value="user_id",
        confidence=70.0,
        parent="https://app.example.com/api/orders",
        engine="param_oracle",
        technique="probe_value_reflection",
        observation="parameter reflected",
    )

    groups = resolve_entities([first, second, other])
    assert len(groups) == 2
    fused = fuse_findings([first, second, other])
    assert len(fused) == 2
    users = next(f for f in fused if f.parent == "https://app.example.com/api/users")
    assert users.asset_value == "user_id"
    assert users.confidence.value == 85.0
    assert users.metadata["source_count"] == 2


def test_endpoint_entity_key_normalises_url() -> None:
    first = _finding(
        run_id="content:example.com",
        kind=FindingClass.ENDPOINT,
        asset_value="https://example.com/api/?b=1&a=2",
        confidence=50.0,
        parent="example.com",
        engine="content_crawl",
        technique="js_extract",
        observation="extracted endpoint",
    )
    second = _finding(
        run_id="vulnharvest:example.com",
        kind=FindingClass.ENDPOINT,
        asset_value="https://example.com/api/?a=2&b=1",
        confidence=60.0,
        parent="example.com",
        engine="vulnharvest",
        technique="archive",
        observation="harvested endpoint",
    )

    assert entity_key(first) == entity_key(second)
    fused = fuse_findings([first, second])
    assert len(fused) == 1
    assert fused[0].asset_value == "https://example.com/api/?a=2&b=1"
    assert fused[0].confidence.value == 80.0

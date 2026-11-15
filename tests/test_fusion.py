from strata.core.schema.models import (
    Confidence,
    ConfidenceMethod,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)
from strata.core.store.db import StrataDB
from strata.engines.fusion import (
    EntityGroup,
    entity_key,
    fuse_findings,
    fuse_group,
    noisy_or_confidence,
    resolve_entities,
    superseded_finding_ids,
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


def test_fusion_preserves_engine_metadata() -> None:
    first = _finding(
        run_id="content:example.com",
        kind=FindingClass.ENDPOINT,
        asset_value="https://example.com/api",
        confidence=50.0,
        parent="example.com",
        engine="content_crawl",
        technique="js_extract",
        observation="extracted",
    ).model_copy(
        update={"metadata": {"tech_stack": ["nginx"], "params": ["user_id"]}}
    )
    second = _finding(
        run_id="fingerprint:example.com",
        kind=FindingClass.ENDPOINT,
        asset_value="https://example.com/api",
        confidence=60.0,
        parent="example.com",
        engine="http_fp",
        technique="header_probe",
        observation="fingerprinted",
    ).model_copy(
        update={
            "metadata": {
                "tech_stack": ["nginx", "php"],
                "params": ["page"],
                "waf": "Cloudflare",
            }
        }
    )

    fused = fuse_findings([first, second])
    assert len(fused) == 1
    metadata = fused[0].metadata
    assert metadata["tech_stack"] == ["nginx", "php"]
    assert metadata["params"] == ["user_id", "page"]
    assert metadata["waf"] == "Cloudflare"
    assert metadata["source"] == "fusion"
    assert metadata["source_count"] == 2


def test_fusion_replaces_raw_rows_and_is_idempotent(tmp_path) -> None:
    db_path = tmp_path / "strata.db"
    db = StrataDB(db_path)
    first = _finding(
        run_id="dns:example.com",
        kind=FindingClass.SUBDOMAIN,
        asset_value="api.example.com",
        confidence=40.0,
        engine="dns_brute",
        technique="wordlist",
        observation="dns resolves",
    )
    second = _finding(
        run_id="aperture:abc",
        kind=FindingClass.SUBDOMAIN,
        asset_value="api.example.com",
        confidence=60.0,
        engine="crtsh",
        technique="ct",
        observation="ct lists",
    )
    db.upsert_finding(first, target="example.com")
    db.upsert_finding(second, target="example.com")
    assert db.stats(target="example.com")["findings"] == 2

    def fuse_once() -> int:
        findings = list(db.iter_findings(target="example.com"))
        fused = fuse_findings(findings)
        removed = 0
        for finding in fused:
            db.upsert_finding(finding, target="example.com")
            removed += db.delete_findings(superseded_finding_ids(finding))
        return removed

    assert fuse_once() == 2
    rows = list(db.iter_findings(target="example.com"))
    assert len(rows) == 1
    assert rows[0].metadata["source_count"] == 2
    assert len(rows[0].evidence) == 2
    assert rows[0].confidence.value == 76.0

    assert fuse_once() == 0
    rows = list(db.iter_findings(target="example.com"))
    db.close()
    assert len(rows) == 1
    assert rows[0].confidence.value == 76.0
    assert rows[0].metadata["source_count"] == 2


def _group(
    *,
    statuses: list[FindingStatus],
    confidences: list[float],
    engines: list[str] | None = None,
) -> EntityGroup:
    engines = engines or ["crtsh"] * len(statuses)
    members = []
    for index, (status, value) in enumerate(
        zip(statuses, confidences, strict=True)
    ):
        members.append(
            UnifiedFinding(
                finding_id=f"src:{index}",
                run_id=f"r{index}",
                kind=FindingClass.SUBDOMAIN,
                status=status,
                asset_value="api.example.com",
                confidence=Confidence(
                    value=value,
                    method=ConfidenceMethod.NOISY_OR,
                    components={f"{engines[index]}:r{index}": value},
                ),
                evidence=[
                    Evidence(
                        engine=engines[index], technique="test", observation="t"
                    )
                ],
            )
        )
    return EntityGroup(
        kind=FindingClass.SUBDOMAIN,
        key="subdomain|api.example.com",
        findings=members,
    )


def test_fusion_flags_contested_claim_when_dead_mixes_with_alive() -> None:
    fused = fuse_group(
        _group(
            statuses=[FindingStatus.CANDIDATE, FindingStatus.DEAD],
            confidences=[60.0, 40.0],
        )
    )
    assert fused.metadata.get("contested") is True
    assert fused.status is not FindingStatus.DEAD


def test_unanimous_claim_is_not_contested() -> None:
    fused = fuse_group(
        _group(statuses=[FindingStatus.CANDIDATE] * 2, confidences=[50.0, 50.0])
    )
    assert "contested" not in fused.metadata


def test_reliability_weights_lower_low_quality_sources() -> None:
    group = _group(
        statuses=[FindingStatus.CANDIDATE] * 2,
        confidences=[60.0, 60.0],
        engines=["poisoned", "solid"],
    )
    plain = fuse_group(group)
    weighted = fuse_group(group, reliability={"poisoned": 0.0, "solid": 1.0})
    assert weighted.confidence.value < plain.confidence.value
    assert plain.confidence.value == noisy_or_confidence([60.0, 60.0])


def test_correlated_sources_do_not_double_count() -> None:
    from strata.core.reliability import source_family

    assert source_family("dns_brute") == "dns"
    assert source_family("passive_dns") == "dns"
    assert source_family("custom_engine") == "custom_engine"
    group = _group(
        statuses=[FindingStatus.CANDIDATE] * 2,
        confidences=[60.0, 60.0],
        engines=["dns_brute", "passive_dns"],
    )
    fused = fuse_group(group)
    # Two DNS-family voters act as one: no noisy-OR boost.
    assert fused.confidence.value == 60.0
    assert fused.metadata["source_count"] == 1
    assert fused.metadata["source_count_raw"] == 2


def test_independent_families_still_multiply() -> None:
    group = _group(
        statuses=[FindingStatus.CANDIDATE] * 2,
        confidences=[60.0, 60.0],
        engines=["dns_brute", "content_crawl"],
    )
    fused = fuse_group(group)
    assert fused.confidence.value == noisy_or_confidence([60.0, 60.0])
    assert fused.metadata["source_count"] == 2


def test_family_keeps_strongest_signal_within_correlated_sources() -> None:
    group = _group(
        statuses=[FindingStatus.CANDIDATE] * 3,
        confidences=[40.0, 60.0, 60.0],
        engines=["dns_brute", "dns_verify", "content_crawl"],
    )
    fused = fuse_group(group)
    # dns family contributes max(40, 60); content contributes 60
    assert fused.confidence.value == noisy_or_confidence([60.0, 60.0])

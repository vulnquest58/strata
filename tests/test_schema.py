import pytest
from pydantic import ValidationError

from strata.core.schema.models import (
    Confidence,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
    is_probable_domain,
)


def make_finding(**overrides):
    base = dict(
        run_id="run-1",
        kind=FindingClass.SUBDOMAIN,
        asset_value="api.example.com",
        parent="example.com",
        confidence=Confidence(value=70.0),
        evidence=[Evidence(engine="crtsh", technique="ct_log")],
    )
    base.update(overrides)
    return UnifiedFinding(**base)


class TestUnifiedFinding:
    def test_defaults_are_candidate_with_uuid(self):
        f = make_finding()
        assert f.status is FindingStatus.CANDIDATE
        assert f.finding_id
        assert f.asset_value == "api.example.com"

    def test_asset_value_normalized(self):
        f = make_finding(asset_value="  API.Example.COM ")
        assert f.asset_value == "api.example.com"

    def test_verified_requires_evidence(self):
        with pytest.raises(ValidationError, match="verified requires"):
            make_finding(evidence=[]).model_validate(
                {**make_finding(evidence=[]).model_dump(), "status": "verified"}
            )

    def test_verified_with_evidence_ok(self):
        f = make_finding(status=FindingStatus.VERIFIED)
        assert f.status is FindingStatus.VERIFIED

    def test_dead_requires_evidence(self):
        with pytest.raises(ValidationError, match="dead requires"):
            make_finding(status=FindingStatus.DEAD, evidence=[])

    def test_subdomain_needs_two_labels(self):
        with pytest.raises(ValidationError, match="two labels"):
            make_finding(asset_value="localhost")

    def test_subdomain_rejects_bad_labels(self):
        with pytest.raises(ValidationError, match="invalid domain label"):
            make_finding(asset_value="-bad..example.com")

    def test_confidence_clamped_range(self):
        with pytest.raises(ValidationError):
            Confidence(value=150.0)
        with pytest.raises(ValidationError):
            Confidence(value=-1.0)

    def test_confidence_components_range(self):
        with pytest.raises(ValidationError, match="outside 0..100"):
            Confidence(value=50.0, components={"crtsh": 120.0})

    def test_dedup_key(self):
        f = make_finding()
        assert f.dedup_key() == ("run-1", "subdomain", "api.example.com")

    def test_strongest_evidence(self):
        f = make_finding(
            evidence=[
                Evidence(engine="a", technique="t", strength=EvidenceStrength.WEAK),
                Evidence(engine="b", technique="t", strength=EvidenceStrength.STRONG),
            ]
        )
        assert f.strongest_evidence() is EvidenceStrength.STRONG
        assert make_finding(evidence=[]).strongest_evidence() is None


class TestDomainHeuristic:
    def test_probable_domains(self):
        assert is_probable_domain("api.example.com")
        assert is_probable_domain("Example.COM")
        assert is_probable_domain("_dmarc.example.com")
        assert not is_probable_domain("localhost")
        assert not is_probable_domain("a.b")
        assert not is_probable_domain("-bad.example.com")
        assert not is_probable_domain("bad..example.com")

    def test_other_kinds_skip_domain_validation(self):
        f = make_finding(kind=FindingClass.SECRET, asset_value="AKIA1234EXAMPLE")
        assert f.kind is FindingClass.SECRET
